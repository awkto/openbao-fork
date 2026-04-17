// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/helper/configutil"
	"github.com/openbao/openbao/helper/pkcs11util"
)

// entropyAugmentReader XORs bytes from a primary (HSM) reader with bytes
// from a secondary (OS) reader. A failure on either side is surfaced to the
// caller; we never silently fall back to one source alone — the whole point
// of augmentation is that an adversary must break both sources.
//
// This mirrors NIST SP 800-90B Appendix B combining advice: XOR of two
// independent sources preserves min-entropy of the stronger source, so even
// if the HSM silently degrades to a constant, the stream is still indistin-
// guishable from /dev/urandom.
type entropyAugmentReader struct {
	primary   io.Reader // HSM-backed, may return pkcs11util.ErrHSMUnavailable
	secondary io.Reader // OS PRNG, practically never fails
}

// Read fills p by XORing equal-sized reads from primary and secondary. If the
// primary source reports that the HSM is unavailable we return that error
// directly so the caller can surface a 503 instead of silently degrading.
func (r *entropyAugmentReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	// Fully read primary first so we fail fast on HSM outage before mixing in
	// OS entropy (which would otherwise mask the failure).
	if _, err := io.ReadFull(r.primary, p); err != nil {
		return 0, err
	}
	secondary := make([]byte, len(p))
	if _, err := io.ReadFull(r.secondary, secondary); err != nil {
		return 0, err
	}
	for i := range p {
		p[i] ^= secondary[i]
	}
	return len(p), nil
}

// pickPkcs11Seal returns the configured pkcs11 seal's KMS block, or nil if
// no pkcs11 seal is configured. It ignores seals explicitly marked disabled
// (those are the "migrate from" side of a seal migration).
func pickPkcs11Seal(seals []*configutil.KMS) *configutil.KMS {
	for _, s := range seals {
		if s == nil || s.Disabled {
			continue
		}
		if s.Type == "pkcs11" {
			return s
		}
	}
	return nil
}

// BuildEntropyAugmenter wires up a PKCS#11-backed entropy augmenter from a
// server config. It returns:
//
//   - a *pkcs11util.Client, the owner of the HSM session; the caller is
//     responsible for calling Close on shutdown,
//   - an io.Reader that mixes HSM bytes with crypto/rand,
//   - nil, nil when no entropy stanza is configured (callers should fall
//     back to crypto/rand.Reader for everything).
//
// If the entropy stanza is present but points at a seal kind we can't drive
// (non-pkcs11, or HSM build not linked in) we return an error and the server
// refuses to start — we do not silently degrade, since that would defeat the
// purpose of entropy augmentation.
func BuildEntropyAugmenter(cfg *configutil.SharedConfig, logger hclog.Logger) (*pkcs11util.Client, io.Reader, error) {
	if cfg == nil || cfg.Entropy == nil {
		return nil, nil, nil
	}
	if err := cfg.Entropy.Validate(); err != nil {
		return nil, nil, err
	}

	seal := pickPkcs11Seal(cfg.Seals)
	if seal == nil {
		return nil, nil, errors.New(`entropy "seal" requires a non-disabled seal block with type = "pkcs11"`)
	}

	p11cfg, err := pkcs11ConfigFromSeal(seal)
	if err != nil {
		return nil, nil, fmt.Errorf("entropy: %w", err)
	}

	client, err := pkcs11util.NewClient(p11cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("entropy: could not open PKCS#11 client: %w", err)
	}

	if logger != nil {
		logger.Info("entropy augmentation enabled",
			"source", cfg.Entropy.Source,
			"mode", cfg.Entropy.Mode,
			"seal", seal.Type,
		)
	}

	reader := &entropyAugmentReader{
		primary:   client.Reader(contextForReader()),
		secondary: rand.Reader,
	}
	return client, reader, nil
}

// pkcs11ConfigFromSeal extracts pkcs11util.Config from a KMS block. Key names
// mirror those accepted by go-kms-wrapping/wrappers/pkcs11 so operators see
// one set of settings across the seal and the entropy stanza.
func pkcs11ConfigFromSeal(seal *configutil.KMS) (pkcs11util.Config, error) {
	out := pkcs11util.Config{SlotID: -1}
	for k, v := range seal.Config {
		switch k {
		case "lib", "module":
			out.Library = v
		case "token", "token_label":
			out.TokenLabel = v
		case "pin":
			out.Pin = v
		case "slot":
			slot, err := parseSlot(v)
			if err != nil {
				return out, fmt.Errorf("invalid slot %q: %w", v, err)
			}
			out.SlotID = slot
		}
	}
	if out.Library == "" {
		return out, errors.New(`seal is missing "lib" (PKCS#11 module path)`)
	}
	return out, nil
}
