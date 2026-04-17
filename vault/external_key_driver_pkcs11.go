// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

//go:build hsm && (linux || darwin)

package vault

import (
	"context"
	"crypto"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"

	"github.com/openbao/openbao/helper/pkcs11util"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func init() {
	// "pkcs11" matches the type name advertised in the external-keys RFC:
	//   external_keys "pkcs11" { name = "softhsm"; library = "..."; ... }
	RegisterExternalKeyDriver("pkcs11", func() (ExternalKeyDriver, error) {
		return &pkcs11Driver{}, nil
	})
}

// pkcs11Driver is the External Keys driver that talks to a PKCS#11 HSM
// via helper/pkcs11util. It is lazy: the PKCS#11 library is loaded on
// first OpenKey call and shared across subsequent Opens.
type pkcs11Driver struct {
	mu      sync.Mutex
	clients map[string]*pkcs11util.Client
}

func (d *pkcs11Driver) Type() string { return "pkcs11" }

// OpenKey resolves the target key on the HSM and returns a
// logical.ExternalKey that proxies Sign calls into C_Sign. The config/
// key value maps follow the same keys as the PKCS#11 seal wrapper:
//
//   config values: library (or lib/module), token_label (or token),
//                  slot, pin
//   key values   : key_label (or label), key_id (or id)
//
// Matching that existing operator vocabulary means an operator
// converting a PKCS#11 seal into an external-keys setup doesn't have to
// learn a new set of field names.
func (d *pkcs11Driver) OpenKey(ctx context.Context, configValues, keyValues map[string]string) (logical.ExternalKey, error) {
	cfg, err := pkcs11ConfigFromValues(keyValues)
	if err != nil {
		return nil, err
	}

	keyLabel := firstNonEmpty(keyValues, "key_label", "label")
	// key_id is hex-encoded for operator ergonomics: pkcs11-tool --id AA
	// writes a single byte 0xAA, and we want operators to copy that same
	// value into OpenBao. Accept empty, then decode if present.
	rawID := firstNonEmpty(keyValues, "key_id", "id")
	keyID, err := decodeHexID(rawID)
	if err != nil {
		return nil, err
	}
	if keyLabel == "" && keyID == "" {
		return nil, errors.New("pkcs11 driver: key entry needs key_label or key_id")
	}

	client, err := d.clientFor(cfg)
	if err != nil {
		return nil, err
	}

	handle, err := client.FindKey(keyLabel, keyID)
	if err != nil {
		return nil, fmt.Errorf("pkcs11 driver: FindKey(%q, %q): %w", keyLabel, keyID, err)
	}

	return &pkcs11ExternalKey{
		client: client,
		handle: handle,
	}, nil
}

// clientFor returns a shared Client for a given library+token+slot+pin
// combination. Reusing the client across OpenKey calls avoids paying
// C_Initialize on every sign — which on some HSMs is hundreds of ms.
func (d *pkcs11Driver) clientFor(cfg pkcs11util.Config) (*pkcs11util.Client, error) {
	key := cfg.Library + "|" + cfg.TokenLabel + "|" + strconv.Itoa(cfg.SlotID)
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.clients == nil {
		d.clients = map[string]*pkcs11util.Client{}
	}
	if c, ok := d.clients[key]; ok {
		return c, nil
	}
	c, err := pkcs11util.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	d.clients[key] = c
	return c, nil
}

// Close releases every Client this driver opened. The registry calls
// this exactly once when a driverScopedKey is closed.
func (d *pkcs11Driver) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	var firstErr error
	for _, c := range d.clients {
		if err := c.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	d.clients = nil
	return firstErr
}

// pkcs11ExternalKey is a logical.ExternalKey that delegates to a PKCS#11
// key handle. We hold a *pkcs11util.Client + *KeyHandle; the driver owns
// the Client lifecycle.
type pkcs11ExternalKey struct {
	client *pkcs11util.Client
	handle *pkcs11util.KeyHandle
}

func (k *pkcs11ExternalKey) Public() crypto.PublicKey { return k.handle.Public() }

func (k *pkcs11ExternalKey) Sign(_ context.Context, _ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// rand is unused — HSM generates its own randomness during signing
	// (PSS salt, ECDSA nonce) per PKCS#11 semantics.
	return k.client.Sign(k.handle, digest, opts)
}

// Close is intentionally a no-op on the key itself — the pkcs11util.
// Client's session is pooled and the driver's Close tears everything
// down in one shot. Closing a single key does not close the client
// because other keys may still hold handles.
func (k *pkcs11ExternalKey) Close() error { return nil }

// pkcs11ConfigFromValues extracts library/token/slot/pin from a merged
// config+key values map. Accepts synonyms that match the go-kms-wrapping
// PKCS#11 wrapper (lib/module, token/token_label) for operator
// familiarity.
func pkcs11ConfigFromValues(values map[string]string) (pkcs11util.Config, error) {
	cfg := pkcs11util.Config{SlotID: -1}
	cfg.Library = firstNonEmpty(values, "library", "lib", "module")
	cfg.TokenLabel = firstNonEmpty(values, "token_label", "token")
	cfg.Pin = values["pin"]
	if s := values["slot"]; s != "" {
		n, err := parsePKCS11Slot(s)
		if err != nil {
			return cfg, fmt.Errorf("pkcs11 driver: invalid slot %q: %w", s, err)
		}
		cfg.SlotID = n
	}
	if cfg.Library == "" {
		return cfg, errors.New("pkcs11 driver: missing library (one of library/lib/module)")
	}
	return cfg, nil
}

func firstNonEmpty(m map[string]string, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok && v != "" {
			return v
		}
	}
	return ""
}

// decodeHexID turns the operator-supplied key_id (e.g. "AA", "aa",
// "0xAA", "de:ad:be:ef") into the byte sequence pkcs11util.FindKey will
// compare against CKA_ID. An empty input returns "" (FindKey then
// matches on label alone).
func decodeHexID(s string) (string, error) {
	if s == "" {
		return "", nil
	}
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	s = strings.ReplaceAll(s, ":", "")
	if len(s)%2 != 0 {
		s = "0" + s
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return "", fmt.Errorf("pkcs11 driver: key_id must be hex: %w", err)
	}
	return string(b), nil
}

func parsePKCS11Slot(s string) (int, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		v, err := strconv.ParseUint(s[2:], 16, 32)
		if err != nil {
			return 0, err
		}
		return int(v), nil
	}
	v, err := strconv.ParseInt(s, 10, 32)
	if err != nil {
		return 0, err
	}
	return int(v), nil
}
