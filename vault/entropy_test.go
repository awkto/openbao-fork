// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

//go:build hsm && (linux || darwin)

package vault

import (
	"bytes"
	"io"
	"testing"

	"github.com/openbao/openbao/helper/configutil"
	"github.com/openbao/openbao/helper/testhelpers/pkcs11testhelper"
)

// TestBuildEntropyAugmenter_EndToEnd stands up a SoftHSM, wires an
// `entropy "seal"` + `seal "pkcs11"` pair, and verifies that the returned
// reader produces non-trivial bytes. This exercises the full happy-path from
// config → PKCS#11 session → augmented reader.
func TestBuildEntropyAugmenter_EndToEnd(t *testing.T) {
	fix := pkcs11testhelper.NewSoftHSM(t)

	cfg := &configutil.SharedConfig{
		Entropy: &configutil.Entropy{
			Source: configutil.EntropySourceSeal,
			Mode:   configutil.EntropyModeAugmentation,
		},
		Seals: []*configutil.KMS{
			{
				Type: "pkcs11",
				Config: map[string]string{
					"lib":         fix.Library,
					"token_label": fix.TokenLabel,
					"pin":         fix.Pin,
				},
			},
		},
	}

	client, reader, err := BuildEntropyAugmenter(cfg, nil)
	if err != nil {
		t.Fatalf("BuildEntropyAugmenter: %v", err)
	}
	if client == nil || reader == nil {
		t.Fatalf("expected non-nil client+reader")
	}
	t.Cleanup(func() { _ = client.Close() })

	buf := make([]byte, 256)
	if _, err := io.ReadFull(reader, buf); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	// Two consecutive reads of 256 bytes have a ~0 probability of matching.
	buf2 := make([]byte, 256)
	if _, err := io.ReadFull(reader, buf2); err != nil {
		t.Fatalf("ReadFull#2: %v", err)
	}
	if bytes.Equal(buf, buf2) {
		t.Fatal("two consecutive reads returned identical bytes")
	}
	// The augmented reader must not trivially match the HSM alone or /dev/
	// urandom alone — if a bug makes it emit zeros we catch it here.
	zeros := 0
	for _, b := range buf {
		if b == 0 {
			zeros++
		}
	}
	if zeros > len(buf)/2 {
		t.Fatalf("too many zero bytes in augmented output: %d/%d", zeros, len(buf))
	}
}

// TestBuildEntropyAugmenter_NoEntropyStanza returns nil cleanly when the
// server config has no entropy block — the happy-path for every non-HSM
// deployment.
func TestBuildEntropyAugmenter_NoEntropyStanza(t *testing.T) {
	client, reader, err := BuildEntropyAugmenter(&configutil.SharedConfig{}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client != nil || reader != nil {
		t.Fatalf("expected nils, got client=%v reader=%v", client, reader)
	}
}

// TestBuildEntropyAugmenter_RequiresPkcs11Seal rejects `entropy "seal"` when
// no pkcs11 seal is configured — otherwise the operator silently gets a
// shamir-only deployment thinking augmentation was wired.
func TestBuildEntropyAugmenter_RequiresPkcs11Seal(t *testing.T) {
	cfg := &configutil.SharedConfig{
		Entropy: &configutil.Entropy{Source: "seal", Mode: "augmentation"},
		Seals:   []*configutil.KMS{{Type: "shamir"}},
	}
	if _, _, err := BuildEntropyAugmenter(cfg, nil); err == nil {
		t.Fatal("expected error when no pkcs11 seal is present")
	}
}

func TestBuildEntropyAugmenter_SealMissingLib(t *testing.T) {
	cfg := &configutil.SharedConfig{
		Entropy: &configutil.Entropy{Source: "seal", Mode: "augmentation"},
		Seals: []*configutil.KMS{
			{Type: "pkcs11", Config: map[string]string{"pin": "1234"}},
		},
	}
	if _, _, err := BuildEntropyAugmenter(cfg, nil); err == nil {
		t.Fatal("expected error when pkcs11 seal has no library path")
	}
}
