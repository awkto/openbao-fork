// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

//go:build hsm && (linux || darwin)

package vault

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os/exec"
	"testing"
	"time"

	"github.com/openbao/openbao/helper/testhelpers/pkcs11testhelper"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// pkcs11ToolCreateKey uses pkcs11-tool to provision an RSA key pair on
// the fixture's token. This mirrors how an operator would pre-create a
// key before registering it with OpenBao (External Keys explicitly does
// NOT create key material per RFC).
func pkcs11ToolCreateRSAKey(t *testing.T, fix *pkcs11testhelper.Fixture, label, id string) {
	t.Helper()
	if _, err := exec.LookPath("pkcs11-tool"); err != nil {
		t.Skipf("pkcs11-tool not installed: %v", err)
	}
	// CKM_RSA_PKCS_KEY_PAIR_GEN
	cmd := exec.Command("pkcs11-tool",
		"--module", fix.Library,
		"--login", "--pin", fix.Pin,
		"--keypairgen", "--key-type", "rsa:2048",
		"--label", label,
		"--id", id,
	)
	cmd.Env = append(cmd.Env, "SOFTHSM2_CONF="+fix.ConfigPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("pkcs11-tool keypairgen: %v\n%s", err, out)
	}
}

// TestExternalKeyDriver_Pkcs11_SignRoundTrip covers the end-to-end happy
// path: provision an RSA key on SoftHSM, OpenKey it through a fake
// logical.Storage with the registry populated, sign a digest, verify the
// signature against the stdlib public key. This proves the driver wiring,
// the Registry.OpenKey dispatch, and the pkcs11util.Sign payload shape
// all agree.
func TestExternalKeyDriver_Pkcs11_SignRoundTrip(t *testing.T) {
	fix := pkcs11testhelper.NewSoftHSM(t)
	pkcs11ToolCreateRSAKey(t, fix, "openbao-ek", "AA")

	// Spin up a registry on an InmemStorage; we call Put* directly to
	// populate the config and key rather than going through the HTTP API.
	storage := &logical.InmemStorage{}
	ctx := context.Background()

	// Synthesize the sys/external-keys/configs/my-softhsm entry. In
	// production this is built via PutConfig; here we marshal the struct
	// directly so the test focuses on driver behavior, not REST plumbing.
	configView := logical.NewStorageView(storage, "external-keys/configs/")
	mustPutJSON(t, ctx, configView, "my-softhsm", &ExternalKeyConfig{
		Type: "pkcs11",
		Values: map[string]string{
			"library":     fix.Library,
			"token_label": fix.TokenLabel,
			"pin":         fix.Pin,
		},
	})

	keyView := logical.NewStorageView(storage, "external-keys/keys/")
	mustPutJSON(t, ctx, keyView, "my-softhsm/ca", &ExternalKey{
		Values: map[string]string{
			"key_label": "openbao-ek",
			"key_id":    "AA",
		},
	})

	reg := NewExternalKeyRegistry(nil, nil)
	regStorage := logical.NewStorageView(storage, "external-keys/")

	ext, err := reg.OpenKey(ctx, regStorage, "my-softhsm", "ca")
	if err != nil {
		t.Fatalf("OpenKey: %v", err)
	}
	t.Cleanup(func() { _ = ext.Close() })

	pub, ok := ext.Public().(*rsa.PublicKey)
	if !ok || pub == nil {
		t.Fatalf("Public: want *rsa.PublicKey, got %T", ext.Public())
	}

	digest := sha256.Sum256([]byte("hello, external keys"))
	sig, err := ext.Sign(ctx, rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}
}

// TestExternalKeyDriver_Pkcs11_SignsX509Cert proves the crypto.Signer
// adapter works end-to-end: we drive x509.CreateCertificate with the
// HSM-backed signer and parse the result. This is the core PKI
// integration contract — if this test passes, a PKI mount could issue
// certs backed by this key just by holding a CryptoSigner.
func TestExternalKeyDriver_Pkcs11_SignsX509Cert(t *testing.T) {
	fix := pkcs11testhelper.NewSoftHSM(t)
	pkcs11ToolCreateRSAKey(t, fix, "openbao-ek-ca", "BB")

	storage := &logical.InmemStorage{}
	ctx := context.Background()
	configView := logical.NewStorageView(storage, "external-keys/configs/")
	mustPutJSON(t, ctx, configView, "my-softhsm", &ExternalKeyConfig{
		Type: "pkcs11",
		Values: map[string]string{
			"library":     fix.Library,
			"token_label": fix.TokenLabel,
			"pin":         fix.Pin,
		},
	})
	keyView := logical.NewStorageView(storage, "external-keys/keys/")
	mustPutJSON(t, ctx, keyView, "my-softhsm/ca", &ExternalKey{
		Values: map[string]string{"key_label": "openbao-ek-ca", "key_id": "BB"},
	})

	reg := NewExternalKeyRegistry(nil, nil)
	ext, err := reg.OpenKey(ctx, logical.NewStorageView(storage, "external-keys/"), "my-softhsm", "ca")
	if err != nil {
		t.Fatalf("OpenKey: %v", err)
	}
	t.Cleanup(func() { _ = ext.Close() })

	signer := logical.CryptoSigner{Key: ext}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "openbao-ek-ca-test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageCertSign,
		IsCA:         true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tpl, tpl, signer.Public(), signer)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if err := cert.CheckSignature(x509.SHA256WithRSA, cert.RawTBSCertificate, cert.Signature); err != nil {
		t.Fatalf("cert self-signature invalid: %v", err)
	}
}

// mustPutJSON is a small testing helper that marshals and stores a typed
// struct at the given storage path. We bypass the Put* registry APIs
// because they assume an *logical.Request context we don't want to
// fabricate in unit tests.
func mustPutJSON(t *testing.T, ctx context.Context, storage logical.Storage, key string, v any) {
	t.Helper()
	entry, err := logical.StorageEntryJSON(key, v)
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.Put(ctx, entry); err != nil {
		t.Fatal(err)
	}
}
