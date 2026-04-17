// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package logical

import (
	"context"
	"crypto"
	"io"
)

// ExternalKey is the handle a mount holds to a key that lives in an external
// KMS or HSM via the External Keys subsystem. See
// website/content/docs/rfcs/external-keys.mdx.
//
// The interface is deliberately narrow — it looks like crypto.Signer plus a
// Close hook — so the implementations can be swapped (PKCS#11 today, named
// cloud KMS types in follow-ups) without changing consumers (PKI, Transit,
// SSH). Implementations MUST be safe for concurrent use; callers are
// allowed to issue parallel Sign calls.
//
// Why not just crypto.Signer? The stdlib interface is pragmatically what
// PKI and SSH already expect, but it lacks a ctx parameter (needed so we
// can cancel long-running HSM calls) and lacks Close (so we can release
// PKCS#11 sessions deterministically). An implementation can trivially
// expose a crypto.Signer adapter — see CryptoSigner below.
type ExternalKey interface {
	// Public returns the public portion of the external key, as an
	// *rsa.PublicKey, *ecdsa.PublicKey, or ed25519.PublicKey — same
	// contract crypto.Signer.Public exposes.
	Public() crypto.PublicKey

	// Sign asks the external KMS/HSM to sign digest with whatever options
	// opts carries (for RSA, *rsa.PSSOptions or a crypto.Hash for PKCS#1
	// v1.5; for ECDSA the hash function is inferred from len(digest)).
	// Identical to crypto.Signer but with an explicit context so callers
	// can cancel.
	Sign(ctx context.Context, rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error)

	// Close releases any session / handle the external provider holds for
	// this key. It is safe to call multiple times.
	Close() error
}

// CryptoSigner adapts an ExternalKey to the crypto.Signer interface so it
// can be passed to x509.CreateCertificate, ssh.NewSignerFromSigner, and
// similar stdlib helpers. The adapter uses context.Background() for the
// Sign call; callers that need cancellation must call ExternalKey.Sign
// directly.
type CryptoSigner struct{ Key ExternalKey }

func (s CryptoSigner) Public() crypto.PublicKey { return s.Key.Public() }

func (s CryptoSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.Key.Sign(context.Background(), rand, digest, opts)
}
