// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

//go:build hsm && (linux || darwin)

package pkcs11util

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"github.com/miekg/pkcs11"
)

// KeyHandle references a PKCS#11 private-key object on the token. The
// handle is opaque to callers; they obtain one from FindKey and pass it
// to Sign. Always pair a KeyHandle with the Client that produced it —
// handles are session-scoped for some vendors.
type KeyHandle struct {
	client  *Client
	private pkcs11.ObjectHandle
	public  pkcs11.ObjectHandle
	pub     crypto.PublicKey
}

// Public returns the crypto.PublicKey that pairs with this handle's
// private key. Decoded once at FindKey time; cached here.
func (k *KeyHandle) Public() crypto.PublicKey { return k.pub }

// FindKey looks up a key pair on the token by label, ID, or both. For
// External Keys the operator pre-provisions the key (OpenBao never
// creates PKCS#11 key material) so this is purely a search operation.
//
// At least one of label/id must be non-empty. If both are given the
// search AND's them, matching ISO PKCS#11 semantics for template
// searches.
func (c *Client) FindKey(label, id string) (*KeyHandle, error) {
	if label == "" && id == "" {
		return nil, errors.New("pkcs11util: FindKey requires label or id")
	}

	session, err := c.acquire()
	if err != nil {
		return nil, err
	}
	defer c.release(session)

	priv, err := c.findObject(session, pkcs11.CKO_PRIVATE_KEY, label, id)
	if err != nil {
		return nil, err
	}

	pub, err := c.findObject(session, pkcs11.CKO_PUBLIC_KEY, label, id)
	if err != nil {
		// Some HSMs store only the private key's public components as
		// attributes. Fall back to reading the public material directly
		// from the private handle before giving up.
		pubKey, err2 := c.readPublicKeyFromPrivate(session, priv)
		if err2 != nil {
			return nil, fmt.Errorf("FindKey: public key lookup failed: %w (and attribute fallback: %v)", err, err2)
		}
		return &KeyHandle{client: c, private: priv, pub: pubKey}, nil
	}

	pubKey, err := c.readPublicKey(session, pub)
	if err != nil {
		return nil, err
	}
	return &KeyHandle{client: c, private: priv, public: pub, pub: pubKey}, nil
}

// Sign runs C_SignInit + C_Sign with a mechanism selected by the key
// type + hash:
//   - RSA + crypto.Hash{SHA256,SHA384,SHA512} → CKM_RSA_PKCS with pre-hashed
//     DigestInfo (we prepend the ASN.1 DigestInfo prefix because CKM_RSA_
//     PKCS expects it; this matches what stdlib crypto/rsa.SignPKCS1v15
//     does in software).
//   - ECDSA + any hash → CKM_ECDSA (the HSM just signs the raw digest).
//
// We don't support RSA PSS or RSA-OAEP in this first pass — callers that
// need them can extend this switch.
func (c *Client) Sign(handle *KeyHandle, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if handle == nil || handle.client != c {
		return nil, errors.New("pkcs11util: key handle does not belong to this client")
	}

	mech, prepared, err := prepareSignMechanism(handle.pub, digest, opts)
	if err != nil {
		return nil, err
	}

	session, err := c.acquire()
	if err != nil {
		return nil, err
	}
	defer c.release(session)

	if err := c.ctx.SignInit(session, []*pkcs11.Mechanism{mech}, handle.private); err != nil {
		return nil, &ErrHSMUnavailable{Op: "C_SignInit", Err: err}
	}
	sig, err := c.ctx.Sign(session, prepared)
	if err != nil {
		return nil, &ErrHSMUnavailable{Op: "C_Sign", Err: err}
	}

	// ECDSA: PKCS#11 returns the concatenation r||s. Go's crypto callers
	// (x509.CreateCertificate, ssh) expect DER-encoded ASN.1 — wrap it.
	if _, ok := handle.pub.(*ecdsa.PublicKey); ok {
		return ecdsaConcatToASN1(sig)
	}
	return sig, nil
}

func (c *Client) findObject(session pkcs11.SessionHandle, class uint, label, id string) (pkcs11.ObjectHandle, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, class),
	}
	if label != "" {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_LABEL, label))
	}
	if id != "" {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(id)))
	}

	if err := c.ctx.FindObjectsInit(session, template); err != nil {
		return 0, &ErrHSMUnavailable{Op: "C_FindObjectsInit", Err: err}
	}
	defer c.ctx.FindObjectsFinal(session)

	objs, _, err := c.ctx.FindObjects(session, 1)
	if err != nil {
		return 0, &ErrHSMUnavailable{Op: "C_FindObjects", Err: err}
	}
	if len(objs) == 0 {
		return 0, fmt.Errorf("pkcs11util: no key with label=%q id=%q class=0x%x", label, id, class)
	}
	return objs[0], nil
}

// readPublicKey reads CKA_KEY_TYPE + the type-specific public components
// off a CKO_PUBLIC_KEY object and reconstructs an rsa/ecdsa PublicKey.
func (c *Client) readPublicKey(session pkcs11.SessionHandle, pub pkcs11.ObjectHandle) (crypto.PublicKey, error) {
	attrs, err := c.ctx.GetAttributeValue(session, pub, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
	})
	if err != nil {
		return nil, &ErrHSMUnavailable{Op: "C_GetAttributeValue(KEY_TYPE)", Err: err}
	}
	keyType := uint(0)
	if len(attrs) > 0 && len(attrs[0].Value) > 0 {
		// Values are little-endian CK_ULONGs; PKCS#11 types fit in a byte
		// for the ones we care about, so reading the first byte is safe.
		keyType = uint(attrs[0].Value[0])
	}

	switch keyType {
	case pkcs11.CKK_RSA:
		return c.readRSAPublic(session, pub)
	case pkcs11.CKK_EC:
		return c.readECPublic(session, pub)
	default:
		return nil, fmt.Errorf("pkcs11util: unsupported public key type 0x%x", keyType)
	}
}

// readPublicKeyFromPrivate is the fallback for HSMs that don't expose a
// separate public-key object. Some vendors let you read CKA_MODULUS or
// CKA_EC_POINT off the private object directly — not portable but worth
// trying before erroring out.
func (c *Client) readPublicKeyFromPrivate(session pkcs11.SessionHandle, priv pkcs11.ObjectHandle) (crypto.PublicKey, error) {
	return c.readPublicKey(session, priv)
}

func (c *Client) readRSAPublic(session pkcs11.SessionHandle, pub pkcs11.ObjectHandle) (*rsa.PublicKey, error) {
	attrs, err := c.ctx.GetAttributeValue(session, pub, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
	})
	if err != nil {
		return nil, &ErrHSMUnavailable{Op: "C_GetAttributeValue(RSA)", Err: err}
	}
	if len(attrs) < 2 || len(attrs[0].Value) == 0 || len(attrs[1].Value) == 0 {
		return nil, errors.New("pkcs11util: RSA modulus or exponent missing")
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(attrs[0].Value),
		E: int(new(big.Int).SetBytes(attrs[1].Value).Int64()),
	}, nil
}

func (c *Client) readECPublic(session pkcs11.SessionHandle, pub pkcs11.ObjectHandle) (*ecdsa.PublicKey, error) {
	attrs, err := c.ctx.GetAttributeValue(session, pub, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	})
	if err != nil {
		return nil, &ErrHSMUnavailable{Op: "C_GetAttributeValue(EC)", Err: err}
	}
	if len(attrs) < 2 {
		return nil, errors.New("pkcs11util: EC params or point missing")
	}
	curve, err := curveFromOID(attrs[0].Value)
	if err != nil {
		return nil, err
	}
	// EC_POINT is DER-encoded OCTET STRING containing the uncompressed point.
	var rawPoint []byte
	if _, err := asn1.Unmarshal(attrs[1].Value, &rawPoint); err != nil {
		// Some HSMs omit the outer OCTET STRING — treat the raw bytes as
		// the point directly.
		rawPoint = attrs[1].Value
	}
	x, y := elliptic.Unmarshal(curve, rawPoint) //nolint:staticcheck // stdlib ec point parse
	if x == nil {
		return nil, errors.New("pkcs11util: could not parse EC public point")
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

// curveFromOID translates the DER-encoded named curve OID in CKA_EC_PARAMS
// to a Go elliptic.Curve. Only the curves PKCS/SSH cert issuance
// realistically uses are covered — extending for P-224 etc. is trivial.
func curveFromOID(der []byte) (elliptic.Curve, error) {
	var oid asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(der, &oid); err != nil {
		return nil, fmt.Errorf("pkcs11util: unmarshal EC params: %w", err)
	}
	switch {
	case oid.Equal(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}): // secp256r1
		return elliptic.P256(), nil
	case oid.Equal(asn1.ObjectIdentifier{1, 3, 132, 0, 34}): // secp384r1
		return elliptic.P384(), nil
	case oid.Equal(asn1.ObjectIdentifier{1, 3, 132, 0, 35}): // secp521r1
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("pkcs11util: unsupported EC curve OID %v", oid)
	}
}

// prepareSignMechanism picks the PKCS#11 mechanism for a key+digest pair
// and returns the bytes to hand to C_Sign (RSA needs a DigestInfo prefix,
// ECDSA passes the digest raw).
func prepareSignMechanism(pub crypto.PublicKey, digest []byte, opts crypto.SignerOpts) (*pkcs11.Mechanism, []byte, error) {
	switch pub.(type) {
	case *rsa.PublicKey:
		hash := opts.HashFunc()
		prefix, ok := rsaPKCS1v15Prefix[hash]
		if !ok {
			return nil, nil, fmt.Errorf("pkcs11util: unsupported RSA hash %v", hash)
		}
		payload := make([]byte, 0, len(prefix)+len(digest))
		payload = append(payload, prefix...)
		payload = append(payload, digest...)
		return pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil), payload, nil
	case *ecdsa.PublicKey:
		return pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil), digest, nil
	default:
		return nil, nil, fmt.Errorf("pkcs11util: unsupported key type %T", pub)
	}
}

// rsaPKCS1v15Prefix holds the ASN.1 DigestInfo prefix for common hashes,
// copied from crypto/rsa's internal prefixHashes table. The HSM sees a
// pre-hashed+prefixed blob via CKM_RSA_PKCS and just wraps it with PKCS1
// padding + RSA encrypt-with-private.
var rsaPKCS1v15Prefix = map[crypto.Hash][]byte{
	crypto.SHA256: {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384: {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512: {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
}

// ecdsaConcatToASN1 converts PKCS#11's raw r||s concatenation into the
// DER-encoded ECDSASignature ASN.1 structure that x509 and ssh expect.
func ecdsaConcatToASN1(sig []byte) ([]byte, error) {
	if len(sig) == 0 || len(sig)%2 != 0 {
		return nil, fmt.Errorf("pkcs11util: invalid ECDSA signature length %d", len(sig))
	}
	half := len(sig) / 2
	r := new(big.Int).SetBytes(sig[:half])
	s := new(big.Int).SetBytes(sig[half:])
	return asn1.Marshal(struct{ R, S *big.Int }{r, s})
}

