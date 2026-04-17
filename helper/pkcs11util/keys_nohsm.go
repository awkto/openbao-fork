// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

//go:build !hsm || (!linux && !darwin)

package pkcs11util

import "crypto"

// KeyHandle is an opaque handle to a key stored on a PKCS#11 token. On
// non-HSM builds it is a zero-value type so consumers compile; calls
// through FindKey/Sign fail with ErrHSMBuildRequired.
type KeyHandle struct{}

func (*KeyHandle) Public() crypto.PublicKey { return nil }

func (*Client) FindKey(_, _ string) (*KeyHandle, error) { return nil, ErrHSMBuildRequired }

func (*Client) Sign(_ *KeyHandle, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return nil, ErrHSMBuildRequired
}
