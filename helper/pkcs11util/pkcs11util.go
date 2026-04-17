// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

// Package pkcs11util is a thin wrapper around github.com/miekg/pkcs11 that
// exposes just the operations OpenBao needs beyond what the seal interface
// covers: RNG access for entropy augmentation, raw key handles for External
// Keys, and session lifecycle for Seal Wrap.
//
// All PKCS#11 calls live in files gated by //go:build hsm. On non-HSM builds
// the exported constructor returns ErrHSMBuildRequired.
package pkcs11util

import (
	"errors"
	"fmt"
)

// Config describes how to connect to a PKCS#11 token. The same struct is
// consumed by the entropy-augmentation, seal-wrap, and external-keys features
// so operators only learn one config surface.
type Config struct {
	// Library is the filesystem path to the PKCS#11 .so/.dylib.
	Library string

	// TokenLabel selects a token by label. Preferred over SlotID because slot
	// IDs are not stable across softhsm restarts. If both are empty the first
	// token is used; if both are set TokenLabel wins.
	TokenLabel string

	// SlotID is a numeric slot ID (hex or decimal in config). -1 means unset.
	SlotID int

	// Pin is the user PIN for C_Login. Required for RNG on vendors that gate
	// C_GenerateRandom behind a login (some HSMs do).
	Pin string
}

// ErrHSMBuildRequired is returned by NewClient when OpenBao was built without
// the hsm tag. Operators should switch to an HSM distribution or the PKCS#11
// KMS plugin.
var ErrHSMBuildRequired = errors.New("this build of OpenBao has PKCS#11 support disabled; build with -tags hsm or use the PKCS#11 KMS plugin")

// ErrHSMUnavailable wraps any transport-layer error that indicates the HSM is
// unreachable (dead session, network blip, C_Initialize failure). Callers MUST
// NOT silently fall back to another entropy source when they see this error —
// per the entropy-augmentation design we fail closed.
type ErrHSMUnavailable struct {
	Op  string
	Err error
}

func (e *ErrHSMUnavailable) Error() string {
	if e.Op == "" {
		return fmt.Sprintf("HSM unavailable: %v", e.Err)
	}
	return fmt.Sprintf("HSM unavailable during %s: %v", e.Op, e.Err)
}

func (e *ErrHSMUnavailable) Unwrap() error { return e.Err }

// IsUnavailable reports whether err chains through an ErrHSMUnavailable.
func IsUnavailable(err error) bool {
	var target *ErrHSMUnavailable
	return errors.As(err, &target)
}
