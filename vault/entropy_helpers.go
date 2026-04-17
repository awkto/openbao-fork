// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"strconv"
	"strings"
)

// contextForReader returns a context with no deadline. The HSM RNG reader
// uses this as a cancellation hook only; we don't attach a timeout because
// GenerateRandom is meant to be a fast PKCS#11 primitive and callers already
// scope request deadlines around their reads.
func contextForReader() context.Context { return context.Background() }

// parseSlot accepts decimal or hex (`0x…`) slot ids. We keep this tolerant
// because operators copy slot ids from `softhsm2-util --show-slots` in
// decimal but vendor HSM docs often show them as hex.
func parseSlot(s string) (int, error) {
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
