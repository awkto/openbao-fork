// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package random

import (
	"crypto/rand"
	"io"
)

// isPlatformReader tells whether a reader is the vanilla crypto/rand.Reader
// that framework.Backend.GetRandomReader returns when no entropy augmentation
// source is configured. HandleRandomAPI uses this to distinguish "source=seal
// but no augmenter" (must fail) from "source=seal with a real augmenter" (use
// the augmented reader).
func isPlatformReader(r io.Reader) bool { return r == rand.Reader }
