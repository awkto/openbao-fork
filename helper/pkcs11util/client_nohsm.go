// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

//go:build !hsm || (!linux && !darwin)

package pkcs11util

import (
	"context"
	"io"
)

// Client is a stub on non-HSM builds. All methods return ErrHSMBuildRequired.
type Client struct{}

func NewClient(_ Config) (*Client, error) { return nil, ErrHSMBuildRequired }

func (*Client) Close() error { return nil }

func (*Client) GenerateRandom(_ context.Context, _ int) ([]byte, error) {
	return nil, ErrHSMBuildRequired
}

func (*Client) Reader(_ context.Context) io.Reader { return errReader{} }

type errReader struct{}

func (errReader) Read(_ []byte) (int, error) { return 0, ErrHSMBuildRequired }
