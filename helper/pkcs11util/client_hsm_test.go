// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

//go:build hsm && (linux || darwin)

package pkcs11util_test

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/openbao/openbao/helper/pkcs11util"
	"github.com/openbao/openbao/helper/testhelpers/pkcs11testhelper"
)

func TestClient_GenerateRandom(t *testing.T) {
	fix := pkcs11testhelper.NewSoftHSM(t)
	client, err := pkcs11util.NewClient(fix.Config())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	ctx := context.Background()
	for _, length := range []int{1, 16, 4096, 10_000} {
		buf, err := client.GenerateRandom(ctx, length)
		if err != nil {
			t.Fatalf("GenerateRandom(%d): %v", length, err)
		}
		if len(buf) != length {
			t.Fatalf("GenerateRandom(%d): got %d bytes", length, len(buf))
		}
	}

	// Two consecutive reads must not be identical — extremely unlikely from a
	// real RNG, so this also guards against the stub path being picked up by
	// accident.
	a, _ := client.GenerateRandom(ctx, 32)
	b, _ := client.GenerateRandom(ctx, 32)
	if bytes.Equal(a, b) {
		t.Fatalf("two random reads were identical")
	}
}

func TestClient_Reader(t *testing.T) {
	fix := pkcs11testhelper.NewSoftHSM(t)
	client, err := pkcs11util.NewClient(fix.Config())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	r := client.Reader(context.Background())
	buf := make([]byte, 9000) // spans multiple chunks
	if _, err := io.ReadFull(r, buf); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if bytes.Count(buf, []byte{0}) > len(buf)/2 {
		t.Fatalf("read buffer is suspiciously zero-heavy")
	}
}

func TestClient_CloseThenUseErrors(t *testing.T) {
	fix := pkcs11testhelper.NewSoftHSM(t)
	client, err := pkcs11util.NewClient(fix.Config())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Close is idempotent.
	if err := client.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := client.GenerateRandom(context.Background(), 16); err == nil {
		t.Fatalf("expected error after Close")
	}
}
