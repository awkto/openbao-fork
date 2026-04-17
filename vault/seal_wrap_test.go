// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"bytes"
	"context"
	"testing"

	hclog "github.com/hashicorp/go-hclog"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/openbao/openbao/sdk/v2/physical"
	"github.com/openbao/openbao/sdk/v2/physical/inmem"
	"github.com/openbao/openbao/vault/seal"
)

// testSealAccess wraps go-kms-wrapping's NewTestWrapper in a seal.Access so
// we can drive the seal-wrap layer with an in-memory, deterministic key.
func testSealAccess(t *testing.T) seal.Access {
	t.Helper()
	// 32-byte AES-256 key for the test wrapper.
	secret := bytes.Repeat([]byte{0x42}, 32)
	return seal.NewAccess(wrapping.NewTestWrapper(secret))
}

func newSealWrapBackend(t *testing.T) (*SealWrappingBackend, physical.Backend) {
	t.Helper()
	inner, err := inmem.NewInmem(nil, hclog.NewNullLogger())
	if err != nil {
		t.Fatalf("NewInmem: %v", err)
	}
	return NewSealWrappingBackend(inner, testSealAccess(t), hclog.NewNullLogger()), inner
}

// TestSealWrap_RoundTrip: a value put with SealWrap=true must come back
// unchanged through the same layer.
func TestSealWrap_RoundTrip(t *testing.T) {
	b, _ := newSealWrapBackend(t)
	ctx := context.Background()
	in := &physical.Entry{Key: "foo", Value: []byte("the quick brown fox"), SealWrap: true}
	if err := b.Put(ctx, in); err != nil {
		t.Fatalf("Put: %v", err)
	}
	out, err := b.Get(ctx, "foo")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(out.Value, in.Value) {
		t.Fatalf("round-trip mismatch: got %q, want %q", out.Value, in.Value)
	}
}

// TestSealWrap_RawIsCiphertext: the underlying storage must see the wrapped
// bytes, not plaintext — if the magic prefix is absent on the raw entry,
// the wrap layer was bypassed.
func TestSealWrap_RawIsCiphertext(t *testing.T) {
	b, inner := newSealWrapBackend(t)
	ctx := context.Background()
	plain := []byte("super secret")
	if err := b.Put(ctx, &physical.Entry{Key: "k", Value: plain, SealWrap: true}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	raw, err := inner.Get(ctx, "k")
	if err != nil {
		t.Fatalf("inner Get: %v", err)
	}
	if !isSealWrapped(raw.Value) {
		t.Fatalf("raw storage missing seal-wrap magic prefix; got %x", raw.Value)
	}
	if bytes.Contains(raw.Value, plain) {
		t.Fatalf("plaintext leaked into raw storage: %x", raw.Value)
	}
}

// TestSealWrap_PassthroughWhenDisabled: entries without SealWrap=true must
// reach the underlying backend byte-identical. This is the guard that keeps
// the middleware safe to enable globally.
func TestSealWrap_PassthroughWhenDisabled(t *testing.T) {
	b, inner := newSealWrapBackend(t)
	ctx := context.Background()
	plain := []byte("unwrapped data")
	if err := b.Put(ctx, &physical.Entry{Key: "plain", Value: plain}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	raw, err := inner.Get(ctx, "plain")
	if err != nil {
		t.Fatalf("inner Get: %v", err)
	}
	if !bytes.Equal(raw.Value, plain) {
		t.Fatalf("passthrough mismatch: got %q, want %q", raw.Value, plain)
	}
}

// TestSealWrap_DoesNotMutateInputEntry guards the cache-layer contract:
// physical.Cache.Put caches whatever value is on the entry AFTER Put
// returns, so mutating the input would cause cache poisoning.
func TestSealWrap_DoesNotMutateInputEntry(t *testing.T) {
	b, _ := newSealWrapBackend(t)
	ctx := context.Background()
	original := []byte("do not mutate")
	in := &physical.Entry{Key: "k", Value: original, SealWrap: true}
	if err := b.Put(ctx, in); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if !bytes.Equal(in.Value, original) {
		t.Fatalf("input entry was mutated: got %q, want %q", in.Value, original)
	}
}

// TestSealWrap_GetUnwrapsEvenWhenFlagCleared: once an entry is stored with
// seal wrap, the layer must unwrap on every read — even if a later mount
// tune turned seal_wrap off, a single entry could outlive that toggle.
func TestSealWrap_GetUnwrapsEvenWhenFlagCleared(t *testing.T) {
	b, inner := newSealWrapBackend(t)
	ctx := context.Background()
	plain := []byte("older entry")
	if err := b.Put(ctx, &physical.Entry{Key: "k", Value: plain, SealWrap: true}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	// Simulate: the mount's SealWrap flag is no longer set on reads, but
	// the entry in raw storage still carries the magic prefix.
	raw, _ := inner.Get(ctx, "k")
	if !isSealWrapped(raw.Value) {
		t.Fatalf("raw should be seal-wrapped")
	}
	got, err := b.Get(ctx, "k")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got.Value, plain) {
		t.Fatalf("unwrap mismatch: got %q, want %q", got.Value, plain)
	}
}

// TestSealWrap_NoAccessFailsWrappedRead: if an entry exists but no seal is
// available (e.g. operator switched seal types without migrating), we must
// surface an error rather than returning ciphertext to the barrier.
func TestSealWrap_NoAccessFailsWrappedRead(t *testing.T) {
	b, inner := newSealWrapBackend(t)
	ctx := context.Background()
	if err := b.Put(ctx, &physical.Entry{Key: "k", Value: []byte("x"), SealWrap: true}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	// Clear the access so the layer has nothing to decrypt with.
	bNoSeal := NewSealWrappingBackend(inner, nil, hclog.NewNullLogger())
	if _, err := bNoSeal.Get(ctx, "k"); err == nil {
		t.Fatalf("expected error when seal is missing")
	}
}

func TestSealWrap_MagicPrefixStable(t *testing.T) {
	if string(sealWrapMagic) != "SEALWRAPv1" {
		t.Fatalf("magic prefix drifted: %q", sealWrapMagic)
	}
}
