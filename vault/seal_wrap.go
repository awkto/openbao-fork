// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	hclog "github.com/hashicorp/go-hclog"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/openbao/openbao/sdk/v2/physical"
	"github.com/openbao/openbao/vault/seal"
	"google.golang.org/protobuf/proto"
)

// sealWrapMagic is the fixed prefix prepended to every seal-wrapped physical
// entry. On read we use it to distinguish wrapped from unwrapped entries;
// this keeps the layer transparent to pre-existing data and to entries whose
// mount never opted into seal wrap.
//
// Version is embedded in the magic so we can evolve the format later without
// a migration scan. "SEALWRAPv1" (10 bytes) is short, stable, and unlikely
// to collide with barrier ciphertexts (which start with a 4-byte term
// prefix, not ASCII).
var sealWrapMagic = []byte("SEALWRAPv1")

// SealWrappingBackend is a physical.Backend middleware that transparently
// encrypts entries flagged with SealWrap=true via the configured seal's
// wrapping.Wrapper before persisting them, and decrypts them on read.
//
// Design choice: sits BELOW the LRU cache so a cache hit skips the seal
// round-trip. Never mutates the input *physical.Entry — it clones into a
// new entry before wrapping, so upper layers that retain entry references
// (e.g. cache.Put's clone-after-Put pattern) observe the original plaintext.
//
// Parallel-unseal future compatibility: the wrapped format carries the
// wrapper's type+key id via wrapping.BlobInfo.KeyInfo. When OpenBao
// eventually supports multiple active seals, the unwrap side can dispatch
// to the seal that matches KeyInfo.KeyId.
type SealWrappingBackend struct {
	physical.Backend
	access seal.Access
	logger hclog.Logger

	// Track fail-closed behaviour: if the seal is unreachable mid-write,
	// we surface the error rather than persisting plaintext. We do NOT
	// attempt retries here — upper layers (request handling) get to see
	// the 5xx and the operator's monitoring can page.
	metricsOnce sync.Once
}

// NewSealWrappingBackend wraps `inner` so entries with SealWrap=true get
// encrypted via `access` before reaching the storage backend.
func NewSealWrappingBackend(inner physical.Backend, access seal.Access, logger hclog.Logger) *SealWrappingBackend {
	if logger == nil {
		logger = hclog.NewNullLogger()
	}
	return &SealWrappingBackend{Backend: inner, access: access, logger: logger}
}

// Put seal-wraps the entry's value if SealWrap is set, then writes to the
// underlying backend. The input entry is never mutated.
func (b *SealWrappingBackend) Put(ctx context.Context, entry *physical.Entry) error {
	if !entry.SealWrap || b.access == nil {
		return b.Backend.Put(ctx, entry)
	}

	defer func(now time.Time) {
		// Emit seal.wrap.time alongside the seal.encrypt.time metric the
		// seal.Access already publishes; distinguishable by the .wrap suffix
		// so we can graph barrier encrypt separately from seal-wrap usage.
		_ = now // metrics.MeasureSince goes here once we finalize label set
	}(time.Now())

	blob, err := b.access.Encrypt(ctx, entry.Value)
	if err != nil {
		return fmt.Errorf("seal wrap: encrypt failed for key %q: %w", entry.Key, err)
	}

	wrapped, err := marshalSealWrappedBlob(blob)
	if err != nil {
		return fmt.Errorf("seal wrap: marshal failed for key %q: %w", entry.Key, err)
	}

	// Clone the entry. The cache layer above us will clone back from this
	// *original* entry after Put returns, so we must NOT mutate it.
	cloned := &physical.Entry{
		Key:       entry.Key,
		Value:     wrapped,
		SealWrap:  entry.SealWrap,
		ValueHash: entry.ValueHash,
	}
	return b.Backend.Put(ctx, cloned)
}

// Get reads from the underlying backend. If the resulting value has the
// seal-wrap magic prefix we unwrap it transparently, regardless of whether
// the caller's expected SealWrap state — this lets entries written with
// seal wrap be read back cleanly even after the mount's seal_wrap tune was
// later turned off.
func (b *SealWrappingBackend) Get(ctx context.Context, key string) (*physical.Entry, error) {
	entry, err := b.Backend.Get(ctx, key)
	if err != nil || entry == nil {
		return entry, err
	}

	if !isSealWrapped(entry.Value) {
		return entry, nil
	}

	if b.access == nil {
		// Sealed entry exists but no seal configured — almost certainly
		// means the operator changed seal types without running seal
		// migration. Fail loudly rather than silently returning ciphertext.
		return nil, fmt.Errorf("seal wrap: entry %q is seal-wrapped but no seal is configured", key)
	}

	blob, err := unmarshalSealWrappedBlob(entry.Value)
	if err != nil {
		return nil, fmt.Errorf("seal wrap: unmarshal failed for key %q: %w", key, err)
	}

	plaintext, err := b.access.Decrypt(ctx, blob)
	if err != nil {
		return nil, fmt.Errorf("seal wrap: decrypt failed for key %q: %w", key, err)
	}

	return &physical.Entry{
		Key:       entry.Key,
		Value:     plaintext,
		SealWrap:  entry.SealWrap,
		ValueHash: entry.ValueHash,
	}, nil
}

// isSealWrapped reports whether a physical-entry value carries the seal
// wrap magic prefix. Cheap bytes.HasPrefix so we can check every Get.
func isSealWrapped(value []byte) bool {
	return len(value) >= len(sealWrapMagic) && bytes.HasPrefix(value, sealWrapMagic)
}

// marshalSealWrappedBlob encodes a BlobInfo with the seal-wrap magic
// prefix. The format is:
//
//	magic(10) | length(4, big-endian) | proto-encoded BlobInfo
//
// We avoid length-prefixed protobuf framing because our length is always
// the remainder of the entry; the length field is strictly a sanity check
// against truncation.
func marshalSealWrappedBlob(blob *wrapping.BlobInfo) ([]byte, error) {
	raw, err := proto.Marshal(blob)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(sealWrapMagic)+4+len(raw))
	out = append(out, sealWrapMagic...)
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(raw)))
	out = append(out, lenBuf[:]...)
	out = append(out, raw...)
	return out, nil
}

func unmarshalSealWrappedBlob(value []byte) (*wrapping.BlobInfo, error) {
	if !isSealWrapped(value) {
		return nil, errors.New("value is not seal-wrapped")
	}
	rest := value[len(sealWrapMagic):]
	if len(rest) < 4 {
		return nil, errors.New("seal-wrap entry truncated: missing length")
	}
	protoLen := binary.BigEndian.Uint32(rest[:4])
	rest = rest[4:]
	if uint32(len(rest)) != protoLen {
		return nil, fmt.Errorf("seal-wrap entry length mismatch: got %d, want %d", len(rest), protoLen)
	}
	blob := &wrapping.BlobInfo{}
	if err := proto.Unmarshal(rest, blob); err != nil {
		return nil, err
	}
	return blob, nil
}
