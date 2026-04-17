// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package routing

import (
	"context"
	"strings"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// sealWrapStorage wraps a logical.Storage so that Put calls on paths the
// backend declared as SealWrapStorage carry the SealWrap flag. The flag is
// passed down through the barrier into vault.SealWrappingBackend which
// actually performs the seal encryption.
//
// Without this middleware the SealWrap=true bool on MountEntry is a dead
// switch — no writer sets it on individual StorageEntry objects. This
// middleware is the single place where mount-level seal wrap policy
// becomes per-entry behaviour.
//
// Matching rules:
//   - An exact string in SealWrapStorage matches that exact key.
//   - A string ending in "/" matches keys with that prefix.
//   - A lone "*" matches every key (passthrough/legacy-kv case).
type sealWrapStorage struct {
	logical.Storage
	prefixes []string
	exact    map[string]struct{}
	all      bool
}

// newSealWrapStorageAdapter returns inner unwrapped if the mount has seal
// wrap off or declares no seal-wrapped paths, and a wrapping storage
// otherwise.
func newSealWrapStorageAdapter(inner logical.Storage, mountSealWrap bool, paths []string) logical.Storage {
	if !mountSealWrap || len(paths) == 0 {
		return inner
	}
	s := &sealWrapStorage{Storage: inner, exact: map[string]struct{}{}}
	for _, p := range paths {
		switch {
		case p == "*":
			s.all = true
		case strings.HasSuffix(p, "/"):
			s.prefixes = append(s.prefixes, p)
		default:
			s.exact[p] = struct{}{}
		}
	}
	return s
}

func (s *sealWrapStorage) matches(key string) bool {
	if s.all {
		return true
	}
	if _, ok := s.exact[key]; ok {
		return true
	}
	for _, p := range s.prefixes {
		if strings.HasPrefix(key, p) {
			return true
		}
	}
	return false
}

func (s *sealWrapStorage) Put(ctx context.Context, entry *logical.StorageEntry) error {
	if entry != nil && s.matches(entry.Key) {
		// Clone rather than mutate — callers may keep a reference to the
		// entry for logging, audit, or retry.
		cloned := *entry
		cloned.SealWrap = true
		return s.Storage.Put(ctx, &cloned)
	}
	return s.Storage.Put(ctx, entry)
}
