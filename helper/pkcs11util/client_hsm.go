// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

//go:build hsm && (linux || darwin)

package pkcs11util

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/miekg/pkcs11"
)

// Client owns a single C_Initialize/C_Finalize lifetime and a pool of logged-in
// sessions. It is safe for concurrent use; methods acquire a session from the
// pool, run the operation, and return the session.
//
// One Client serves all OpenBao HSM features; callers obtain feature-specific
// behavior by calling the method they need (GenerateRandom, Wrap, Sign, ...).
type Client struct {
	cfg  Config
	ctx  *pkcs11.Ctx
	slot uint

	mu       sync.Mutex
	idle     []pkcs11.SessionHandle
	closed   bool
	sessions int
}

// NewClient opens the PKCS#11 library, finds the configured token, and returns
// a ready-to-use Client. The caller must invoke Close on shutdown.
func NewClient(cfg Config) (*Client, error) {
	if cfg.Library == "" {
		return nil, errors.New("pkcs11util: Library path is required")
	}

	ctx := pkcs11.New(cfg.Library)
	if ctx == nil {
		return nil, &ErrHSMUnavailable{Op: "load", Err: fmt.Errorf("could not load %s", cfg.Library)}
	}

	if err := ctx.Initialize(); err != nil {
		// CKR_CRYPTOKI_ALREADY_INITIALIZED is fine — another part of the
		// process initialized the same library first.
		var pErr pkcs11.Error
		if !errors.As(err, &pErr) || pErr != pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED {
			ctx.Destroy()
			return nil, &ErrHSMUnavailable{Op: "C_Initialize", Err: err}
		}
	}

	slot, err := findSlot(ctx, cfg)
	if err != nil {
		_ = ctx.Finalize()
		ctx.Destroy()
		return nil, err
	}

	return &Client{cfg: cfg, ctx: ctx, slot: slot}, nil
}

// Close releases all sessions and the library context. Safe to call multiple
// times.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true

	for _, s := range c.idle {
		_ = c.ctx.Logout(s)
		_ = c.ctx.CloseSession(s)
	}
	c.idle = nil

	_ = c.ctx.Finalize()
	c.ctx.Destroy()
	return nil
}

// GenerateRandom returns length bytes drawn from the HSM's RNG. This wraps
// C_GenerateRandom; on any transport-level failure we return ErrHSMUnavailable
// so callers can fail closed.
func (c *Client) GenerateRandom(ctx context.Context, length int) ([]byte, error) {
	if length <= 0 {
		return nil, errors.New("pkcs11util: length must be > 0")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	session, err := c.acquire()
	if err != nil {
		return nil, err
	}
	defer c.release(session)

	buf, err := c.ctx.GenerateRandom(session, length)
	if err != nil {
		// Any error from GenerateRandom means we either lost the session or
		// the token itself is gone; either way the augmentation source cannot
		// be trusted. Fail closed.
		return nil, &ErrHSMUnavailable{Op: "C_GenerateRandom", Err: err}
	}
	if len(buf) != length {
		return nil, &ErrHSMUnavailable{Op: "C_GenerateRandom", Err: fmt.Errorf("short read: got %d, want %d", len(buf), length)}
	}
	return buf, nil
}

// Reader returns an io.Reader backed by GenerateRandom. Reads of up to
// pkcs11MaxRandomChunk bytes are issued directly; larger reads are chunked.
func (c *Client) Reader(ctx context.Context) io.Reader {
	return &randomReader{c: c, ctx: ctx}
}

const pkcs11MaxRandomChunk = 4096

type randomReader struct {
	c   *Client
	ctx context.Context
}

func (r *randomReader) Read(p []byte) (int, error) {
	remaining := len(p)
	if remaining == 0 {
		return 0, nil
	}
	read := 0
	for remaining > 0 {
		n := remaining
		if n > pkcs11MaxRandomChunk {
			n = pkcs11MaxRandomChunk
		}
		buf, err := r.c.GenerateRandom(r.ctx, n)
		if err != nil {
			return read, err
		}
		copy(p[read:], buf)
		read += n
		remaining -= n
	}
	return read, nil
}

// acquire returns a logged-in session, reusing an idle one if available.
func (c *Client) acquire() (pkcs11.SessionHandle, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, errors.New("pkcs11util: client is closed")
	}
	if n := len(c.idle); n > 0 {
		s := c.idle[n-1]
		c.idle = c.idle[:n-1]
		c.mu.Unlock()
		return s, nil
	}
	c.sessions++
	c.mu.Unlock()

	session, err := c.ctx.OpenSession(c.slot, pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		c.mu.Lock()
		c.sessions--
		c.mu.Unlock()
		return 0, &ErrHSMUnavailable{Op: "C_OpenSession", Err: err}
	}

	if c.cfg.Pin != "" {
		if err := c.ctx.Login(session, pkcs11.CKU_USER, c.cfg.Pin); err != nil {
			var pErr pkcs11.Error
			// CKR_USER_ALREADY_LOGGED_IN is benign: the underlying token
			// treats login as a token-level state and another session may have
			// already logged in. The session is still usable.
			if !errors.As(err, &pErr) || pErr != pkcs11.CKR_USER_ALREADY_LOGGED_IN {
				_ = c.ctx.CloseSession(session)
				c.mu.Lock()
				c.sessions--
				c.mu.Unlock()
				return 0, &ErrHSMUnavailable{Op: "C_Login", Err: err}
			}
		}
	}
	return session, nil
}

func (c *Client) release(session pkcs11.SessionHandle) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		_ = c.ctx.CloseSession(session)
		return
	}
	c.idle = append(c.idle, session)
}

// findSlot resolves the configured token label or slot ID to a slot number.
func findSlot(ctx *pkcs11.Ctx, cfg Config) (uint, error) {
	slots, err := ctx.GetSlotList(true)
	if err != nil {
		return 0, &ErrHSMUnavailable{Op: "C_GetSlotList", Err: err}
	}
	if len(slots) == 0 {
		return 0, &ErrHSMUnavailable{Op: "C_GetSlotList", Err: errors.New("no tokens present")}
	}

	if cfg.TokenLabel != "" {
		for _, s := range slots {
			info, err := ctx.GetTokenInfo(s)
			if err != nil {
				continue
			}
			if info.Label == cfg.TokenLabel || trimLabel(info.Label) == cfg.TokenLabel {
				return s, nil
			}
		}
		return 0, fmt.Errorf("pkcs11util: no token with label %q", cfg.TokenLabel)
	}

	if cfg.SlotID >= 0 {
		for _, s := range slots {
			if s == uint(cfg.SlotID) {
				return s, nil
			}
		}
		return 0, fmt.Errorf("pkcs11util: slot %d not present", cfg.SlotID)
	}

	return slots[0], nil
}

// trimLabel strips the trailing spaces PKCS#11 uses to pad labels to 32 bytes.
func trimLabel(s string) string {
	for len(s) > 0 && s[len(s)-1] == ' ' {
		s = s[:len(s)-1]
	}
	return s
}
