// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package random

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/openbao/openbao/sdk/v2/framework"
)

// stubReader deterministically returns the same byte for every Read, so we
// can distinguish "seal source was actually used" from "platform was used
// under the hood" without needing real entropy.
type stubReader struct{ b byte }

func (s stubReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = s.b
	}
	return len(p), nil
}

func newFieldData(t *testing.T, source string, bytes int) *framework.FieldData {
	t.Helper()
	raw := map[string]interface{}{
		"format":   "base64",
		"bytes":    bytes,
		"urlbytes": "",
	}
	if source != "" {
		raw["source"] = source
	} else {
		raw["source"] = ""
	}
	return &framework.FieldData{
		Raw: raw,
		Schema: map[string]*framework.FieldSchema{
			"urlbytes": {Type: framework.TypeString},
			"bytes":    {Type: framework.TypeInt, Default: 32},
			"format":   {Type: framework.TypeString, Default: "base64"},
			"source":   {Type: framework.TypeString, Default: "platform"},
		},
	}
}

// TestHandleRandomAPI_SealSourceRequiresAugmenter verifies the fail-closed
// behavior mandated by issue #15: asking for source=seal when no augmenter
// is wired must error, not silently fall through to /dev/urandom.
func TestHandleRandomAPI_SealSourceRequiresAugmenter(t *testing.T) {
	d := newFieldData(t, "seal", 16)
	resp, err := HandleRandomAPI(d, rand.Reader)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected error response, got %+v", resp)
	}
	if !strings.Contains(resp.Error().Error(), "entropy augmentation") {
		t.Errorf("error = %v; want message about entropy augmentation", resp.Error())
	}
}

// TestHandleRandomAPI_SealSourceUsesAugmenter verifies that when a non-
// platform reader is passed we actually consume from it.
func TestHandleRandomAPI_SealSourceUsesAugmenter(t *testing.T) {
	stub := stubReader{b: 0xAB}
	d := newFieldData(t, "seal", 8)
	resp, err := HandleRandomAPI(d, stub)
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("unexpected err/resp: %v / %+v", err, resp)
	}
	got, err := base64.StdEncoding.DecodeString(resp.Data["random_bytes"].(string))
	if err != nil {
		t.Fatal(err)
	}
	want := bytes.Repeat([]byte{0xAB}, 8)
	if !bytes.Equal(got, want) {
		t.Errorf("got %x, want %x (augmenter reader was not used)", got, want)
	}
}

// TestHandleRandomAPI_AllUsesAugmenterWhenPresent — "all" with an augmenter
// must pick the augmenter; previously it always warned + fell through to
// /dev/urandom even if a real augmenter existed.
func TestHandleRandomAPI_AllUsesAugmenterWhenPresent(t *testing.T) {
	stub := stubReader{b: 0x7F}
	d := newFieldData(t, "all", 4)
	resp, err := HandleRandomAPI(d, stub)
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("unexpected err/resp: %v / %+v", err, resp)
	}
	if len(resp.Warnings) != 0 {
		t.Errorf("expected no warnings, got %v", resp.Warnings)
	}
	got, _ := base64.StdEncoding.DecodeString(resp.Data["random_bytes"].(string))
	if !bytes.Equal(got, bytes.Repeat([]byte{0x7F}, 4)) {
		t.Errorf("augmenter not used for source=all; got %x", got)
	}
}

// TestHandleRandomAPI_AllFallsBackToPlatform — without an augmenter "all"
// must fall back to /dev/urandom but emit a warning so the caller knows
// they're not getting HSM-mixed bytes.
func TestHandleRandomAPI_AllFallsBackToPlatform(t *testing.T) {
	d := newFieldData(t, "all", 16)
	resp, err := HandleRandomAPI(d, rand.Reader)
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("unexpected err/resp: %v / %+v", err, resp)
	}
	if len(resp.Warnings) == 0 {
		t.Errorf("expected a warning when no augmenter is configured")
	}
}

// TestHandleRandomAPI_PlatformIgnoresAugmenter — explicit source=platform
// must always pick /dev/urandom so operators can opt out of HSM dependency
// for a single call.
func TestHandleRandomAPI_PlatformIgnoresAugmenter(t *testing.T) {
	stub := stubReader{b: 0xCC}
	d := newFieldData(t, "platform", 16)
	resp, err := HandleRandomAPI(d, stub)
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("unexpected err/resp: %v / %+v", err, resp)
	}
	got, _ := base64.StdEncoding.DecodeString(resp.Data["random_bytes"].(string))
	// If platform mode leaked to the augmenter we'd get all 0xCC bytes.
	if bytes.Equal(got, bytes.Repeat([]byte{0xCC}, 16)) {
		t.Errorf("platform source leaked to augmenter reader")
	}
}
