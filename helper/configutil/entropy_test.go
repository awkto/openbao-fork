// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package configutil

import (
	"strings"
	"testing"
)

func TestParseEntropy_Augmentation(t *testing.T) {
	conf := `
disable_mlock = true
entropy "seal" {
  mode = "augmentation"
}
`
	c, err := ParseConfig(conf)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if c.Entropy == nil {
		t.Fatal("expected Entropy to be set")
	}
	if c.Entropy.Source != "seal" {
		t.Errorf("Source = %q, want %q", c.Entropy.Source, "seal")
	}
	if c.Entropy.Mode != "augmentation" {
		t.Errorf("Mode = %q, want %q", c.Entropy.Mode, "augmentation")
	}
}

func TestParseEntropy_RejectsUnknownSource(t *testing.T) {
	conf := `
disable_mlock = true
entropy "pkcs11" {
  mode = "augmentation"
}
`
	_, err := ParseConfig(conf)
	if err == nil {
		t.Fatal("expected error for unsupported source")
	}
	if !strings.Contains(err.Error(), "unsupported source") {
		t.Errorf("error = %v, want 'unsupported source'", err)
	}
}

func TestParseEntropy_RejectsUnknownMode(t *testing.T) {
	conf := `
disable_mlock = true
entropy "seal" {
  mode = "replacement"
}
`
	_, err := ParseConfig(conf)
	if err == nil {
		t.Fatal("expected error for unsupported mode")
	}
	if !strings.Contains(err.Error(), "unsupported mode") {
		t.Errorf("error = %v, want 'unsupported mode'", err)
	}
}

func TestParseEntropy_AbsentIsNil(t *testing.T) {
	conf := `
disable_mlock = true
seal "shamir" {}
`
	c, err := ParseConfig(conf)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if c.Entropy != nil {
		t.Errorf("Entropy should be nil when not configured, got %+v", c.Entropy)
	}
}

func TestParseEntropy_AtMostOne(t *testing.T) {
	conf := `
disable_mlock = true
entropy "seal" { mode = "augmentation" }
entropy "seal" { mode = "augmentation" }
`
	_, err := ParseConfig(conf)
	if err == nil {
		t.Fatal("expected error for two entropy blocks")
	}
}
