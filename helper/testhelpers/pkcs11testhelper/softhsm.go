// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

//go:build hsm && (linux || darwin)

// Package pkcs11testhelper provisions an ephemeral SoftHSMv2 token for tests.
// Each call to NewSoftHSM returns a fully initialized token in a private
// tmpdir; t.Cleanup tears it down. Intended to be shared by the entropy-
// augmentation, seal-wrap, and external-keys test suites.
package pkcs11testhelper

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/openbao/openbao/helper/pkcs11util"
)

// Fixture holds everything a test needs to talk to the ephemeral SoftHSM
// token it provisioned.
type Fixture struct {
	Library    string
	TokenLabel string
	Pin        string
	SOPin      string
	ConfigPath string
}

// Config returns a pkcs11util.Config that points at this fixture.
func (f *Fixture) Config() pkcs11util.Config {
	return pkcs11util.Config{
		Library:    f.Library,
		TokenLabel: f.TokenLabel,
		SlotID:     -1,
		Pin:        f.Pin,
	}
}

// NewSoftHSM initializes a SoftHSM token in a tmpdir and returns the fixture.
// The test is skipped if softhsm2-util or the SoftHSM library cannot be found.
// On success, SOFTHSM2_CONF is set in the process environment for the duration
// of the test (SoftHSM's library reads it at load time).
func NewSoftHSM(t *testing.T) *Fixture {
	t.Helper()

	utilPath, err := exec.LookPath("softhsm2-util")
	if err != nil {
		t.Skipf("softhsm2-util not installed: %v", err)
	}

	lib := findSoftHSMLibrary()
	if lib == "" {
		t.Skip("libsofthsm2.so not found in known locations")
	}

	dir := t.TempDir()
	tokenDir := filepath.Join(dir, "tokens")
	if err := os.MkdirAll(tokenDir, 0o700); err != nil {
		t.Fatalf("mkdir tokens: %v", err)
	}

	confPath := filepath.Join(dir, "softhsm2.conf")
	conf := fmt.Sprintf("directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\nslots.removable = false\nslots.mechanisms = ALL\n", tokenDir)
	if err := os.WriteFile(confPath, []byte(conf), 0o600); err != nil {
		t.Fatalf("write softhsm2.conf: %v", err)
	}

	// SoftHSM reads SOFTHSM2_CONF when the library is first loaded. Set it
	// in the current process so that subsequent pkcs11.New(lib) calls from
	// the test pick up this config. t.Setenv restores on cleanup.
	t.Setenv("SOFTHSM2_CONF", confPath)

	label := fmt.Sprintf("ob-test-%d", os.Getpid())
	pin := "1234"
	soPin := "5678"

	cmd := exec.Command(utilPath,
		"--init-token", "--free",
		"--label", label,
		"--pin", pin,
		"--so-pin", soPin,
	)
	cmd.Env = append(os.Environ(), "SOFTHSM2_CONF="+confPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("softhsm2-util init-token failed: %v\n%s", err, out)
	}

	return &Fixture{
		Library:    lib,
		TokenLabel: label,
		Pin:        pin,
		SOPin:      soPin,
		ConfigPath: confPath,
	}
}

// findSoftHSMLibrary returns the filesystem path to libsofthsm2, or "" if
// not found.
func findSoftHSMLibrary() string {
	if override := os.Getenv("OPENBAO_TEST_SOFTHSM_LIB"); override != "" {
		if _, err := os.Stat(override); err == nil {
			return override
		}
	}
	candidates := []string{
		"/usr/lib/softhsm/libsofthsm2.so",
		"/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
		"/usr/local/lib/softhsm/libsofthsm2.so",
		"/opt/homebrew/lib/softhsm/libsofthsm2.so",
		"/usr/local/Cellar/softhsm/2.6.1/lib/softhsm/libsofthsm2.so",
	}
	if runtime.GOOS == "darwin" {
		candidates = append(candidates,
			"/opt/homebrew/opt/softhsm/lib/softhsm/libsofthsm2.so",
			"/usr/local/opt/softhsm/lib/softhsm/libsofthsm2.so",
		)
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	// Best-effort fallback via `pkg-config --variable=libdir softhsm2` etc.
	// is deliberately not attempted to keep tests hermetic.
	_ = strings.TrimSpace
	return ""
}
