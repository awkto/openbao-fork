// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package configutil

import (
	"fmt"
	"strings"

	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
)

// Entropy describes an `entropy { ... }` config block. In v1 only the
// `entropy "seal" { mode = "augmentation" }` form is supported: it draws
// hardware randomness from the already-configured PKCS#11 seal and mixes it
// with the OS PRNG for mounts that opt in via -external-entropy-access.
//
// Shape matches Vault Enterprise's entropy stanza so operators migrating over
// can keep their config.
type Entropy struct {
	// Source is the kind of backing source. Only "seal" is accepted in v1.
	Source string

	// Mode controls how the source is consumed. Only "augmentation" is
	// accepted in v1 — we blend HSM bytes with /dev/urandom rather than
	// using the HSM alone.
	Mode string
}

const (
	EntropySourceSeal       = "seal"
	EntropyModeAugmentation = "augmentation"
)

// Validate checks that Source and Mode are values we actually support.
func (e *Entropy) Validate() error {
	if e == nil {
		return nil
	}
	if e.Source != EntropySourceSeal {
		return fmt.Errorf("entropy: unsupported source %q (only %q is implemented)", e.Source, EntropySourceSeal)
	}
	if e.Mode != EntropyModeAugmentation {
		return fmt.Errorf("entropy: unsupported mode %q (only %q is implemented)", e.Mode, EntropyModeAugmentation)
	}
	return nil
}

// parseEntropy parses one or more `entropy` blocks. Only one block is allowed.
// The syntax mirrors Vault Enterprise for operator familiarity.
func parseEntropy(result *SharedConfig, list *ast.ObjectList, blockName string) error {
	if len(list.Items) > 1 {
		return fmt.Errorf("at most one %q block is permitted", blockName)
	}

	item := list.Items[0]
	key := ""
	if len(item.Keys) > 0 {
		key = strings.ToLower(item.Keys[0].Token.Value().(string))
	}
	if key == "" {
		return fmt.Errorf("%s block requires a source label, e.g. %s \"seal\" { ... }", blockName, blockName)
	}

	var m map[string]interface{}
	if err := hcl.DecodeObject(&m, item.Val); err != nil {
		return multierror.Prefix(err, fmt.Sprintf("%s.%s:", blockName, key))
	}

	entropy := &Entropy{Source: key}
	if v, ok := m["mode"]; ok {
		mode, ok := v.(string)
		if !ok {
			return fmt.Errorf("entropy.%s: 'mode' must be a string", key)
		}
		entropy.Mode = strings.ToLower(mode)
	}

	if err := entropy.Validate(); err != nil {
		return err
	}

	result.Entropy = entropy
	return nil
}
