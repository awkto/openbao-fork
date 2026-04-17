// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package random

import (
	"encoding/base64"
	"encoding/hex"
	"io"
	"strconv"

	"github.com/hashicorp/go-uuid"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const APIMaxBytes = 128 * 1024

// HandleRandomAPI implements sys/tools/random and its transit equivalent.
//
// entropyReader is the reader returned by b.GetRandomReader(): when the mount
// has external_entropy_access enabled AND an entropy augmentation source is
// configured, it returns HSM-derived bytes XOR'd with the OS PRNG; otherwise
// it returns crypto/rand.Reader. The "platform" source always uses the OS
// PRNG directly regardless of augmentation so callers can opt out of HSM
// dependency on a per-request basis.
func HandleRandomAPI(d *framework.FieldData, entropyReader io.Reader) (*logical.Response, error) {
	bytes := 0
	// Parsing is convoluted here, but allows operators to ACL both source and byte count
	maybeUrlBytes := d.Raw["urlbytes"]
	maybeSource := d.Raw["source"]
	source := "platform"
	var err error
	if maybeSource == "" {
		bytes = d.Get("bytes").(int)
	} else if maybeUrlBytes == "" && isValidSource(maybeSource.(string)) {
		source = maybeSource.(string)
		bytes = d.Get("bytes").(int)
	} else if maybeUrlBytes == "" {
		bytes, err = strconv.Atoi(maybeSource.(string))
		if err != nil {
			return logical.ErrorResponse("error parsing url-set byte count: %s", err), nil
		}
	} else {
		source = maybeSource.(string)
		bytes, err = strconv.Atoi(maybeUrlBytes.(string))
		if err != nil {
			return logical.ErrorResponse("error parsing url-set byte count: %s", err), nil
		}
	}
	format := d.Get("format").(string)

	if bytes < 1 {
		return logical.ErrorResponse("'bytes' cannot be less than 1"), nil
	}

	if bytes > APIMaxBytes {
		return logical.ErrorResponse("'bytes' should be less than %d", APIMaxBytes), nil
	}

	switch format {
	case "hex":
	case "base64":
	default:
		return logical.ErrorResponse("unsupported encoding format %q; must be \"hex\" or \"base64\"", format), nil
	}

	// isAugmented returns true when entropyReader is a non-nil reader that is
	// NOT the default platform reader (nil or crypto/rand.Reader). We use
	// pointer identity via a sentinel nil check; framework.Backend.
	// GetRandomReader returns crypto/rand.Reader when no augmenter is wired,
	// so we treat that as "no augmentation" by also accepting a nil
	// entropyReader for callers that want to explicitly signal that.
	augmented := entropyReader != nil && !isPlatformReader(entropyReader)

	var randBytes []byte
	var warning string
	switch source {
	case "", "platform":
		randBytes, err = uuid.GenerateRandomBytes(bytes)
		if err != nil {
			return nil, err
		}
	case "seal":
		if !augmented {
			// Fail closed: if the operator explicitly asked for seal-backed
			// entropy and the server has no augmenter wired, we refuse rather
			// than silently substituting /dev/urandom.
			return logical.ErrorResponse("source=seal requires entropy augmentation; configure an entropy \"seal\" { mode = \"augmentation\" } block and enable the mount with -external-entropy-access"), nil
		}
		randBytes = make([]byte, bytes)
		if _, err = io.ReadFull(entropyReader, randBytes); err != nil {
			return nil, err
		}
	case "all":
		if augmented {
			randBytes = make([]byte, bytes)
			if _, err = io.ReadFull(entropyReader, randBytes); err != nil {
				return nil, err
			}
		} else {
			warning = "no seal/entropy augmentation available, using platform entropy source"
			randBytes, err = uuid.GenerateRandomBytes(bytes)
			if err != nil {
				return nil, err
			}
		}
	default:
		return logical.ErrorResponse("unsupported entropy source %q; must be \"platform\" or \"seal\", or \"all\"", source), nil
	}

	var retStr string
	switch format {
	case "hex":
		retStr = hex.EncodeToString(randBytes)
	case "base64":
		retStr = base64.StdEncoding.EncodeToString(randBytes)
	}

	// Generate the response
	resp := &logical.Response{
		Data: map[string]interface{}{
			"random_bytes": retStr,
		},
	}
	if warning != "" {
		resp.Warnings = []string{warning}
	}
	return resp, nil
}

func isValidSource(s string) bool {
	switch s {
	case "", "platform", "seal", "all":
		return true
	}
	return false
}
