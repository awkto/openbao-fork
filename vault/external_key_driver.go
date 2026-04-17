// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path"
	"sync"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// ExternalKeyDriver opens a concrete key backed by an external KMS/HSM.
// Each configured `external_keys "<type>"` server stanza registers a
// driver; the Registry dispatches to the right one based on
// ExternalKeyConfig.Type at Open time.
//
// Drivers must be safe for concurrent use. Closing an ExternalKey must
// release any per-key session without impacting other handles served by
// the same driver.
type ExternalKeyDriver interface {
	// Type returns the registered driver name, e.g. "pkcs11". Used by the
	// registry for diagnostics and driver lookup logging.
	Type() string

	// OpenKey returns a logical.ExternalKey bound to the (config, key)
	// pair. configValues comes from ExternalKeyConfig.Values (connection
	// parameters set in the server config stanza plus any sys/external-
	// keys/configs/<name> overrides). keyValues comes from the registered
	// key entry (typically label/id).
	OpenKey(ctx context.Context, configValues, keyValues map[string]string) (logical.ExternalKey, error)

	// Close is called at Registry teardown so the driver can release
	// long-lived resources (e.g. an open PKCS#11 library context).
	Close() error
}

// driverRegistry is the process-global set of registered drivers.
// Populated at init() time from the build-tag-gated driver files so a
// non-HSM build has zero PKCS#11 symbols.
var (
	driverRegistry     = map[string]func() (ExternalKeyDriver, error){}
	driverRegistryLock sync.RWMutex
)

// RegisterExternalKeyDriver wires up a driver factory. Call from init()
// in the driver's build-tagged file. It is an error to register the same
// type twice — catches accidental double-registration.
func RegisterExternalKeyDriver(typeName string, factory func() (ExternalKeyDriver, error)) {
	driverRegistryLock.Lock()
	defer driverRegistryLock.Unlock()
	if _, ok := driverRegistry[typeName]; ok {
		panic(fmt.Sprintf("external-keys: driver %q already registered", typeName))
	}
	driverRegistry[typeName] = factory
}

// lookupDriver resolves a type name to a ready-to-use driver instance.
// Registry callers must Close the returned driver when done.
func lookupDriver(typeName string) (ExternalKeyDriver, error) {
	driverRegistryLock.RLock()
	factory, ok := driverRegistry[typeName]
	driverRegistryLock.RUnlock()
	if !ok {
		return nil, fmt.Errorf("external-keys: no driver registered for type %q (built without -tags hsm?)", typeName)
	}
	return factory()
}

// OpenKey is the one-call entrypoint a mount uses to get a
// logical.ExternalKey. The mount supplies the config name (as declared in
// the server's external_keys stanzas or in sys/external-keys/configs) and
// the key name registered under it via sys/external-keys/configs/<c>/
// keys/<k>. Resolution flow:
//
//  1. Read the config (following `inherits = "…"` chains if present).
//  2. Read the key entry.
//  3. Dispatch to the type's registered driver.
//  4. Ask the driver to open and return a logical.ExternalKey.
//
// The caller is responsible for calling Close on the returned key when
// done so per-HSM-session resources can be released.
func (r *ExternalKeyRegistry) OpenKey(ctx context.Context, storage logical.Storage, configName, keyName string) (logical.ExternalKey, error) {
	if r == nil {
		return nil, errors.New("external-keys: registry not initialized")
	}

	r.storageLock.RLock()
	defer r.storageLock.RUnlock()

	config, err := r.resolveConfig(ctx, storage, configName)
	if err != nil {
		return nil, err
	}

	fullKey := path.Join(configName, keyName)
	key, err := r.getKeyCommon(ctx, storage, fullKey)
	switch {
	case err != nil:
		return nil, err
	case key == nil:
		return nil, logical.CodedError(http.StatusNotFound, fmt.Sprintf("external-keys: key %q not registered", fullKey))
	}

	driver, err := lookupDriver(config.Type)
	if err != nil {
		return nil, err
	}

	// Merge config values and key values into a single map the driver
	// consumes. Key values win on conflicts so per-key overrides work.
	merged := make(map[string]string, len(config.Values)+len(key.Values))
	for k, v := range config.Values {
		merged[k] = v
	}
	for k, v := range key.Values {
		merged[k] = v
	}

	opened, err := driver.OpenKey(ctx, config.Values, merged)
	if err != nil {
		_ = driver.Close()
		return nil, fmt.Errorf("external-keys: driver %q failed to open key %q: %w", config.Type, fullKey, err)
	}

	// Wrap so Close on the returned key also closes the driver. This
	// keeps the lifecycle contract one-shot: callers only need to manage
	// the ExternalKey they received.
	return &driverScopedKey{ExternalKey: opened, driver: driver}, nil
}

// resolveConfig walks `inherits = "<parent>"` chains. In v1 the RFC
// restricts inheritance to the direct parent namespace; we just follow
// within a single namespace's view here (cross-namespace inheritance is
// already enforced by the storage view the registry operates on).
func (r *ExternalKeyRegistry) resolveConfig(ctx context.Context, storage logical.Storage, name string) (*ExternalKeyConfig, error) {
	seen := map[string]struct{}{}
	for {
		if _, looped := seen[name]; looped {
			return nil, fmt.Errorf("external-keys: inheritance cycle detected at config %q", name)
		}
		seen[name] = struct{}{}

		config, err := r.getConfigCommon(ctx, storage, name)
		switch {
		case err != nil:
			return nil, err
		case config == nil:
			return nil, logical.CodedError(http.StatusNotFound, fmt.Sprintf("external-keys: config %q not found", name))
		}
		if config.Inherits == "" {
			return config, nil
		}
		name = config.Inherits
	}
}

// driverScopedKey ties a logical.ExternalKey to the driver that produced
// it, so closing the key closes the driver too. Without this, every
// OpenKey call would leak the driver's library context.
type driverScopedKey struct {
	logical.ExternalKey
	driver ExternalKeyDriver
	once   sync.Once
}

func (k *driverScopedKey) Close() error {
	var err error
	k.once.Do(func() {
		keyErr := k.ExternalKey.Close()
		drvErr := k.driver.Close()
		switch {
		case keyErr != nil:
			err = keyErr
		case drvErr != nil:
			err = drvErr
		}
	})
	return err
}

