// Package admin is doublethink's operator-privilege layer (docs/DESIGN-M2.md
// decision 6). The operator sets a high-entropy admin key in the environment
// (DOUBLETHINK_ADMIN_KEY); presenting it unlocks admin-only operations such as
// raising limits for preferred channels or accounts and reading usage metadata.
//
// Fail-safe rules (load-bearing):
//   - If the env var is unset or empty, admin is DISABLED: Enabled() is false and
//     every Verify returns false. No admin key means no admin surface, not an open
//     one.
//   - A weak key (shorter than minKeyLen) also disables admin, with a startup
//     warning, so a trivially guessable key cannot be brute-forced.
//   - The key is compared in constant time and is never logged or returned.
//
// The admin key grants metadata/limit control only. It does NOT grant access to
// any channel's payloads: those are end-to-end encrypted under the channel secret
// S, which the broker never holds.
package admin

import (
	"crypto/subtle"
	"os"
)

// EnvVar is the environment variable the operator sets to enable admin.
const EnvVar = "DOUBLETHINK_ADMIN_KEY"

// minKeyLen is the minimum admin-key length; shorter keys disable admin.
const minKeyLen = 32

// Admin holds the configured admin key (or empty if disabled).
type Admin struct {
	key     string
	enabled bool
}

// FromEnv reads DOUBLETHINK_ADMIN_KEY. It returns the Admin plus a human-readable
// status string for the startup log (which never contains the key itself).
func FromEnv() (*Admin, string) {
	return From(os.Getenv(EnvVar))
}

// From builds an Admin from a raw key value (env injection point; testable).
func From(key string) (*Admin, string) {
	switch {
	case key == "":
		return &Admin{enabled: false}, "admin API disabled (" + EnvVar + " not set)"
	case len(key) < minKeyLen:
		return &Admin{enabled: false}, "admin API disabled (" + EnvVar + " too short; need >= 32 chars)"
	default:
		return &Admin{key: key, enabled: true}, "admin API enabled"
	}
}

// Enabled reports whether admin operations are available.
func (a *Admin) Enabled() bool { return a.enabled }

// Verify reports whether the presented key matches the configured admin key, in
// constant time. Always false when admin is disabled.
func (a *Admin) Verify(presented string) bool {
	if !a.enabled {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(presented), []byte(a.key)) == 1
}
