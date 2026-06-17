package store

import (
	"encoding/json"
	"errors"
	"os"
)

// legacyState mirrors the M1 JSON state file: channel id -> base32 K_auth.
type legacyState struct {
	Channels map[string]string `json:"channels"`
}

// MigrateLegacyJSON imports channels from an M1 state.json into the store, if the
// file exists. Existing M1 channels are grandfathered: ephemeral (not retained),
// no owner (legacy), keeping their K_auth so already-paired peers keep working.
// Idempotent: a channel already in the store is skipped, so re-running is safe and
// a half-finished migration can be resumed. Returns the number of channels imported.
//
// It does NOT delete the JSON file; the caller decides when to retire it, so a
// migration can be verified before the source is removed.
func (s *Store) MigrateLegacyJSON(jsonPath string) (int, error) {
	b, err := os.ReadFile(jsonPath)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil // nothing to migrate
	}
	if err != nil {
		return 0, err
	}
	var ls legacyState
	if err := json.Unmarshal(b, &ls); err != nil {
		return 0, err
	}
	imported := 0
	for id, kauth := range ls.Channels {
		if s.HasChannel(id) {
			continue // already migrated; idempotent
		}
		// Grandfathered: ephemeral, no owner, original K_auth preserved.
		ch := Channel{ID: id, KAuth: kauth, Retained: false}
		if err := s.CreateChannel(ch, 1<<30); err != nil {
			if errors.Is(err, ErrExists) {
				continue
			}
			return imported, err
		}
		imported++
	}
	return imported, nil
}
