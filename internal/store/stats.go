package store

// Stats is the aggregate, non-personal usage snapshot exposed publicly at /stats.
// It contains only counts, no IPs, no per-user data, no channel ids.
type Stats struct {
	Channels        int64 `json:"channels"`
	RetainedChannels int64 `json:"retained_channels"`
	Accounts        int64 `json:"accounts"`
	RetainedMessages int64 `json:"retained_messages"`
	RetainedBytes   int64 `json:"retained_bytes"`
}

// ChannelInfo is per-channel METADATA for the admin listing. Never includes the
// secret, the K_auth, or any payload, only operational metadata.
type ChannelInfo struct {
	ID         string `json:"id"`
	OwnerID    string `json:"owner_id,omitempty"`
	Retained   bool   `json:"retained"`
	TTLSeconds int64  `json:"ttl_sec"`
	MaxBytes   int64  `json:"max_bytes"`
	MaxMsgs    int64  `json:"max_msgs"`
	Bytes      int64  `json:"bytes"`
	Msgs       int64  `json:"msgs"`
}

// Stats returns the aggregate snapshot. It scans channel metadata only.
func (s *Store) Stats() (Stats, error) {
	ids, err := s.rdb.SMembers(s.ctx, chansSet).Result()
	if err != nil {
		return Stats{}, err
	}
	var st Stats
	st.Channels = int64(len(ids))
	for _, id := range ids {
		c, err := s.GetChannel(id)
		if err != nil {
			continue
		}
		if c.Retained {
			st.RetainedChannels++
		}
		b, m, err := s.ChannelUsage(id)
		if err == nil {
			st.RetainedBytes += b
			st.RetainedMessages += m
		}
	}
	// account count: scan the keyspace for account hashes (small N; admin/stats only)
	var cursor uint64
	seen := map[string]struct{}{}
	for {
		keys, cur, err := s.rdb.Scan(s.ctx, cursor, "dt:acct:*", 200).Result()
		if err != nil {
			break
		}
		for _, k := range keys {
			// count only the base "dt:acct:<id>" hash, not "dt:acct:<id>:usage"
			if len(k) > len("dt:acct:") && k[len(k)-6:] != ":usage" {
				seen[k] = struct{}{}
			}
		}
		cursor = cur
		if cursor == 0 {
			break
		}
	}
	st.Accounts = int64(len(seen))
	return st, nil
}

// ListChannels returns per-channel metadata (admin only). No secrets, no payloads.
func (s *Store) ListChannels() ([]ChannelInfo, error) {
	ids, err := s.rdb.SMembers(s.ctx, chansSet).Result()
	if err != nil {
		return nil, err
	}
	out := make([]ChannelInfo, 0, len(ids))
	for _, id := range ids {
		c, err := s.GetChannel(id)
		if err != nil {
			continue
		}
		b, m, _ := s.ChannelUsage(id)
		out = append(out, ChannelInfo{
			ID: id, OwnerID: c.OwnerID, Retained: c.Retained,
			TTLSeconds: c.TTLSeconds, MaxBytes: c.MaxBytes, MaxMsgs: c.MaxMsgs,
			Bytes: b, Msgs: m,
		})
	}
	return out, nil
}
