package store

import (
	"errors"
	"testing"
)

func TestGrantIssueAndRedeem(t *testing.T) {
	s := startRedis(t)
	// A permanent, uncapped grant bound to an exact channel id.
	ticket, err := s.IssueGrant(Grant{ChannelMatch: "perm/topic-1", Retained: true, TTLSeconds: 0, MaxBytes: 0, MaxMsgs: 0}, 600)
	if err != nil {
		t.Fatal(err)
	}
	if ticket == "" {
		t.Fatal("empty ticket")
	}
	if err := s.CreateChannelWithTicket(ticket, "perm/topic-1", "kauth", ""); err != nil {
		t.Fatalf("redeem: %v", err)
	}
	// The created channel has the TICKET's policy (permanent, uncapped), not defaults.
	c, err := s.GetChannel("perm/topic-1")
	if err != nil || !c.Retained || c.TTLSeconds != 0 || c.MaxMsgs != 0 || c.MaxBytes != 0 {
		t.Fatalf("channel policy from ticket = %+v %v (want retained, ttl0, uncapped)", c, err)
	}
}

func TestGrantSingleUse(t *testing.T) {
	s := startRedis(t)
	ticket, _ := s.IssueGrant(Grant{ChannelMatch: "c1", Retained: true}, 600)
	if err := s.CreateChannelWithTicket(ticket, "c1", "k", ""); err != nil {
		t.Fatal(err)
	}
	// Replaying the same ticket for a different channel must fail (consumed).
	if err := s.CreateChannelWithTicket(ticket, "c2", "k", ""); !errors.Is(err, ErrBadTicket) {
		t.Fatalf("replay = %v, want ErrBadTicket", err)
	}
}

func TestGrantChannelMismatch(t *testing.T) {
	s := startRedis(t)
	ticket, _ := s.IssueGrant(Grant{ChannelMatch: "allowed", Retained: true}, 600)
	// Using the ticket for a channel it does not authorize must fail (and not consume).
	if err := s.CreateChannelWithTicket(ticket, "other", "k", ""); !errors.Is(err, ErrBadTicket) {
		t.Fatalf("mismatch = %v, want ErrBadTicket", err)
	}
	// The ticket should still be usable for its bound channel (not consumed on mismatch).
	if err := s.CreateChannelWithTicket(ticket, "allowed", "k", ""); err != nil {
		t.Fatalf("bound channel after mismatch attempt: %v", err)
	}
}

func TestGrantPrefixMatch(t *testing.T) {
	s := startRedis(t)
	ticket, _ := s.IssueGrant(Grant{ChannelMatch: "team-x/*", Retained: true, TTLSeconds: 0}, 600)
	if err := s.CreateChannelWithTicket(ticket, "team-x/anything", "k", ""); err != nil {
		t.Fatalf("prefix redeem: %v", err)
	}
	// A channel outside the prefix is rejected by a fresh ticket.
	t2, _ := s.IssueGrant(Grant{ChannelMatch: "team-x/*", Retained: true}, 600)
	if err := s.CreateChannelWithTicket(t2, "team-y/nope", "k", ""); !errors.Is(err, ErrBadTicket) {
		t.Fatalf("outside-prefix = %v, want ErrBadTicket", err)
	}
}

func TestGrantUnknownTicket(t *testing.T) {
	s := startRedis(t)
	if err := s.CreateChannelWithTicket("does-not-exist", "c", "k", ""); !errors.Is(err, ErrBadTicket) {
		t.Fatalf("unknown ticket = %v, want ErrBadTicket", err)
	}
}

func TestChannelMatchesHelper(t *testing.T) {
	cases := []struct {
		match, id string
		want      bool
	}{
		{"a", "a", true},
		{"a", "b", false},
		{"team/*", "team/x", true},
		{"team/*", "team/x/y", true},
		{"team/*", "teamx", false},
		{"team/*", "other/x", false},
	}
	for _, c := range cases {
		if got := channelMatches(c.match, c.id); got != c.want {
			t.Errorf("channelMatches(%q,%q)=%v want %v", c.match, c.id, got, c.want)
		}
	}
}
