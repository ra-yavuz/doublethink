package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func openTemp(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestAccountAndChannelCRUD(t *testing.T) {
	s := openTemp(t)
	if err := s.CreateAccount("acct1", "hash1"); err != nil {
		t.Fatal(err)
	}
	if h, err := s.AccountKeyHash("acct1"); err != nil || h != "hash1" {
		t.Fatalf("key hash = %q, %v", h, err)
	}
	if _, err := s.AccountKeyHash("nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing account = %v, want ErrNotFound", err)
	}

	ch := Channel{ID: "c1", OwnerID: "acct1", KAuth: "ka", Retained: true, TTLSeconds: 3600, MaxBytes: 1000, MaxMsgs: 5}
	if err := s.CreateChannel(ch, 100); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateChannel(ch, 100); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate channel = %v, want ErrExists", err)
	}
	got, err := s.GetChannel("c1")
	if err != nil || !got.Retained || got.OwnerID != "acct1" || got.MaxMsgs != 5 {
		t.Fatalf("GetChannel = %+v, %v", got, err)
	}
}

func TestChannelsPerAccountCap(t *testing.T) {
	s := openTemp(t)
	s.CreateAccount("a", "h")
	for i := 0; i < 3; i++ {
		ch := Channel{ID: fmt.Sprintf("c%d", i), OwnerID: "a", KAuth: "k", Retained: true}
		if err := s.CreateChannel(ch, 3); err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
	}
	over := Channel{ID: "c3", OwnerID: "a", KAuth: "k", Retained: true}
	if err := s.CreateChannel(over, 3); !errors.Is(err, ErrTooManyChan) {
		t.Fatalf("over-cap create = %v, want ErrTooManyChan", err)
	}
}

// seq is monotonic and catch-up returns seq>cursor in order.
func TestAppendSeqAndCatchUp(t *testing.T) {
	s := openTemp(t)
	s.CreateAccount("a", "h")
	s.CreateChannel(Channel{ID: "c", OwnerID: "a", KAuth: "k", Retained: true, TTLSeconds: 3600, MaxMsgs: 100}, 100)

	for i := 0; i < 5; i++ {
		seq, err := s.Append("c", fmt.Sprintf("m%d", i), "progress", "ts", []byte(fmt.Sprintf("blob%d", i)), 0)
		if err != nil {
			t.Fatal(err)
		}
		if seq != int64(i+1) {
			t.Fatalf("msg %d got seq %d, want %d (monotonic from 1)", i, seq, i+1)
		}
	}
	// Catch up from seq 2: expect seq 3,4,5.
	msgs, err := s.CatchUp("c", 2, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 3 {
		t.Fatalf("catch-up after 2 got %d messages, want 3", len(msgs))
	}
	for i, m := range msgs {
		wantSeq := int64(i + 3)
		if m.Seq != wantSeq {
			t.Errorf("msg %d seq = %d, want %d (order)", i, m.Seq, wantSeq)
		}
	}
	if string(msgs[0].Ciphertext) != "blob2" {
		t.Errorf("first caught-up blob = %q, want blob2", msgs[0].Ciphertext)
	}
}

// Ring buffer: max_msgs evicts oldest.
func TestRingBufferMaxMsgs(t *testing.T) {
	s := openTemp(t)
	s.CreateAccount("a", "h")
	s.CreateChannel(Channel{ID: "c", OwnerID: "a", KAuth: "k", Retained: true, TTLSeconds: 3600, MaxMsgs: 3}, 100)
	for i := 0; i < 6; i++ {
		if _, err := s.Append("c", "", "", "", []byte("x"), 0); err != nil {
			t.Fatal(err)
		}
	}
	_, msgs, _ := s.ChannelUsage("c")
	if msgs != 3 {
		t.Fatalf("msgs after 6 appends with cap 3 = %d, want 3", msgs)
	}
	// Catch-up from 0 should return only the surviving (newest 3): seq 4,5,6.
	got, _ := s.CatchUp("c", 0, 100)
	if len(got) != 3 || got[0].Seq != 4 {
		t.Fatalf("survivors = %d starting at seq %d, want 3 starting at 4", len(got), got[0].Seq)
	}
}

// Ring buffer: max_bytes evicts oldest.
func TestRingBufferMaxBytes(t *testing.T) {
	s := openTemp(t)
	s.CreateChannel(Channel{ID: "c", KAuth: "k", Retained: true, TTLSeconds: 3600, MaxBytes: 30}, 100)
	for i := 0; i < 10; i++ {
		if _, err := s.Append("c", "", "", "", []byte("0123456789"), 0); err != nil { // 10 bytes each
			t.Fatal(err)
		}
	}
	bytes, _, _ := s.ChannelUsage("c")
	if bytes > 30 {
		t.Fatalf("bytes = %d, want <= 30 (cap)", bytes)
	}
}

// Account storage cap rejects an append that would exceed it.
func TestAccountByteCap(t *testing.T) {
	s := openTemp(t)
	s.CreateAccount("a", "h")
	s.CreateChannel(Channel{ID: "c", OwnerID: "a", KAuth: "k", Retained: true, TTLSeconds: 3600, MaxMsgs: 1000}, 100)
	// cap = 25 bytes; each msg 10 bytes. 3rd should be rejected (20+10 > 25).
	if _, err := s.Append("c", "", "", "", []byte("0123456789"), 25); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Append("c", "", "", "", []byte("0123456789"), 25); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Append("c", "", "", "", []byte("0123456789"), 25); !errors.Is(err, ErrQuotaAcct) {
		t.Fatalf("3rd append = %v, want ErrQuotaAcct", err)
	}
}

// TTL prune removes expired messages and they are not caught up.
func TestPruneExpired(t *testing.T) {
	base := int64(1_000_000)
	cur := base
	realNow := nowUnix
	nowUnix = func() int64 { return cur }
	defer func() { nowUnix = realNow }()

	s := openTemp(t)
	s.CreateChannel(Channel{ID: "c", KAuth: "k", Retained: true, TTLSeconds: 100, MaxMsgs: 1000}, 100)
	s.Append("c", "", "", "", []byte("old"), 0) // expires at base+100

	cur = base + 50
	s.Append("c", "", "", "", []byte("new"), 0) // expires at base+150

	// Advance past the first message's TTL but not the second's.
	cur = base + 120
	n, err := s.PruneExpired()
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("pruned %d, want 1", n)
	}
	got, _ := s.CatchUp("c", 0, 100)
	if len(got) != 1 || string(got[0].Ciphertext) != "new" {
		t.Fatalf("after prune, survivors = %v, want just 'new'", got)
	}
}

// Migration from an M1 JSON state is idempotent and grandfathers channels.
func TestMigrateLegacyJSON(t *testing.T) {
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "state.json")
	os.WriteFile(jsonPath, []byte(`{"channels":{"codespeak/old1":"KA1","codespeak/old2":"KA2"}}`), 0o600)

	s := openTemp(t)
	n, err := s.MigrateLegacyJSON(jsonPath)
	if err != nil || n != 2 {
		t.Fatalf("migrate imported %d, %v; want 2", n, err)
	}
	c, err := s.GetChannel("codespeak/old1")
	if err != nil || c.KAuth != "KA1" || c.Retained || c.OwnerID != "" {
		t.Fatalf("migrated channel = %+v, %v (want ephemeral, no owner, KA1)", c, err)
	}
	// Idempotent: re-run imports nothing new.
	n2, _ := s.MigrateLegacyJSON(jsonPath)
	if n2 != 0 {
		t.Fatalf("re-migrate imported %d, want 0 (idempotent)", n2)
	}
}

func TestMigrateNoFile(t *testing.T) {
	s := openTemp(t)
	if n, err := s.MigrateLegacyJSON(filepath.Join(t.TempDir(), "nope.json")); err != nil || n != 0 {
		t.Fatalf("migrate of missing file = %d, %v; want 0, nil", n, err)
	}
}
