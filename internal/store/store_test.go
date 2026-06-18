package store

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// startRedis boots a throwaway redis-server on a unix socket in a temp dir and
// returns a connected Store. Requires redis-server on PATH (the dev container has
// it). Skips the test if it is absent.
func startRedis(t *testing.T) *Store {
	t.Helper()
	bin, err := exec.LookPath("redis-server")
	if err != nil {
		t.Skip("redis-server not on PATH; skipping Redis store tests")
	}
	dir := t.TempDir()
	// Use a TCP port derived from nothing fixed: let redis pick by binding :0 is not
	// supported, so use a unix socket which avoids port collisions entirely.
	sock := filepath.Join(dir, "r.sock")
	cmd := exec.Command(bin,
		"--port", "0", // disable TCP
		"--unixsocket", sock,
		"--save", "", // no RDB in tests
		"--appendonly", "no",
		"--dir", dir,
	)
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		t.Fatalf("start redis: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })

	// Wait for the socket to accept.
	var s *Store
	for i := 0; i < 100; i++ {
		s, err = Open("unix://" + sock)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if s == nil {
		t.Fatalf("could not connect to redis: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestAccountAndChannelCRUD(t *testing.T) {
	s := startRedis(t)
	if err := s.CreateAccount("a", "hash1"); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateAccount("a", "hash2"); !errors.Is(err, ErrExists) {
		t.Fatalf("dup account = %v, want ErrExists", err)
	}
	if h, err := s.AccountKeyHash("a"); err != nil || h != "hash1" {
		t.Fatalf("hash = %q %v", h, err)
	}
	if _, err := s.AccountKeyHash("nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing acct = %v", err)
	}
	ch := Channel{ID: "c1", OwnerID: "a", KAuth: "ka", Retained: true, TTLSeconds: 3600, MaxBytes: 1000, MaxMsgs: 5}
	if err := s.CreateChannel(ch, 100); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateChannel(ch, 100); !errors.Is(err, ErrExists) {
		t.Fatalf("dup channel = %v", err)
	}
	got, err := s.GetChannel("c1")
	if err != nil || !got.Retained || got.OwnerID != "a" || got.MaxMsgs != 5 {
		t.Fatalf("GetChannel = %+v %v", got, err)
	}
	if !s.HasChannel("c1") || s.HasChannel("nope") {
		t.Fatal("HasChannel wrong")
	}
	if ka, _ := s.AllChannelKAuth(); ka["c1"] != "ka" {
		t.Fatalf("AllChannelKAuth = %v", ka)
	}
}

func TestChannelsPerAccountCap(t *testing.T) {
	s := startRedis(t)
	s.CreateAccount("a", "h")
	for i := 0; i < 3; i++ {
		if err := s.CreateChannel(Channel{ID: fmt.Sprintf("c%d", i), OwnerID: "a", KAuth: "k", Retained: true}, 3); err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
	}
	if err := s.CreateChannel(Channel{ID: "c3", OwnerID: "a", KAuth: "k", Retained: true}, 3); !errors.Is(err, ErrTooManyChan) {
		t.Fatalf("over cap = %v, want ErrTooManyChan", err)
	}
}

func TestAppendSeqAndCatchUp(t *testing.T) {
	s := startRedis(t)
	s.CreateChannel(Channel{ID: "c", KAuth: "k", Retained: true, TTLSeconds: 3600, MaxMsgs: 100}, 0)
	for i := 0; i < 5; i++ {
		seq, err := s.Append("c", "", "", "", []byte(fmt.Sprintf("blob%d", i)), 0)
		if err != nil {
			t.Fatal(err)
		}
		if seq != int64(i+1) {
			t.Fatalf("msg %d seq = %d, want %d", i, seq, i+1)
		}
	}
	msgs, err := s.CatchUp("c", 2, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 3 || msgs[0].Seq != 3 || string(msgs[0].Ciphertext) != "blob2" {
		t.Fatalf("catch-up after 2 = %+v", msgs)
	}
}

func TestRingBufferMaxMsgs(t *testing.T) {
	s := startRedis(t)
	s.CreateChannel(Channel{ID: "c", KAuth: "k", Retained: true, TTLSeconds: 3600, MaxMsgs: 3}, 0)
	for i := 0; i < 6; i++ {
		if _, err := s.Append("c", "", "", "", []byte("x"), 0); err != nil {
			t.Fatal(err)
		}
	}
	_, msgs, _ := s.ChannelUsage("c")
	if msgs != 3 {
		t.Fatalf("msgs = %d, want 3", msgs)
	}
	got, _ := s.CatchUp("c", 0, 100)
	if len(got) != 3 || got[0].Seq != 4 {
		t.Fatalf("survivors = %d start seq %d, want 3 @ 4", len(got), got[0].Seq)
	}
}

func TestRingBufferMaxBytes(t *testing.T) {
	s := startRedis(t)
	s.CreateChannel(Channel{ID: "c", KAuth: "k", Retained: true, TTLSeconds: 3600, MaxBytes: 30}, 0)
	for i := 0; i < 10; i++ {
		s.Append("c", "", "", "", []byte("0123456789"), 0)
	}
	bytes, _, _ := s.ChannelUsage("c")
	if bytes > 30 {
		t.Fatalf("bytes = %d, want <= 30", bytes)
	}
}

func TestAccountByteCap(t *testing.T) {
	s := startRedis(t)
	s.CreateAccount("a", "h")
	s.CreateChannel(Channel{ID: "c", OwnerID: "a", KAuth: "k", Retained: true, TTLSeconds: 3600, MaxMsgs: 1000}, 100)
	s.Append("c", "", "", "", []byte("0123456789"), 25)
	s.Append("c", "", "", "", []byte("0123456789"), 25)
	if _, err := s.Append("c", "", "", "", []byte("0123456789"), 25); !errors.Is(err, ErrQuotaAcct) {
		t.Fatalf("3rd append = %v, want ErrQuotaAcct", err)
	}
}

// never-expire (ttl=0): a message stored with no TTL is never pruned.
func TestNeverExpire(t *testing.T) {
	base := int64(1_000_000)
	cur := base
	real := nowUnix
	nowUnix = func() int64 { return cur }
	defer func() { nowUnix = real }()

	s := startRedis(t)
	s.CreateChannel(Channel{ID: "c", KAuth: "k", Retained: true, TTLSeconds: 0, MaxMsgs: 1000}, 0) // ttl 0 = forever
	s.Append("c", "", "", "", []byte("permanent"), 0)

	cur = base + 100*365*24*3600 // a century later
	n, err := s.PruneExpired()
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("pruned %d never-expire messages, want 0", n)
	}
	got, _ := s.CatchUp("c", 0, 10)
	if len(got) != 1 || string(got[0].Ciphertext) != "permanent" {
		t.Fatalf("never-expire message gone: %+v", got)
	}
}

// uncapped (max=0): no eviction however many messages.
func TestUncapped(t *testing.T) {
	s := startRedis(t)
	s.CreateChannel(Channel{ID: "c", KAuth: "k", Retained: true, TTLSeconds: 0, MaxMsgs: 0, MaxBytes: 0}, 0)
	for i := 0; i < 50; i++ {
		s.Append("c", "", "", "", []byte("x"), 0)
	}
	_, msgs, _ := s.ChannelUsage("c")
	if msgs != 50 {
		t.Fatalf("uncapped channel evicted: msgs = %d, want 50", msgs)
	}
}

// TTL prune removes expired, leaves live, and is reflected in catch-up.
func TestPruneExpired(t *testing.T) {
	base := int64(1_000_000)
	cur := base
	real := nowUnix
	nowUnix = func() int64 { return cur }
	defer func() { nowUnix = real }()

	s := startRedis(t)
	s.CreateChannel(Channel{ID: "c", KAuth: "k", Retained: true, TTLSeconds: 100, MaxMsgs: 1000}, 0)
	s.Append("c", "", "", "", []byte("old"), 0) // expires base+100
	cur = base + 50
	s.Append("c", "", "", "", []byte("new"), 0) // expires base+150
	cur = base + 120
	n, err := s.PruneExpired()
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("pruned %d, want 1", n)
	}
	got, _ := s.CatchUp("c", 0, 10)
	if len(got) != 1 || string(got[0].Ciphertext) != "new" {
		t.Fatalf("after prune = %+v, want just new", got)
	}
}

func TestMain(m *testing.M) { os.Exit(m.Run()) }
