package account

import "testing"

func TestNewIDUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		id, err := NewID()
		if err != nil {
			t.Fatal(err)
		}
		if id == "" || seen[id] {
			t.Fatalf("id empty or repeated: %q", id)
		}
		seen[id] = true
	}
}

func TestKeyRoundTrip(t *testing.T) {
	key, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	if !LooksLikeKey(key) {
		t.Fatalf("fresh key fails shape check: %q", key)
	}
	h := HashKey(key)
	if h == key {
		t.Fatal("hash equals key; the key would be stored in the clear")
	}
	if !VerifyKey(key, h) {
		t.Fatal("VerifyKey rejected the matching key")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	k1, _ := NewKey()
	k2, _ := NewKey()
	if VerifyKey(k2, HashKey(k1)) {
		t.Fatal("a different key verified against another's hash")
	}
}

func TestLooksLikeKeyRejectsJunk(t *testing.T) {
	for _, bad := range []string{"", "nope", "dtk_", "Bearer x", "dtk_short"} {
		if LooksLikeKey(bad) {
			t.Errorf("LooksLikeKey accepted junk: %q", bad)
		}
	}
}

func TestHashStable(t *testing.T) {
	k, _ := NewKey()
	if HashKey(k) != HashKey(k) {
		t.Fatal("HashKey is not deterministic")
	}
}
