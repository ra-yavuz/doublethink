package main

import (
	"crypto/rand"
	"encoding/base32"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ra-yavuz/doublethink/internal/clientcrypto"
)

// runChannel handles "doublethink channel create": self-service creation of a
// private channel. The client mints a shared secret S, derives K_auth from it,
// registers only the channel id + K_auth with the broker (never S), and prints S.
// Whoever holds S can join the channel and read its traffic; no operator, no
// pairing ceremony.
func runChannel(args []string) error {
	if len(args) < 1 || args[0] != "create" {
		return fmt.Errorf("usage: doublethink channel create [flags]")
	}
	fs := flag.NewFlagSet("channel create", flag.ContinueOnError)
	server := fs.String("server", "http://127.0.0.1:8080", "base URL of the doublethink broker")
	prefix := fs.String("prefix", "", "optional human prefix for the channel id (e.g. codespeak)")
	quiet := fs.Bool("quiet", false, "print only 'channel<TAB>secret' (for scripting)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: doublethink channel create [flags]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	// High-entropy, unguessable channel id (the name is not the gate, the secret
	// is, but an unguessable id removes enumeration as a cheap probe).
	id, err := randomChannelID(*prefix)
	if err != nil {
		return err
	}

	// The shared secret S: generated here, shared out of band, NEVER sent to the
	// broker. K_auth is what the broker stores.
	secret, err := clientcrypto.GenerateSecret()
	if err != nil {
		return err
	}
	authKey, err := clientcrypto.RegistrationKey(secret)
	if err != nil {
		return err
	}

	req := map[string]string{"channel": id, "auth_key": authKey}
	if err := postJSON(*server, "/channel", req, nil); err != nil {
		return fmt.Errorf("creating channel: %w", err)
	}

	if *quiet {
		fmt.Printf("%s\t%s\n", id, secret)
		return nil
	}
	fmt.Printf("created private channel:\n")
	fmt.Printf("  channel: %s\n", id)
	fmt.Printf("  secret:  %s\n\n", secret)
	fmt.Printf("Share the secret with the other party over a trusted channel. Anyone who\n")
	fmt.Printf("holds it can join and read this channel; the broker never sees it and cannot\n")
	fmt.Printf("read your messages. To use the channel, both parties connect with --secret.\n")
	return nil
}

func randomChannelID(prefix string) (string, error) {
	raw := make([]byte, 16) // 128 bits
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", err
	}
	enc := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw))
	if prefix != "" {
		return prefix + "/" + enc, nil
	}
	return enc, nil
}
