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
	channelID := fs.String("channel", "", "explicit channel id (required with --ticket if the grant is for an exact id)")
	retain := fs.Bool("retain", false, "retain messages so an offline peer can catch up (requires an account)")
	account := fs.String("account", "", "account id (required with --retain)")
	apiKey := fs.String("api-key", "", "account API key (required with --retain)")
	ttlSec := fs.Int64("ttl-sec", 0, "retention TTL in seconds (0 = server default; capped at the server max)")
	ticket := fs.String("ticket", "", "admin grant ticket -> create a permanent / over-default topic the admin pre-authorized")
	quiet := fs.Bool("quiet", false, "print only 'channel<TAB>secret' (for scripting)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: doublethink channel create [flags]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *retain && *ticket == "" && (*account == "" || *apiKey == "") {
		return fmt.Errorf("--retain requires --account and --api-key (run 'doublethink account create'), or use --ticket")
	}

	// Channel id: an explicit --channel (needed when redeeming a ticket bound to an
	// exact id), else a high-entropy unguessable id. The name is not the gate, the
	// secret is; an unguessable id removes enumeration as a cheap probe.
	id := *channelID
	if id == "" {
		var err error
		id, err = randomChannelID(*prefix)
		if err != nil {
			return err
		}
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

	req := map[string]any{"channel": id, "auth_key": authKey, "retain": *retain}
	var headers map[string]string
	switch {
	case *ticket != "":
		// Redeem an admin grant: the channel's policy (e.g. permanent) comes from
		// the ticket. An account key, if supplied, attributes ownership.
		req["ticket"] = *ticket
		if *account != "" && *apiKey != "" {
			headers = map[string]string{"Authorization": "Bearer " + *apiKey, "X-Doublethink-Account": *account}
		}
	case *retain:
		req["ttl_sec"] = *ttlSec
		headers = map[string]string{"Authorization": "Bearer " + *apiKey, "X-Doublethink-Account": *account}
	}
	if err := postJSONAuth(*server, "/channel", req, nil, headers); err != nil {
		return fmt.Errorf("creating channel: %w", err)
	}

	if *quiet {
		fmt.Printf("%s\t%s\n", id, secret)
		return nil
	}
	kind := "ephemeral (online-only)"
	if *ticket != "" {
		kind = "permanent / admin-granted (retained)"
	} else if *retain {
		kind = "retained (offline peers can catch up)"
	}
	fmt.Printf("created private channel (%s):\n", kind)
	fmt.Printf("  channel: %s\n", id)
	fmt.Printf("  secret:  %s\n\n", secret)
	fmt.Printf("Share the secret with the other party over a trusted channel. Anyone who\n")
	fmt.Printf("holds it can join and read this channel; the broker never sees it and cannot\n")
	fmt.Printf("read your messages. Both parties connect to the channel using this secret.\n")
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
