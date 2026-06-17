package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/ra-yavuz/doublethink/internal/clientcrypto"
)

// peerIdentityFile is what a peer stores locally: its PRIVATE identity plus the
// channel it is paired on. This file must stay on the peer's own machine; it is
// never sent to the broker.
type peerIdentityFile struct {
	Channel  string                          `json:"channel"`
	Identity clientcrypto.PersistedIdentity  `json:"identity"`
}

// runPair handles "doublethink pair": generate this peer's identity, register its
// public keys with the running server, learn the other peer's X25519 key, and
// save the identity locally. Running pair again on a channel rotates this peer's
// keys (the M1 re-pair revocation path).
func runPair(args []string) error {
	fs := flag.NewFlagSet("pair", flag.ContinueOnError)
	channel := fs.String("channel", "", "the private channel id to join (from 'channel create')")
	identityPath := fs.String("identity", "", "path to write this peer's identity file (required)")
	adminURL := fs.String("admin", "http://127.0.0.1:8081", "admin API base URL of a running server")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: doublethink pair --channel <id> --identity <file> [flags]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *channel == "" || *identityPath == "" {
		fs.Usage()
		return fmt.Errorf("--channel and --identity are required")
	}

	id, err := clientcrypto.GenerateIdentity()
	if err != nil {
		return fmt.Errorf("generating identity: %w", err)
	}

	ecdhPub := id.ECDHPublic()
	req := map[string]string{
		"channel":  *channel,
		"id_pub":   base64.StdEncoding.EncodeToString(id.SignPub),
		"ecdh_pub": base64.StdEncoding.EncodeToString(ecdhPub[:]),
	}
	var resp struct {
		Channel string            `json:"channel"`
		Peers   map[string]string `json:"peers"`
	}
	url := strings.TrimRight(*adminURL, "/") + "/admin/pair"
	if err := httpJSON(url, req, &resp); err != nil {
		return fmt.Errorf("pairing against %s: %w (did you run 'channel create' first?)", *adminURL, err)
	}

	// Save this peer's private identity locally.
	pf := peerIdentityFile{Channel: *channel, Identity: id.Export()}
	out, _ := json.MarshalIndent(pf, "", "  ")
	if err := os.WriteFile(*identityPath, out, 0o600); err != nil {
		return fmt.Errorf("writing identity file: %w", err)
	}

	fmt.Printf("paired on channel %s\n", *channel)
	fmt.Printf("identity saved to %s (keep this private; it is never sent to the broker)\n", *identityPath)

	// Report how many peers are paired so far. Two means the channel is ready for
	// end-to-end traffic; one means we are waiting for the other peer to pair.
	mine := base64.StdEncoding.EncodeToString(id.SignPub)
	others := 0
	for k := range resp.Peers {
		if k != mine {
			others++
		}
	}
	switch others {
	case 0:
		fmt.Printf("waiting for the other peer to pair. Run pair on the second device with the same --channel.\n")
	default:
		fmt.Printf("%d other peer(s) paired; this channel is ready for end-to-end messages.\n", others)
	}
	return nil
}
