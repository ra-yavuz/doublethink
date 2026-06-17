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

// runChannel handles "doublethink channel create": mint a private channel and
// enrol the creating (first) peer. The creator owns the channel from the start, so
// it is admitted directly; the SECOND peer joins later via invite + SAS confirm.
func runChannel(args []string) error {
	if len(args) < 1 || args[0] != "create" {
		return fmt.Errorf("usage: doublethink channel create [flags]")
	}
	fs := flag.NewFlagSet("channel create", flag.ContinueOnError)
	adminURL := fs.String("admin", "http://127.0.0.1:8081", "admin API base URL of a running server")
	prefix := fs.String("prefix", "", "optional human prefix for the channel id (e.g. codespeak)")
	identityPath := fs.String("identity", "", "path to write the creating peer's identity file (required)")
	role := fs.String("role", "agent", "this peer's role label (e.g. agent, pwa)")
	quiet := fs.Bool("quiet", false, "print only the channel id (for scripting)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: doublethink channel create --identity <file> [flags]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *identityPath == "" {
		fs.Usage()
		return fmt.Errorf("--identity is required (the creator's private keys are stored there)")
	}

	// A high-entropy random channel id so the name is unguessable. The id is not
	// the security boundary (auth is), but unguessability removes enumeration as a
	// cheap attack (DESIGN-M1.md decision 5).
	id, err := randomChannelID(*prefix)
	if err != nil {
		return err
	}

	creator, err := clientcrypto.GenerateIdentity()
	if err != nil {
		return fmt.Errorf("generating identity: %w", err)
	}
	ecdh := creator.ECDHPublic()
	req := map[string]string{
		"channel":  id,
		"id_pub":   b64(creator.SignPub),
		"ecdh_pub": b64(ecdh[:]),
	}
	if err := adminPost(*adminURL, "/admin/channel/create", req, nil); err != nil {
		return fmt.Errorf("creating channel: %w", err)
	}
	if err := saveIdentity(*identityPath, peerIdentityFile{Channel: id, Role: *role, Identity: creator.Export()}); err != nil {
		return fmt.Errorf("writing identity file: %w", err)
	}

	if *quiet {
		fmt.Println(id)
		return nil
	}
	fmt.Printf("created private channel and enrolled this peer (role %q):\n  %s\n\n", *role, id)
	fmt.Printf("identity saved to %s (keep private; never sent to the broker)\n\n", *identityPath)
	fmt.Printf("invite the second peer with:\n  doublethink invite --channel %s --identity %s\n", id, *identityPath)
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
