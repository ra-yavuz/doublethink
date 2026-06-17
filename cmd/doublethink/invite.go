package main

import (
	"flag"
	"fmt"
	"os"
)

// runInvite handles "doublethink invite": the already-enrolled peer mints a
// single-use, short-TTL pairing code for the second peer. The code authorises
// rendezvous only; the second peer's key is not trusted until the SAS is
// confirmed (doublethink pair, then confirm).
func runInvite(args []string) error {
	fs := flag.NewFlagSet("invite", flag.ContinueOnError)
	channel := fs.String("channel", "", "the channel to invite a peer to (defaults to the identity file's channel)")
	identityPath := fs.String("identity", "", "this (already-enrolled) peer's identity file (required)")
	adminURL := fs.String("admin", "http://127.0.0.1:8081", "admin API base URL of a running server")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: doublethink invite --identity <file> [flags]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *identityPath == "" {
		fs.Usage()
		return fmt.Errorf("--identity is required")
	}

	pf, id, err := loadIdentity(*identityPath)
	if err != nil {
		return fmt.Errorf("loading identity %s: %w", *identityPath, err)
	}
	ch := *channel
	if ch == "" {
		ch = pf.Channel
	}

	ecdh := id.ECDHPublic()
	req := map[string]string{
		"channel":  ch,
		"role":     pf.Role,
		"id_pub":   b64(id.SignPub),
		"ecdh_pub": b64(ecdh[:]),
	}
	var resp struct {
		Code       string `json:"code"`
		Channel    string `json:"channel"`
		TTLSeconds int    `json:"ttl_seconds"`
	}
	if err := adminPost(*adminURL, "/admin/invite", req, &resp); err != nil {
		return fmt.Errorf("creating invite: %w", err)
	}

	fmt.Printf("pairing code (single use, valid %d minutes):\n  %s\n\n", resp.TTLSeconds/60, resp.Code)
	fmt.Printf("on the second device, run:\n  doublethink pair --channel %s --code %s --identity <peer>.json\n\n", resp.Channel, resp.Code)
	fmt.Printf("then compare the SAS it prints with this device out of band before confirming.\n")
	return nil
}
