package main

import (
	"flag"
	"fmt"
	"os"
)

// runAdmin handles "doublethink admin set-limit": an operator raises a channel's
// retention limits, authenticated with the admin key (the same value set in the
// broker's DOUBLETHINK_ADMIN_KEY environment variable).
func runAdmin(args []string) error {
	if len(args) < 1 || args[0] != "set-limit" {
		return fmt.Errorf("usage: doublethink admin set-limit [flags]")
	}
	fs := flag.NewFlagSet("admin set-limit", flag.ContinueOnError)
	server := fs.String("server", "http://127.0.0.1:8080", "base URL of the doublethink broker")
	adminKey := fs.String("admin-key", os.Getenv("DOUBLETHINK_ADMIN_KEY"), "admin key (defaults to $DOUBLETHINK_ADMIN_KEY)")
	channel := fs.String("channel", "", "channel id to adjust (required)")
	ttlSec := fs.Int64("ttl-sec", -1, "new retention TTL in seconds (-1 = leave unchanged)")
	maxBytes := fs.Int64("max-bytes", -1, "new per-channel storage cap in bytes (-1 = leave unchanged)")
	maxMsgs := fs.Int64("max-msgs", -1, "new per-channel message cap (-1 = leave unchanged)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: doublethink admin set-limit --channel <id> [flags]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *channel == "" {
		fs.Usage()
		return fmt.Errorf("--channel is required")
	}
	if *adminKey == "" {
		return fmt.Errorf("no admin key (pass --admin-key or set DOUBLETHINK_ADMIN_KEY)")
	}

	req := map[string]any{
		"channel":   *channel,
		"ttl_sec":   *ttlSec,
		"max_bytes": *maxBytes,
		"max_msgs":  *maxMsgs,
	}
	headers := map[string]string{"Authorization": "Bearer " + *adminKey}
	if err := postJSONAuth(*server, "/admin/limit", req, nil, headers); err != nil {
		return fmt.Errorf("setting limit: %w", err)
	}
	fmt.Printf("updated limits for channel %s\n", *channel)
	return nil
}
