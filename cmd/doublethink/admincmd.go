package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

// runAdmin dispatches the operator admin subcommands, all authenticated by the
// admin key (the DOUBLETHINK_ADMIN_KEY the broker runs with):
//
//	doublethink admin set-limit   raise an existing channel's retention limits
//	doublethink admin grant       issue a single-use ticket for a permanent / over-default topic
//	doublethink admin channels    list channel metadata (no secrets)
func runAdmin(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: doublethink admin <set-limit|grant|channels> [flags]")
	}
	switch args[0] {
	case "set-limit":
		return runAdminSetLimit(args[1:])
	case "grant":
		return runAdminGrant(args[1:])
	case "channels":
		return runAdminChannels(args[1:])
	default:
		return fmt.Errorf("unknown admin subcommand %q (set-limit|grant|channels)", args[0])
	}
}

func adminKeyFlag(fs *flag.FlagSet) *string {
	return fs.String("admin-key", os.Getenv("DOUBLETHINK_ADMIN_KEY"), "admin key (defaults to $DOUBLETHINK_ADMIN_KEY)")
}

func runAdminSetLimit(args []string) error {
	fs := flag.NewFlagSet("admin set-limit", flag.ContinueOnError)
	server := fs.String("server", "http://127.0.0.1:8080", "base URL of the doublethink broker")
	adminKey := adminKeyFlag(fs)
	channel := fs.String("channel", "", "channel id to adjust (required)")
	ttlSec := fs.Int64("ttl-sec", -1, "new retention TTL seconds (-1 = unchanged, 0 = never expire)")
	maxBytes := fs.Int64("max-bytes", -1, "new per-channel byte cap (-1 = unchanged, 0 = uncapped)")
	maxMsgs := fs.Int64("max-msgs", -1, "new per-channel message cap (-1 = unchanged, 0 = uncapped)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *channel == "" || *adminKey == "" {
		return fmt.Errorf("--channel and an admin key are required")
	}
	req := map[string]any{"channel": *channel, "ttl_sec": *ttlSec, "max_bytes": *maxBytes, "max_msgs": *maxMsgs}
	if err := postJSONAuth(*server, "/admin/limit", req, nil, bearer(*adminKey)); err != nil {
		return fmt.Errorf("setting limit: %w", err)
	}
	fmt.Printf("updated limits for channel %s\n", *channel)
	return nil
}

// runAdminGrant issues a single-use grant ticket. The admin sets the policy; the
// USER redeems the ticket creating the channel with their own secret, so the admin
// never sees the secret.
func runAdminGrant(args []string) error {
	fs := flag.NewFlagSet("admin grant", flag.ContinueOnError)
	server := fs.String("server", "http://127.0.0.1:8080", "base URL of the doublethink broker")
	adminKey := adminKeyFlag(fs)
	match := fs.String("channel", "", "channel id, or \"prefix/*\" namespace, the ticket authorizes (required)")
	ttlSec := fs.Int64("ttl-sec", 0, "retention TTL of the granted channel in seconds (0 = never expires / permanent)")
	maxBytes := fs.Int64("max-bytes", 0, "per-channel byte cap of the granted channel (0 = uncapped)")
	maxMsgs := fs.Int64("max-msgs", 0, "per-channel message cap of the granted channel (0 = uncapped)")
	expirySec := fs.Int64("expiry-sec", 0, "how long the ticket is valid to redeem in seconds (0 = server default, 1 hour)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *match == "" || *adminKey == "" {
		return fmt.Errorf("--channel (id or prefix/*) and an admin key are required")
	}
	req := map[string]any{
		"channel_match": *match, "ttl_sec": *ttlSec, "max_bytes": *maxBytes,
		"max_msgs": *maxMsgs, "expiry_sec": *expirySec,
	}
	var out struct {
		Ticket    string `json:"ticket"`
		ExpirySec int64  `json:"expiry_sec"`
	}
	if err := postJSONAuth(*server, "/admin/grant", req, &out, bearer(*adminKey)); err != nil {
		return fmt.Errorf("issuing grant: %w", err)
	}
	fmt.Printf("grant ticket (single use, valid %d minutes to redeem):\n  %s\n\n", out.ExpirySec/60, out.Ticket)
	fmt.Printf("give the ticket to the user. They create the channel with it AND their own secret:\n")
	fmt.Printf("  doublethink channel create --channel %s --ticket %s\n", *match, out.Ticket)
	fmt.Printf("(you, the admin, never see their secret.)\n")
	return nil
}

func runAdminChannels(args []string) error {
	fs := flag.NewFlagSet("admin channels", flag.ContinueOnError)
	server := fs.String("server", "http://127.0.0.1:8080", "base URL of the doublethink broker")
	adminKey := adminKeyFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *adminKey == "" {
		return fmt.Errorf("an admin key is required")
	}
	var out map[string]any
	if err := getJSONAuth(*server, "/admin/channels", &out, bearer(*adminKey)); err != nil {
		return fmt.Errorf("listing channels: %w", err)
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(b))
	return nil
}

func bearer(key string) map[string]string { return map[string]string{"Authorization": "Bearer " + key} }
