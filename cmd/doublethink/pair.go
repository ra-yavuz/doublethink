package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/ra-yavuz/doublethink/internal/clientcrypto"
)

// runPair handles "doublethink pair": the second peer redeems a pairing code,
// generates its identity, and learns the SAS it must compare with the inviter out
// of band. Its key is NOT yet admitted to the channel: that happens at confirm,
// after a human verifies the SAS matches on both devices. This is the
// MITM-resistant step.
func runPair(args []string) error {
	fs := flag.NewFlagSet("pair", flag.ContinueOnError)
	channel := fs.String("channel", "", "the private channel id to join (required)")
	code := fs.String("code", "", "the single-use pairing code from 'invite' (required)")
	identityPath := fs.String("identity", "", "path to write this peer's identity file (required)")
	role := fs.String("role", "pwa", "this peer's role label (e.g. pwa, agent)")
	adminURL := fs.String("admin", "http://127.0.0.1:8081", "admin API base URL of a running server")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: doublethink pair --channel <id> --code <code> --identity <file> [flags]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *channel == "" || *code == "" || *identityPath == "" {
		fs.Usage()
		return fmt.Errorf("--channel, --code, and --identity are required")
	}

	id, err := clientcrypto.GenerateIdentity()
	if err != nil {
		return fmt.Errorf("generating identity: %w", err)
	}
	ecdh := id.ECDHPublic()
	req := map[string]string{
		"code":     *code,
		"id_pub":   b64(id.SignPub),
		"ecdh_pub": b64(ecdh[:]),
	}
	var resp struct {
		Channel     string `json:"channel"`
		SAS         string `json:"sas"`
		InviterECDH string `json:"inviter_ecdh"`
	}
	if err := adminPost(*adminURL, "/admin/redeem", req, &resp); err != nil {
		return fmt.Errorf("redeeming pairing code: %w", err)
	}

	// Save this peer's private identity locally.
	pf := peerIdentityFile{Channel: resp.Channel, Role: *role, Identity: id.Export()}
	if err := saveIdentity(*identityPath, pf); err != nil {
		return fmt.Errorf("writing identity file: %w", err)
	}

	fmt.Printf("redeemed pairing code for channel %s\n", resp.Channel)
	fmt.Printf("identity saved to %s (keep private; never sent to the broker)\n\n", *identityPath)
	fmt.Printf("SAS (compare with the other device OUT OF BAND):\n\n    %s\n\n", resp.SAS)
	fmt.Printf("if and only if both devices show the SAME SAS, run on the INVITING device:\n")
	fmt.Printf("  doublethink confirm --sas %s\n\n", resp.SAS)
	fmt.Printf("until confirmed, this peer cannot attach to the channel.\n")
	return nil
}
