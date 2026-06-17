package main

import (
	"flag"
	"fmt"
	"os"
)

// runConfirm handles "doublethink confirm": after a human has verified that both
// devices display the SAME SAS, this admits the pending peer's key to the channel.
// This is the human-in-the-loop gate that makes a silent broker MITM impossible:
// the broker cannot admit a substituted key, because a substituted key would have
// produced a different SAS that the human would not have matched.
func runConfirm(args []string) error {
	fs := flag.NewFlagSet("confirm", flag.ContinueOnError)
	sas := fs.String("sas", "", "the SAS that matched on both devices (required)")
	adminURL := fs.String("admin", "http://127.0.0.1:8081", "admin API base URL of a running server")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: doublethink confirm --sas <sas> [flags]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *sas == "" {
		fs.Usage()
		return fmt.Errorf("--sas is required")
	}

	var resp struct {
		Channel  string `json:"channel"`
		Admitted bool   `json:"admitted"`
	}
	if err := adminPost(*adminURL, "/admin/confirm", map[string]string{"sas": *sas}, &resp); err != nil {
		return fmt.Errorf("confirming pairing: %w", err)
	}
	fmt.Printf("peer admitted to channel %s; it can now attach and exchange end-to-end-encrypted messages.\n", resp.Channel)
	return nil
}
