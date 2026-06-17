package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// runChannel handles "doublethink channel create".
func runChannel(args []string) error {
	if len(args) < 1 || args[0] != "create" {
		return fmt.Errorf("usage: doublethink channel create [flags]")
	}
	fs := flag.NewFlagSet("channel create", flag.ContinueOnError)
	adminURL := fs.String("admin", "http://127.0.0.1:8081", "admin API base URL of a running server")
	prefix := fs.String("prefix", "", "optional human prefix for the channel id (e.g. codespeak)")
	quiet := fs.Bool("quiet", false, "print only the channel id (for scripting)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: doublethink channel create [flags]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	// A high-entropy random channel id so the name is unguessable. The id is not
	// the security boundary (auth is), but unguessability removes enumeration as a
	// cheap attack (DESIGN-M1.md decision 5).
	id, err := randomChannelID(*prefix)
	if err != nil {
		return err
	}

	body, _ := json.Marshal(map[string]string{"channel": id})
	resp, err := http.Post(strings.TrimRight(*adminURL, "/")+"/admin/channel/create", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("contacting admin API at %s: %w (is the server running?)", *adminURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("create failed: %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}

	if *quiet {
		fmt.Println(id)
		return nil
	}
	fmt.Printf("created private channel:\n  %s\n\n", id)
	fmt.Printf("pair each peer with:\n  doublethink pair --channel %s --identity <peer>.json\n", id)
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

// httpJSON is a small helper for POSTing JSON to the admin API and decoding the
// JSON response. Shared by pair.
func httpJSON(url string, reqBody any, out any) error {
	b, _ := json.Marshal(reqBody)
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}
