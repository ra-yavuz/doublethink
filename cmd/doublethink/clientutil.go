package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ra-yavuz/doublethink/internal/clientcrypto"
)

// peerIdentityFile is what a peer stores locally: its PRIVATE identity plus the
// channel it is paired on. This file must stay on the peer's own machine; it is
// never sent to the broker.
type peerIdentityFile struct {
	Channel  string                         `json:"channel"`
	Role     string                         `json:"role"`
	Identity clientcrypto.PersistedIdentity `json:"identity"`
}

func saveIdentity(path string, pf peerIdentityFile) error {
	out, err := json.MarshalIndent(pf, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, 0o600)
}

func loadIdentity(path string) (peerIdentityFile, *clientcrypto.Identity, error) {
	var pf peerIdentityFile
	b, err := os.ReadFile(path)
	if err != nil {
		return pf, nil, err
	}
	if err := json.Unmarshal(b, &pf); err != nil {
		return pf, nil, err
	}
	id, err := clientcrypto.ImportIdentity(pf.Identity)
	if err != nil {
		return pf, nil, err
	}
	return pf, id, nil
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// adminPost POSTs JSON to an admin endpoint and decodes the JSON response.
func adminPost(adminURL, path string, reqBody any, out any) error {
	b, _ := json.Marshal(reqBody)
	client := &http.Client{Timeout: 15 * time.Second}
	url := strings.TrimRight(adminURL, "/") + path
	resp, err := client.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("contacting admin API at %s: %w (is the server running?)", adminURL, err)
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
