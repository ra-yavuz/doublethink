package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// postJSON POSTs a JSON body to a broker endpoint and optionally decodes the JSON
// response. Used by the CLI to talk to the public broker API.
func postJSON(server, path string, reqBody any, out any) error {
	b, _ := json.Marshal(reqBody)
	client := &http.Client{Timeout: 15 * time.Second}
	url := strings.TrimRight(server, "/") + path
	resp, err := client.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("contacting broker at %s: %w (is it running?)", server, err)
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
