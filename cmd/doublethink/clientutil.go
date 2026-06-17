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
	return postJSONAuth(server, path, reqBody, out, nil)
}

// postJSONAuth is postJSON with optional request headers (e.g. Authorization).
func postJSONAuth(server, path string, reqBody any, out any, headers map[string]string) error {
	b, _ := json.Marshal(reqBody)
	client := &http.Client{Timeout: 15 * time.Second}
	url := strings.TrimRight(server, "/") + path
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
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
