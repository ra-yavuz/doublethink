package transport_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ra-yavuz/doublethink/internal/auth"
	"github.com/ra-yavuz/doublethink/internal/broker"
	"github.com/ra-yavuz/doublethink/internal/limits"
	"github.com/ra-yavuz/doublethink/internal/transport"
)

const allowedOrigin = "https://ra-yavuz.github.io"

func corsServer(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(transport.NewWithConfig(transport.Config{
		Broker: broker.New(), Reg: auth.NewRegistry(), Limits: limits.DefaultLimits(),
		AllowedOrigins: []string{allowedOrigin},
	}).Handler())
	t.Cleanup(srv.Close)
	return srv.URL
}

// An allowed origin gets the CORS allow header echoed back.
func TestCORSAllowedOrigin(t *testing.T) {
	url := corsServer(t)
	req, _ := http.NewRequest(http.MethodGet, url+"/healthz", nil)
	req.Header.Set("Origin", allowedOrigin)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != allowedOrigin {
		t.Fatalf("Allow-Origin = %q, want %q", got, allowedOrigin)
	}
}

// A non-allowed origin gets NO allow header (browser will block it). Never "*".
func TestCORSDisallowedOrigin(t *testing.T) {
	url := corsServer(t)
	req, _ := http.NewRequest(http.MethodGet, url+"/healthz", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("Allow-Origin = %q for a disallowed origin, want empty", got)
	}
}

// OPTIONS preflight is answered with 204 and the allow headers.
func TestCORSPreflight(t *testing.T) {
	url := corsServer(t)
	req, _ := http.NewRequest(http.MethodOptions, url+"/channel", nil)
	req.Header.Set("Origin", allowedOrigin)
	req.Header.Set("Access-Control-Request-Method", "POST")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("preflight status = %d, want 204", resp.StatusCode)
	}
	if resp.Header.Get("Access-Control-Allow-Methods") == "" {
		t.Fatal("preflight missing Allow-Methods")
	}
}

// Default (no allow-list) is OPEN CORS: any origin gets "*". doublethink is meant
// to be used cross-origin and has no cookies/session, so this is safe.
func TestCORSOpenByDefault(t *testing.T) {
	srv := httptest.NewServer(transport.New(broker.New(), auth.NewRegistry()).Handler())
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/healthz", nil)
	req.Header.Set("Origin", "https://anything.example.com")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("default Allow-Origin = %q, want * (open)", got)
	}
}

// A restricted deployment (allow-list set) reflects only allowed origins and never
// pairs the wildcard with credentials.
func TestCORSRestrictedDisallowed(t *testing.T) {
	url := corsServer(t) // configured with only allowedOrigin
	req, _ := http.NewRequest(http.MethodGet, url+"/healthz", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	got := resp.Header.Get("Access-Control-Allow-Origin")
	if got == "*" || got == "https://evil.example.com" {
		t.Fatalf("restricted deployment leaked origin: Allow-Origin = %q", got)
	}
}
