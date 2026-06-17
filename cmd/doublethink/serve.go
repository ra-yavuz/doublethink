package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ra-yavuz/doublethink/internal/auth"
	"github.com/ra-yavuz/doublethink/internal/broker"
	"github.com/ra-yavuz/doublethink/internal/transport"
)

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	addr := fs.String("addr", ":8080", "public listen address for channels (WebSocket + plaintext HTTP)")
	adminAddr := fs.String("admin-addr", "127.0.0.1:8081", "loopback-only admin/pairing listen address")
	statePath := fs.String("state", defaultStatePath(), "path to the channel state file")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: doublethink serve [flags]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	b := broker.New()
	reg := auth.NewRegistry()

	// Load persisted channels if the state file exists.
	if err := loadState(*statePath, reg); err != nil {
		return fmt.Errorf("loading state %s: %w", *statePath, err)
	}
	// Persist on every registry change.
	reg.OnChange(func() {
		if err := saveState(*statePath, reg); err != nil {
			log.Printf("warning: could not persist state to %s: %v", *statePath, err)
		}
	})

	srv := transport.New(b, reg)
	var adminReg transport.Registry = reg
	adminAPI := transport.NewAdminAPI(&adminReg)

	// The startup log carries the no-warranty disclaimer (project rule 3).
	log.Printf("doublethink starting")
	log.Printf("NO WARRANTY: provided as is; you are responsible for deployment, security, and the data that flows through it. The author is not liable for any harm, however caused.")
	log.Printf("channels (public + private) on %s", *addr)
	log.Printf("admin/pairing on %s (loopback only, do not expose off-host)", *adminAddr)
	log.Printf("state file: %s", *statePath)

	public := &http.Server{Addr: *addr, Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
	admin := &http.Server{Addr: *adminAddr, Handler: adminAPI.Handler(), ReadHeaderTimeout: 10 * time.Second}

	errCh := make(chan error, 2)
	go func() { errCh <- public.ListenAndServe() }()
	go func() { errCh <- admin.ListenAndServe() }()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	select {
	case <-ctx.Done():
		log.Printf("shutting down")
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = public.Shutdown(sctx)
		_ = admin.Shutdown(sctx)
		return nil
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			return err
		}
		return nil
	}
}

// stateFile is the on-disk shape of the channel registry. It holds only public
// data (channel ids and authorized Ed25519 public keys); no private key is ever
// written here.
type stateFile struct {
	Channels map[string][]string `json:"channels"` // channel id -> base64 ed25519 pubkeys
}

func defaultStatePath() string {
	if x := os.Getenv("DOUBLETHINK_STATE"); x != "" {
		return x
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "doublethink-state.json"
	}
	return filepath.Join(dir, "doublethink", "state.json")
}

func loadState(path string, reg *auth.Registry) error {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil // fresh start
	}
	if err != nil {
		return err
	}
	var sf stateFile
	if err := json.Unmarshal(b, &sf); err != nil {
		return err
	}
	reg.Load(sf.Channels)
	return nil
}

func saveState(path string, reg *auth.Registry) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	sf := stateFile{Channels: reg.Snapshot()}
	b, err := json.MarshalIndent(sf, "", "  ")
	if err != nil {
		return err
	}
	// Write atomically via a temp file + rename so a crash cannot truncate state.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
