package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ra-yavuz/doublethink/internal/admin"
	"github.com/ra-yavuz/doublethink/internal/auth"
	"github.com/ra-yavuz/doublethink/internal/broker"
	"github.com/ra-yavuz/doublethink/internal/limits"
	"github.com/ra-yavuz/doublethink/internal/store"
	"github.com/ra-yavuz/doublethink/internal/transport"
)

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	addr := fs.String("addr", ":8080", "listen address for the broker (channels, accounts, create, plaintext topics)")
	allowedOrigins := fs.String("allowed-origins", "", "comma-separated browser origins allowed cross-origin (CORS + WebSocket), e.g. https://ra-yavuz.github.io; empty = same-origin only")
	dbPath := fs.String("db", defaultDBPath(), "path to the SQLite database (channels, accounts, retained messages)")
	legacyJSON := fs.String("migrate-json", "", "optional path to an M1 state.json to import once (grandfathers existing channels)")
	sweep := fs.Duration("sweep-interval", time.Minute, "how often to prune expired retained messages")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: doublethink serve [flags]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Store (channels, accounts, retained messages).
	if dir := filepath.Dir(*dbPath); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("creating db dir: %w", err)
		}
	}
	st, err := store.Open(*dbPath)
	if err != nil {
		return fmt.Errorf("opening store %s: %w", *dbPath, err)
	}
	defer st.Close()

	// One-time migration from an M1 JSON state file, if given. Idempotent.
	if *legacyJSON != "" {
		n, err := st.MigrateLegacyJSON(*legacyJSON)
		if err != nil {
			return fmt.Errorf("migrating %s: %w", *legacyJSON, err)
		}
		if n > 0 {
			log.Printf("migrated %d channel(s) from %s (grandfathered, ephemeral)", n, *legacyJSON)
		}
	}

	// Load the in-memory admission registry from the store so attach does not hit
	// SQLite on every connection.
	reg := auth.NewRegistry()
	kauths, err := st.AllChannelKAuth()
	if err != nil {
		return fmt.Errorf("loading channels: %w", err)
	}
	snap := make(map[string]string, len(kauths))
	for id, ka := range kauths {
		snap[id] = ka
	}
	reg.Load(snap)

	b := broker.New()
	ad, adStatus := admin.FromEnv()
	lim := limits.DefaultLimits()

	// doublethink is an API meant to be called cross-origin (browsers, PWAs, web
	// apps), so CORS is OPEN by default: any origin may call it. This does not
	// widen the attack surface, the broker has no cookies or ambient session, so
	// auth is always an explicit Bearer key or the in-band channel-secret
	// challenge; a malicious origin can only do what curl already can, bounded by
	// the rate limits. (Allow-Origin "*" is therefore correct and is never paired
	// with credentials.) Pass --allowed-origins to RESTRICT to a fixed allow-list
	// for a private deployment.
	var origins []string
	for _, o := range strings.Split(*allowedOrigins, ",") {
		if o = strings.TrimSpace(o); o != "" {
			origins = append(origins, o)
		}
	}
	srv := transport.NewWithConfig(transport.Config{Broker: b, Reg: reg, Store: st, Admin: ad, Limits: lim, AllowedOrigins: origins})

	// Startup log carries the no-warranty disclaimer (project rule 3).
	log.Printf("doublethink starting")
	log.Printf("NO WARRANTY: provided as is; you are responsible for deployment, security, and the data that flows through it. The author is not liable for any harm, however caused.")
	log.Printf("listening on %s", *addr)
	log.Printf("db: %s  | %s", *dbPath, adStatus)
	log.Printf("loaded %d channel(s)", len(kauths))

	public := &http.Server{Addr: *addr, Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// TTL sweeper: prune expired retained messages periodically.
	go runSweeper(ctx, st, *sweep)

	errCh := make(chan error, 1)
	go func() { errCh <- public.ListenAndServe() }()

	select {
	case <-ctx.Done():
		log.Printf("shutting down")
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = public.Shutdown(sctx)
		return nil
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			return err
		}
		return nil
	}
}

// runSweeper prunes expired retained messages on a fixed interval until ctx is done.
func runSweeper(ctx context.Context, st *store.Store, every time.Duration) {
	if every <= 0 {
		every = time.Minute
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n, err := st.PruneExpired(); err != nil {
				log.Printf("sweeper: prune error: %v", err)
			} else if n > 0 {
				log.Printf("sweeper: pruned %d expired message(s)", n)
			}
		}
	}
}

func defaultDBPath() string {
	if x := os.Getenv("DOUBLETHINK_DB"); x != "" {
		return x
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "doublethink.db"
	}
	return filepath.Join(dir, "doublethink", "doublethink.db")
}
