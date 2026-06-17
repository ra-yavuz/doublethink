package main

import (
	"flag"
	"fmt"
	"os"
)

// runAccount handles "doublethink account create": get an API key from the broker.
// The key is needed to create retained channels; keep it secret.
func runAccount(args []string) error {
	if len(args) < 1 || args[0] != "create" {
		return fmt.Errorf("usage: doublethink account create [flags]")
	}
	fs := flag.NewFlagSet("account create", flag.ContinueOnError)
	server := fs.String("server", "http://127.0.0.1:8080", "base URL of the doublethink broker")
	quiet := fs.Bool("quiet", false, "print only 'account<TAB>api_key' (for scripting)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: doublethink account create [flags]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	var resp struct {
		Account string `json:"account"`
		APIKey  string `json:"api_key"`
	}
	if err := postJSON(*server, "/account", map[string]string{}, &resp); err != nil {
		return fmt.Errorf("creating account: %w", err)
	}
	if *quiet {
		fmt.Printf("%s\t%s\n", resp.Account, resp.APIKey)
		return nil
	}
	fmt.Printf("created account:\n")
	fmt.Printf("  account: %s\n", resp.Account)
	fmt.Printf("  api key: %s\n\n", resp.APIKey)
	fmt.Printf("Keep the API key secret; it is shown only once and the broker stores only a\n")
	fmt.Printf("hash of it. Use it to create retained channels:\n")
	fmt.Printf("  doublethink channel create --retain --account %s --api-key %s\n", resp.Account, resp.APIKey)
	return nil
}
