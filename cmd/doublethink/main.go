// Command doublethink is the broker server and its pairing CLI.
//
//	doublethink serve            run the broker (private + public channels)
//	doublethink channel create   mint a private channel against a running server
//	doublethink pair             join a private channel as a peer (generates keys)
//
// doublethink is a secure publish/subscribe message broker: ntfy-easy setup with
// real authentication and genuinely private, end-to-end-encrypted channels.
//
// NO WARRANTY. doublethink is provided as is, without warranty of any kind. It
// carries other parties' private traffic and enforces access to it; you alone are
// responsible for how you deploy and secure it and for the data that flows through
// it. The author and contributors are not liable for any harm, data loss, data
// exposure, or security incident, however caused. No security mechanism is
// perfect. If you do not accept these terms, do not run this software.
package main

import (
	"fmt"
	"os"
)

const disclaimer = `doublethink is provided AS IS, WITHOUT WARRANTY OF ANY KIND. It carries other
parties' private traffic and enforces access to it; you alone are responsible for
how you deploy and secure it and for the data that flows through it. The author
and contributors are NOT LIABLE for any harm, data loss, data exposure, or
security incident, however caused. No security mechanism is perfect. If you do not
accept these terms, do not run this software.`

func usage() {
	fmt.Fprint(os.Stderr, `doublethink: a secure pub/sub broker, ntfy-easy with real private channels.

Usage:
  doublethink serve [flags]            run the broker
  doublethink channel create [flags]   create a private channel; prints its shared secret

To use a private channel, both parties connect to it with the shared secret. The
secret is the gate: whoever holds it can join, and no one else can. Share it over a
trusted channel; the broker never sees it.

Run "doublethink <command> -h" for command flags.

`+disclaimer+`
`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = runServe(os.Args[2:])
	case "channel":
		err = runChannel(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "doublethink: %v\n", err)
		os.Exit(1)
	}
}
