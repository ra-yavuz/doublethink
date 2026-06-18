// Command doublethink is the broker server and its pairing CLI.
//
//	doublethink serve            run the broker (private + public channels)
//	doublethink account create   create an account (needed for retained channels)
//	doublethink channel create   mint a private channel (or redeem an admin grant)
//	doublethink admin            operator commands: grant, set-limit, channels
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
  doublethink serve [flags]             run the broker
  doublethink account create [flags]    create an account; prints an API key (needed for retained channels)
  doublethink channel create [flags]    create a private channel; prints its shared secret
                                        (--ticket redeems an admin grant for a permanent channel)
  doublethink admin grant [flags]       (operator) issue a single-use ticket for a permanent / over-default channel
  doublethink admin set-limit [flags]   (operator) raise an existing channel's retention limits
  doublethink admin channels [flags]    (operator) list channel metadata (no secrets)

To use a private channel, both parties connect to it with the shared secret. The
secret is the gate: whoever holds it can join, and no one else can. Share it over a
trusted channel; the broker never sees it. A retained channel (messages stored for
an offline peer to catch up) requires an account API key and counts against quota.
A permanent channel is pre-authorized by an operator grant; the user redeems the
grant ticket with their own secret, so the operator never sees the secret.

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
	case "account":
		err = runAccount(os.Args[2:])
	case "channel":
		err = runChannel(os.Args[2:])
	case "admin":
		err = runAdmin(os.Args[2:])
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
