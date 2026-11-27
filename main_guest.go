//go:build guestonly

// The slim client a drop host serves to machines without a browser. It can
// only join sessions; it cannot host one.
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, guestUsage)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "join", "send", "last", "leave":
		if err := runGuestCommand(os.Args[1], os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "drop:", err)
			os.Exit(1)
		}
	case "help", "-h", "--help":
		fmt.Print(guestUsage)
	default:
		fmt.Fprint(os.Stderr, guestUsage)
		os.Exit(2)
	}
}
