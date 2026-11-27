package main

import (
	"errors"
	"strings"
)

// This file holds what the host and the terminal guest both need to know
// about the protocol. It is part of every build, including the slim
// guest-only client.

const (
	maxInboundBytes = 64 << 10                          // largest message a guest may send
	codeAlphabet    = "ABCDEFGHJKMNPQRSTUVWXYZ23456789" // no 0/O, 1/I/L
	codeLength      = 6
)

var errWrongCode = errors.New("wrong code")

// Event is one entry in a session's live log. Both pages replay the log from
// a cursor, so a reload rebuilds the thread.
type Event struct {
	Seq  int64  `json:"seq"`
	T    string `json:"t"` // "msg", "del" or "end"
	ID   int64  `json:"id,omitempty"`
	Dir  string `json:"dir,omitempty"` // "out" = from the host, "in" = from the guest
	Body string `json:"body,omitempty"`
	TS   int64  `json:"ts,omitempty"`
}

func normalizeCode(s string) string {
	s = strings.ToUpper(s)
	return strings.Map(func(r rune) rune {
		if strings.ContainsRune(codeAlphabet, r) {
			return r
		}
		return -1
	}, s)
}

// cleanForTerminal drops control characters (escape sequences included) so
// printed text cannot move the cursor, recolour or retitle the terminal.
// Newlines and tabs are kept.
func cleanForTerminal(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\t':
			return r
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f):
			return -1
		}
		return r
	}, s)
}
