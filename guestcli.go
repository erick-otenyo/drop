package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// The terminal guest: join a session from a machine with no browser. It
// speaks the same protocol as web/guest.js and is part of every build; the
// slim client the host serves contains little else.

const guestUsage = `Join a drop session from the terminal:

  drop join <address>   join (asks for the code), then a live thread:
                        host messages print as they arrive, each line you
                        type is sent back. Ctrl-D detaches; you stay joined.
  drop join             reattach to the session you already joined
  command | drop send   send that output to the host as one message
  drop send some text   send the words as one message
  drop last             print the latest host message exactly as sent
                        (for example: drop last > config.yml)
  drop leave            forget the session on this machine
`

var errSessionOver = errors.New("the session has ended")

// guestState is what a joined guest keeps between commands. It is the
// terminal equivalent of the browser tab's sessionStorage.
type guestState struct {
	Base  string `json:"base"`
	SID   string `json:"sid"`
	C2S   []byte `json:"c2s"`
	S2C   []byte `json:"s2c"`
	Token string `json:"token"`
}

func guestStatePath() (string, error) {
	dir := os.Getenv("DROP_GUEST_DIR")
	if dir == "" {
		if rt := os.Getenv("XDG_RUNTIME_DIR"); rt != "" {
			dir = filepath.Join(rt, "drop")
		} else {
			cache, err := os.UserCacheDir()
			if err != nil {
				return "", err
			}
			dir = filepath.Join(cache, "drop")
		}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return filepath.Join(dir, "guest-session.json"), nil
}

func loadGuestState() *guestState {
	path, err := guestStatePath()
	if err != nil {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var st guestState
	if json.Unmarshal(b, &st) != nil || st.Base == "" || st.Token == "" {
		return nil
	}
	return &st
}

func saveGuestState(st *guestState) error {
	path, err := guestStatePath()
	if err != nil {
		return err
	}
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

func forgetGuestState() {
	if path, err := guestStatePath(); err == nil {
		os.Remove(path)
	}
}

// hostURL turns what the user typed into a base URL. A bare IP address or
// anything with a port is the LAN form (plain HTTP); a bare name is the
// internet form (HTTPS).
func hostURL(addr string) string {
	addr = strings.TrimRight(strings.TrimSpace(addr), "/")
	if strings.HasPrefix(addr, "http://") || strings.HasPrefix(addr, "https://") {
		return addr
	}
	host := addr
	hasPort := false
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host, hasPort = h, true
	}
	if hasPort || net.ParseIP(host) != nil || host == "localhost" {
		return "http://" + addr
	}
	return "https://" + addr
}

type guestClient struct {
	base string
	st   *guestState
}

// call makes one request to the host and returns the status and raw body.
func (c *guestClient) call(method, path string, body any, timeout time.Duration) (int, []byte, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.base+path, rd)
	if err != nil {
		return 0, nil, err
	}
	if c.st != nil {
		req.Header.Set("X-Drop-Token", c.st.Token)
	}
	resp, err := (&http.Client{Timeout: timeout}).Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("cannot reach the host at %s", c.base)
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	return resp.StatusCode, out, err
}

func (c *guestClient) hello() (sid, status string, err error) {
	code, out, err := c.call("GET", "/api/hello", nil, 10*time.Second)
	if err != nil {
		return "", "", err
	}
	var h struct{ SID, Status string }
	if code != 200 || json.Unmarshal(out, &h) != nil || h.SID == "" {
		return "", "", fmt.Errorf("%s does not look like a drop host", c.base)
	}
	return h.SID, h.Status, nil
}

// join runs the handshake with one code. errWrongCode means try another.
func (c *guestClient) join(sid, code string) error {
	x, X, err := pakeStart(sid, code, rand.Reader)
	if err != nil {
		return err
	}
	status, out, err := c.call("POST", "/api/join", map[string]string{"x": base64.StdEncoding.EncodeToString(X)}, 10*time.Second)
	if err != nil {
		return err
	}
	if status != 200 {
		return joinError(status)
	}
	var r1 struct{ ID, Y string }
	json.Unmarshal(out, &r1)
	Y, _ := base64.StdEncoding.DecodeString(r1.Y)
	keys, err := pakeFinish(sid, x, X, Y)
	if err != nil {
		return errors.New("the host sent a bad reply")
	}
	status, out, err = c.call("POST", "/api/confirm", map[string]string{
		"id": r1.ID, "mac": base64.StdEncoding.EncodeToString(keys.clientMac),
	}, 10*time.Second)
	if err != nil {
		return err
	}
	if status != 200 {
		return joinError(status)
	}
	var r2 struct{ MAC string }
	json.Unmarshal(out, &r2)
	if r2.MAC != base64.StdEncoding.EncodeToString(keys.hostMac) {
		return errors.New("could not verify the host; do not use this connection")
	}
	c.st = &guestState{Base: c.base, SID: sid, C2S: keys.c2s, S2C: keys.s2c, Token: keys.token}
	return saveGuestState(c.st)
}

func joinError(status int) error {
	switch status {
	case http.StatusForbidden:
		return errWrongCode
	case http.StatusConflict:
		return errors.New("another device has already joined this session")
	case http.StatusLocked:
		return errors.New("too many wrong codes; ask for a new code on the host")
	case http.StatusGone:
		return errSessionOver
	}
	return fmt.Errorf("could not join (status %d)", status)
}

// events fetches the thread past a cursor. With wait, the host holds the
// request until something arrives.
func (c *guestClient) events(after int64, wait bool) ([]Event, error) {
	path := fmt.Sprintf("/api/poll?after=%d", after)
	timeout := pollHoldClient
	if !wait {
		path += "&wait=0"
		timeout = 10 * time.Second
	}
	status, out, err := c.call("GET", path, nil, timeout)
	if err != nil {
		return nil, err
	}
	if status == http.StatusUnauthorized || status == http.StatusGone {
		return nil, errSessionOver
	}
	if status != 200 {
		return nil, fmt.Errorf("the host answered with status %d", status)
	}
	var r struct{ Box sealedBox }
	if err := json.Unmarshal(out, &r); err != nil {
		return nil, err
	}
	var events []Event
	if err := open(c.st.S2C, "s2c", r.Box, &events); err != nil {
		return nil, errors.New("could not decrypt what the host sent")
	}
	return events, nil
}

const pollHoldClient = 40 * time.Second

func (c *guestClient) send(body string) error {
	if strings.TrimSpace(body) == "" {
		return errors.New("nothing to send")
	}
	if len(body) > maxInboundBytes {
		return fmt.Errorf("too long: %d bytes, the limit is %d", len(body), maxInboundBytes)
	}
	box, err := seal(c.st.C2S, "c2s", map[string]string{"body": body})
	if err != nil {
		return err
	}
	status, _, err := c.call("POST", "/api/send", box, 15*time.Second)
	if err != nil {
		return err
	}
	switch status {
	case 200:
		return nil
	case http.StatusUnauthorized, http.StatusGone:
		return errSessionOver
	case http.StatusRequestEntityTooLarge:
		return errors.New("too long: the limit is 64 KB per message")
	case http.StatusTooManyRequests:
		return errors.New("too many messages; wait a moment")
	case http.StatusBadRequest:
		return errors.New("the message must be text")
	}
	return fmt.Errorf("not sent (status %d)", status)
}

// joinedClient returns a client for the saved session, or an error telling
// the user to join first.
func joinedClient() (*guestClient, error) {
	st := loadGuestState()
	if st == nil {
		return nil, errors.New("not joined; run `drop join <address>` first")
	}
	return &guestClient{base: st.Base, st: st}, nil
}

func over(err error) error {
	if errors.Is(err, errSessionOver) {
		forgetGuestState()
	}
	return err
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func runGuestCommand(cmd string, args []string) error {
	switch cmd {
	case "join":
		return guestJoin(args)
	case "send":
		return guestSend(args)
	case "last":
		return guestLast()
	case "leave":
		forgetGuestState()
		fmt.Println("Left. This machine no longer holds the session.")
		return nil
	}
	return errors.New("unknown command")
}

func guestSend(args []string) error {
	c, err := joinedClient()
	if err != nil {
		return err
	}
	body := strings.Join(args, " ")
	if len(args) == 0 {
		if isTerminal(os.Stdin) {
			return errors.New("give the text as arguments, or pipe it in: command | drop send")
		}
		b, err := io.ReadAll(io.LimitReader(os.Stdin, maxInboundBytes+1))
		if err != nil {
			return err
		}
		body = strings.TrimRight(string(b), "\n")
	}
	if err := c.send(body); err != nil {
		return over(err)
	}
	fmt.Fprintln(os.Stderr, "Sent.")
	return nil
}

func guestLast() error {
	c, err := joinedClient()
	if err != nil {
		return err
	}
	events, err := c.events(0, false)
	if err != nil {
		return over(err)
	}
	for i := len(events) - 1; i >= 0; i-- {
		switch e := events[i]; {
		case e.T == "end":
			return over(errSessionOver)
		case e.T == "msg" && e.Dir == "out":
			// Exact bytes, so redirecting to a file gives the host's text
			// and nothing else. A terminal gets a closing newline.
			fmt.Print(e.Body)
			if isTerminal(os.Stdout) && !strings.HasSuffix(e.Body, "\n") {
				fmt.Println()
			}
			return nil
		}
	}
	return errors.New("the host has not sent anything yet")
}

func guestJoin(args []string) error {
	in := bufio.NewReaderSize(os.Stdin, maxInboundBytes+1024)
	base := ""
	if len(args) > 0 {
		base = hostURL(args[0])
	}

	// Reattach when this machine already holds a live session with that host.
	if st := loadGuestState(); st != nil && (base == "" || base == st.Base) {
		c := &guestClient{base: st.Base, st: st}
		if sid, _, err := c.hello(); err == nil && sid == st.SID {
			if _, err := c.events(0, false); err == nil {
				fmt.Fprintln(os.Stderr, "Reattached to", st.Base)
				return c.thread(in)
			}
		}
		forgetGuestState()
		if base == "" {
			return errors.New("the session you joined has ended; run `drop join <address>` for a new one")
		}
	}
	if base == "" {
		return errors.New("usage: drop join <address>")
	}

	c := &guestClient{base: base}
	sid, status, err := c.hello()
	if err != nil {
		return err
	}
	switch status {
	case "ended":
		return errSessionOver
	case "busy":
		return joinError(http.StatusConflict)
	case "locked":
		return joinError(http.StatusLocked)
	}
	for {
		fmt.Fprint(os.Stderr, "Code shown on the host: ")
		line, err := in.ReadString('\n')
		code := normalizeCode(line)
		if len(code) != codeLength {
			if err != nil {
				return errors.New("no code entered")
			}
			fmt.Fprintf(os.Stderr, "The code has %d characters.\n", codeLength)
			continue
		}
		err = c.join(sid, code)
		if errors.Is(err, errWrongCode) {
			fmt.Fprintln(os.Stderr, "Wrong code.")
			continue
		}
		if err != nil {
			return err
		}
		break
	}
	fmt.Fprintln(os.Stderr, "Joined. Host messages appear below. Type a line and press Enter to send it; Ctrl-D detaches.")
	return c.thread(in)
}

// thread is the interactive view: a poller prints what the host sends while
// lines typed on stdin go back as messages.
func (c *guestClient) thread(in *bufio.Reader) error {
	var mu sync.Mutex // guards printing and ownEchoes
	ownEchoes := 0    // messages sent from here whose echo should not be printed
	ended := make(chan error, 1)
	caughtUp := make(chan struct{}) // closed once the backlog has been printed

	go func() {
		var cursor int64
		fails := 0
		first := true
		for {
			// The first fetch does not wait, so what the host already sent
			// shows up at once.
			events, err := c.events(cursor, !first)
			if errors.Is(err, errSessionOver) {
				ended <- errSessionOver
				return
			}
			if err != nil {
				fails++
				if fails >= 4 {
					ended <- errors.New("lost contact with the host")
					return
				}
				time.Sleep(1500 * time.Millisecond)
				continue
			}
			fails = 0
			for _, e := range events {
				if e.Seq > cursor {
					cursor = e.Seq
				}
				switch e.T {
				case "end":
					ended <- errSessionOver
					return
				case "msg":
					mu.Lock()
					if e.Dir == "in" && ownEchoes > 0 {
						ownEchoes--
						mu.Unlock()
						continue
					}
					who := "host"
					if e.Dir == "in" {
						who = "you"
					}
					fmt.Printf("\n[%s %s]\n%s\n", who, time.UnixMilli(e.TS).Format("15:04:05"), cleanForTerminal(e.Body))
					mu.Unlock()
				}
			}
			if first {
				first = false
				close(caughtUp)
			}
		}
	}()

	lines := make(chan string)
	go func() {
		defer close(lines)
		for {
			line, err := in.ReadString('\n')
			if strings.TrimSpace(line) != "" {
				lines <- strings.TrimRight(line, "\r\n")
			}
			if err != nil {
				return
			}
		}
	}()

	finish := func(err error) error {
		if errors.Is(err, errSessionOver) {
			forgetGuestState()
			fmt.Fprintln(os.Stderr, "\nThe session was ended on the host. Nothing is kept here except what is on your screen.")
			return nil
		}
		return err
	}
	for {
		select {
		case err := <-ended:
			return finish(err)
		case line, ok := <-lines:
			if !ok {
				// Input ran out (Ctrl-D, or a pipe closing). Show the backlog
				// before going, so a scripted join still prints the thread.
				select {
				case <-caughtUp:
				case err := <-ended:
					return finish(err)
				case <-time.After(10 * time.Second):
				}
				fmt.Fprintln(os.Stderr, "\nDetached; still joined. `drop join` reattaches, `drop leave` forgets the session.")
				return nil
			}
			mu.Lock()
			ownEchoes++
			mu.Unlock()
			if err := c.send(line); err != nil {
				mu.Lock()
				ownEchoes--
				mu.Unlock()
				if errors.Is(err, errSessionOver) {
					forgetGuestState()
					return err
				}
				fmt.Fprintln(os.Stderr, "Not sent:", err)
			}
		}
	}
}
