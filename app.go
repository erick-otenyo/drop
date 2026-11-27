//go:build !guestonly

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

var (
	errNotIdle   = errors.New("a session is already running or starting")
	errNoSession = errors.New("no session is running")
	errCancelled = errors.New("cancelled")
)

// endGrace is how long the guest listener stays up after a session ends, so
// the guest's page can collect the end event and wipe itself.
const endGrace = 1500 * time.Millisecond

// App is the long-lived host process: the admin page, the history store, and
// at most one live session at a time.
type App struct {
	store      *Store
	adminToken string
	adminHost  string // host:port the admin page is served on
	guestPort  int
	onLive     func(State) // called once a session is ready for a guest

	mu          sync.Mutex
	phase       string // idle, starting, live, stopping
	mode        string
	notice      []string // what Tailscale said while starting
	startErr    string
	lastEnded   int64
	live        *liveSession
	cancelStart chan struct{}
	version     int64
	changed     chan struct{}
	quit        chan struct{}
	quitOnce    sync.Once
}

type liveSession struct {
	s          *Session
	srv        *http.Server
	stopFunnel func()
}

// AppState is what the admin page renders.
type AppState struct {
	Phase     string       `json:"phase"`
	Mode      string       `json:"mode"`
	Notice    []string     `json:"notice"`
	Error     string       `json:"error"`
	LastEnded int64        `json:"lastEnded"`
	Version   int64        `json:"version"`
	Session   *State       `json:"session"`
	Clients   []ClientInfo `json:"clients"` // terminal clients this host can serve
}

func newApp(store *Store, adminHost string, guestPort int) *App {
	return &App{
		store:      store,
		adminToken: randomHex(24),
		adminHost:  adminHost,
		guestPort:  guestPort,
		phase:      "idle",
		changed:    make(chan struct{}),
		quit:       make(chan struct{}),
	}
}

// bump wakes the admin page's long poll. Callers hold a.mu.
func (a *App) bump() {
	a.version++
	close(a.changed)
	a.changed = make(chan struct{})
}

// Snapshot returns the current state, the live session if any, and a channel
// that closes on the next app-level change.
func (a *App) Snapshot() (AppState, *Session, <-chan struct{}) {
	a.mu.Lock()
	defer a.mu.Unlock()
	st := AppState{
		Phase:     a.phase,
		Mode:      a.mode,
		Notice:    append([]string{}, a.notice...),
		Error:     a.startErr,
		LastEnded: a.lastEnded,
		Version:   a.version,
		Clients:   bundledClients(),
	}
	var s *Session
	if a.live != nil {
		s = a.live.s
		ss := s.State()
		st.Session = &ss
	}
	return st, s, a.changed
}

// Session returns the live session, or an error when there is none.
func (a *App) Session() (*Session, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.live == nil || a.phase != "live" {
		return nil, errNoSession
	}
	return a.live.s, nil
}

// Start begins a session in the background. first, if not empty, is posted
// as the opening message once the session is up.
func (a *App) Start(mode, first string) error {
	if mode != "lan" && mode != "net" {
		return errors.New("mode must be lan or net")
	}
	a.mu.Lock()
	if a.phase != "idle" {
		a.mu.Unlock()
		return errNotIdle
	}
	a.phase, a.mode, a.notice, a.startErr = "starting", mode, nil, ""
	cancel := make(chan struct{})
	a.cancelStart = cancel
	a.bump()
	a.mu.Unlock()

	go func() {
		live, err := a.bringUp(mode, cancel)
		a.mu.Lock()
		a.cancelStart = nil
		if err != nil {
			a.phase = "idle"
			if !errors.Is(err, errCancelled) {
				a.startErr = err.Error()
			}
			a.bump()
			a.mu.Unlock()
			return
		}
		a.live, a.phase = live, "live"
		a.bump()
		a.mu.Unlock()
		if first != "" {
			live.s.Send(first)
		}
		if a.onLive != nil {
			a.onLive(live.s.State())
		}
		a.watch(live)
	}()
	return nil
}

func (a *App) addNotice(line string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.notice = append(a.notice, line)
	a.bump()
}

// bringUp opens the guest listener (and the Funnel, for internet mode) and
// creates the session.
func (a *App) bringUp(mode string, cancel <-chan struct{}) (*liveSession, error) {
	var bind, url, dnsName string
	if mode == "lan" {
		ip, err := lanIP()
		if err != nil {
			return nil, err
		}
		bind = fmt.Sprintf("%s:%d", ip, a.guestPort)
		url = "http://" + bind
	} else {
		name, err := tailscaleDNSName()
		if err != nil {
			return nil, err
		}
		dnsName = name
		bind = fmt.Sprintf("127.0.0.1:%d", a.guestPort)
		url = "https://" + name
	}
	ln, err := net.Listen("tcp", bind)
	if err != nil {
		return nil, fmt.Errorf("port %d is taken; free it or restart drop with --port", a.guestPort)
	}
	session, err := newSession(a.store, mode, url)
	if err != nil {
		ln.Close()
		return nil, err
	}
	session.onInbound = notifyInbound
	live := &liveSession{s: session, srv: newServer(guestHandler(session)), stopFunnel: func() {}}
	go live.srv.Serve(ln)
	if mode == "net" {
		stop, err := startFunnel(a.guestPort, dnsName, cancel, a.addNotice)
		if err != nil {
			session.End("stopped")
			live.srv.Close()
			return nil, err
		}
		live.stopFunnel = stop
	}
	return live, nil
}

// watch tears the guest side down when the session ends, then returns the
// app to idle so another session can start.
func (a *App) watch(live *liveSession) {
	<-live.s.Done()
	a.mu.Lock()
	a.phase = "stopping"
	a.bump()
	a.mu.Unlock()

	time.Sleep(endGrace)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	live.srv.Shutdown(ctx)
	cancel()
	live.srv.Close()
	live.stopFunnel()

	a.mu.Lock()
	a.live, a.phase, a.lastEnded = nil, "idle", live.s.dbID
	a.bump()
	a.mu.Unlock()
}

// CancelStart abandons a session that is still starting.
func (a *App) CancelStart() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cancelStart != nil {
		close(a.cancelStart)
		a.cancelStart = nil
	}
}

// Quit asks the process to exit.
func (a *App) Quit() { a.quitOnce.Do(func() { close(a.quit) }) }

// Close ends whatever is running and waits for the guest side to be torn down.
func (a *App) Close() {
	a.CancelStart()
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		a.mu.Lock()
		phase, live := a.phase, a.live
		a.mu.Unlock()
		if phase == "idle" {
			return
		}
		if live != nil {
			live.s.End("stopped")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// DeleteMessage removes a message from history and from the live thread if
// it is part of it.
func (a *App) DeleteMessage(id int64) error {
	a.mu.Lock()
	live := a.live
	a.mu.Unlock()
	if live != nil {
		return live.s.DeleteMessage(id)
	}
	return a.store.DeleteMessage(id)
}

// liveID is the history id of the session that must not be deleted yet.
func (a *App) liveID() int64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.live != nil {
		return a.live.s.dbID
	}
	return 0
}
