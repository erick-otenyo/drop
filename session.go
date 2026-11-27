//go:build !guestonly

package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	maxJoinAttempts  = 5
	maxOutboundBytes = 256 << 10
	inboundPerMinute = 30
	idleTimeout      = 15 * time.Minute
)

var (
	errEnded   = errors.New("session ended")
	errBusy    = errors.New("another device already joined this session")
	errLocked  = errors.New("too many wrong codes")
	errAuth    = errors.New("not joined")
	errTooBig  = errors.New("message too large")
	errRate    = errors.New("too many messages, slow down")
	errReplay  = errors.New("duplicate message")
	errBadText = errors.New("message must be non-empty text")
)

// State is what the admin page shows about the session.
type State struct {
	Active       bool   `json:"active"`
	Mode         string `json:"mode"`
	URL          string `json:"url"`
	Code         string `json:"code"`
	Status       string `json:"status"` // waiting, joined, locked, ended
	AttemptsLeft int    `json:"attemptsLeft"`
	IdleAt       int64  `json:"idleAt"`
	Version      int64  `json:"version"`
	SessionID    int64  `json:"sessionId"`
}

// Session is one live exchange between the host and a single guest browser.
type Session struct {
	store     *Store
	dbID      int64
	sid       string
	mode      string
	url       string
	onInbound func()

	mu        sync.Mutex
	code      string
	attempts  int
	pending   map[string]*sessionKeys
	keys      *sessionKeys // set once a guest has joined
	seen      map[string]struct{}
	inbound   []time.Time
	events    []Event
	nextSeq   int64
	version   int64
	changed   chan struct{}
	ended     bool
	done      chan struct{}
	lastTouch time.Time
}

func randomCode() string {
	out := make([]byte, codeLength)
	for i := range out {
		for {
			var b [1]byte
			if _, err := rand.Read(b[:]); err != nil {
				panic(err)
			}
			// Rejection sampling keeps every character equally likely.
			if int(b[0]) < 256-256%len(codeAlphabet) {
				out[i] = codeAlphabet[int(b[0])%len(codeAlphabet)]
				break
			}
		}
	}
	return string(out)
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func newSession(store *Store, mode, url string) (*Session, error) {
	id, err := store.NewSession(mode)
	if err != nil {
		return nil, err
	}
	s := &Session{
		store:     store,
		dbID:      id,
		sid:       randomHex(16),
		mode:      mode,
		url:       url,
		code:      randomCode(),
		pending:   map[string]*sessionKeys{},
		seen:      map[string]struct{}{},
		changed:   make(chan struct{}),
		done:      make(chan struct{}),
		lastTouch: time.Now(),
	}
	go s.watchIdle()
	return s, nil
}

func (s *Session) watchIdle() {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-t.C:
			s.mu.Lock()
			idle := time.Since(s.lastTouch) >= idleTimeout
			s.mu.Unlock()
			if idle {
				s.End("idle")
				return
			}
		}
	}
}

// bump wakes every long poll. Callers hold s.mu.
func (s *Session) bump() {
	s.version++
	close(s.changed)
	s.changed = make(chan struct{})
}

func (s *Session) appendEvent(e Event) {
	s.nextSeq++
	e.Seq = s.nextSeq
	s.events = append(s.events, e)
	s.bump()
}

func (s *Session) statusLocked() string {
	switch {
	case s.ended:
		return "ended"
	case s.keys != nil:
		return "joined"
	case s.attempts >= maxJoinAttempts:
		return "locked"
	default:
		return "waiting"
	}
}

func (s *Session) State() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return State{
		Active:       !s.ended,
		Mode:         s.mode,
		URL:          s.url,
		Code:         s.code,
		Status:       s.statusLocked(),
		AttemptsLeft: max(0, maxJoinAttempts-s.attempts),
		IdleAt:       s.lastTouch.Add(idleTimeout).UnixMilli(),
		Version:      s.version,
		SessionID:    s.dbID,
	}
}

// GuestStatus is the little the join page may know before it has the code.
func (s *Session) GuestStatus() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st := s.statusLocked(); st != "joined" {
		return st
	}
	return "busy"
}

// EventsAfter returns the log past a cursor and a channel that closes on the
// next change of any kind.
func (s *Session) EventsAfter(after int64) (events []Event, next int64, version int64, changed <-chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	events = []Event{}
	for _, e := range s.events {
		if e.Seq > after && e.T != "gone" {
			events = append(events, e)
		}
	}
	return events, s.nextSeq, s.version, s.changed
}

func validText(body string, limit int) error {
	if len(body) > limit {
		return errTooBig
	}
	if !utf8.ValidString(body) || strings.TrimSpace(body) == "" {
		return errBadText
	}
	return nil
}

func (s *Session) addMessage(dir, body string) error {
	ts := nowMs()
	id, err := s.store.AddMessage(s.dbID, dir, body, ts)
	if err != nil {
		return err
	}
	s.lastTouch = time.Now()
	s.appendEvent(Event{T: "msg", ID: id, Dir: dir, Body: body, TS: ts})
	return nil
}

// Send posts a message from the host.
func (s *Session) Send(body string) error {
	if err := validText(body, maxOutboundBytes); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ended {
		return errEnded
	}
	return s.addMessage("out", body)
}

// JoinStart answers a guest's key-exchange share. Every call spends one of
// the session's attempts, whether or not the guest goes on to confirm.
func (s *Session) JoinStart(X []byte) (joinID string, Y []byte, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.ended:
		return "", nil, errEnded
	case s.keys != nil:
		return "", nil, errBusy
	case s.attempts >= maxJoinAttempts:
		return "", nil, errLocked
	}
	s.attempts++
	s.bump()
	Y, keys, err := pakeRespond(s.sid, s.code, X)
	if err != nil {
		return "", nil, err
	}
	joinID = randomHex(16)
	s.pending[joinID] = keys
	return joinID, Y, nil
}

// JoinConfirm completes a join. The first guest to prove it derived the same
// keys owns the session; nobody else can join after that.
func (s *Session) JoinConfirm(joinID string, clientMac []byte) (hostMac []byte, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ended {
		return nil, errEnded
	}
	if s.keys != nil {
		return nil, errBusy
	}
	keys, ok := s.pending[joinID]
	if !ok {
		return nil, errWrongCode
	}
	delete(s.pending, joinID)
	if subtle.ConstantTimeCompare(keys.clientMac, clientMac) != 1 {
		return nil, errWrongCode
	}
	s.keys = keys
	s.pending = map[string]*sessionKeys{}
	s.lastTouch = time.Now()
	s.bump()
	return keys.hostMac, nil
}

// NewCode replaces the join code and restores the attempts, for when a session
// was locked by wrong guesses before anyone joined.
func (s *Session) NewCode() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ended {
		return errEnded
	}
	if s.keys != nil {
		return errBusy
	}
	s.code = randomCode()
	s.attempts = 0
	s.pending = map[string]*sessionKeys{}
	s.bump()
	return nil
}

func (s *Session) authLocked(token string) (*sessionKeys, error) {
	if s.keys == nil || subtle.ConstantTimeCompare([]byte(s.keys.token), []byte(token)) != 1 {
		return nil, errAuth
	}
	return s.keys, nil
}

// GuestKeys returns the joined guest's keys if the token is its own.
func (s *Session) GuestKeys(token string) (*sessionKeys, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.authLocked(token)
}

// Receive accepts an encrypted message from the joined guest.
func (s *Session) Receive(token string, box sealedBox) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	keys, err := s.authLocked(token)
	if err != nil {
		return err
	}
	if s.ended {
		return errEnded
	}
	if len(box.C) > base64.StdEncoding.EncodedLen(maxInboundBytes*6+64) {
		return errTooBig
	}
	var msg struct {
		Body string `json:"body"`
	}
	if err := open(keys.c2s, "c2s", box, &msg); err != nil {
		return errAuth
	}
	if _, dup := s.seen[box.N]; dup {
		return errReplay
	}
	if err := validText(msg.Body, maxInboundBytes); err != nil {
		return err
	}
	cutoff := time.Now().Add(-time.Minute)
	recent := s.inbound[:0]
	for _, t := range s.inbound {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}
	s.inbound = recent
	if len(s.inbound) >= inboundPerMinute {
		return errRate
	}
	s.inbound = append(s.inbound, time.Now())
	s.seen[box.N] = struct{}{}
	if err := s.addMessage("in", msg.Body); err != nil {
		return err
	}
	if s.onInbound != nil {
		go s.onInbound()
	}
	return nil
}

// DeleteMessage removes a message from history and, if it belongs to this
// session, from the live thread on both sides.
func (s *Session) DeleteMessage(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.store.DeleteMessage(id); err != nil {
		return err
	}
	for i := range s.events {
		if s.events[i].T == "msg" && s.events[i].ID == id {
			s.events[i] = Event{Seq: s.events[i].Seq, T: "gone"}
			if !s.ended {
				s.appendEvent(Event{T: "del", ID: id})
			}
			break
		}
	}
	return nil
}

// End closes the session. It is safe to call more than once.
func (s *Session) End(reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ended {
		return
	}
	s.ended = true
	s.appendEvent(Event{T: "end", Body: reason})
	s.store.EndSession(s.dbID)
	close(s.done)
}

func (s *Session) Done() <-chan struct{} { return s.done }
