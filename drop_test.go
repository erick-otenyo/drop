//go:build !guestonly

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// testApp returns an app with a live session and its guest surface, skipping
// the real listeners.
func testApp(t *testing.T) (*App, *Session, *httptest.Server) {
	t.Helper()
	store, err := openStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	session, err := newSession(store, "lan", "http://192.168.0.2:8090")
	if err != nil {
		t.Fatal(err)
	}
	app := newApp(store, "127.0.0.1:8091", 8090)
	app.adminToken = "admintoken"
	app.live, app.phase = &liveSession{s: session}, "live"
	srv := httptest.NewServer(guestHandler(session))
	t.Cleanup(func() { srv.Close(); session.End("stopped"); store.Close() })
	return app, session, srv
}

func postJSON(t *testing.T, url string, body any, token string) (*http.Response, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", url, bytes.NewReader(b))
	req.Header.Set("X-Drop-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out := map[string]any{}
	json.NewDecoder(resp.Body).Decode(&out)
	return resp, out
}

// join plays the browser's half of the handshake with the given code.
func join(t *testing.T, base, sid, code string) (int, *sessionKeys) {
	t.Helper()
	x, X, err := pakeStart(sid, code, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	resp, out := postJSON(t, base+"/api/join", map[string]string{"x": base64.StdEncoding.EncodeToString(X)}, "")
	if resp.StatusCode != 200 {
		return resp.StatusCode, nil
	}
	Y, _ := base64.StdEncoding.DecodeString(out["y"].(string))
	keys, err := pakeFinish(sid, x, X, Y)
	if err != nil {
		t.Fatal(err)
	}
	resp, out = postJSON(t, base+"/api/confirm", map[string]string{
		"id": out["id"].(string), "mac": base64.StdEncoding.EncodeToString(keys.clientMac),
	}, "")
	if resp.StatusCode != 200 {
		return resp.StatusCode, nil
	}
	if out["mac"] != base64.StdEncoding.EncodeToString(keys.hostMac) {
		t.Fatal("host confirmation does not match")
	}
	return 200, keys
}

func pollEvents(t *testing.T, base string, keys *sessionKeys, after int64) []Event {
	t.Helper()
	req, _ := http.NewRequest("GET", base+"/api/poll?after="+jsonNum(after), nil)
	req.Header.Set("X-Drop-Token", keys.token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("poll status %d", resp.StatusCode)
	}
	var out struct{ Box sealedBox }
	json.NewDecoder(resp.Body).Decode(&out)
	var events []Event
	if err := open(keys.s2c, "s2c", out.Box, &events); err != nil {
		t.Fatal(err)
	}
	return events
}

func jsonNum(n int64) string { b, _ := json.Marshal(n); return string(b) }

func TestWrongCodeYieldsDifferentKeys(t *testing.T) {
	x, X, _ := pakeStart("sid", "AAAAAA", rand.Reader)
	Y, serverKeys, err := pakeRespond("sid", "BBBBBB", X)
	if err != nil {
		t.Fatal(err)
	}
	clientKeys, _ := pakeFinish("sid", x, X, Y)
	if bytes.Equal(clientKeys.clientMac, serverKeys.clientMac) || bytes.Equal(clientKeys.c2s, serverKeys.c2s) {
		t.Fatal("different codes must not agree on keys")
	}
}

func TestIdentityShareRejected(t *testing.T) {
	if _, _, err := pakeRespond("sid", "AAAAAA", make([]byte, 32)); err == nil {
		t.Fatal("the identity element must be rejected as a share")
	}
}

func TestJoinThenExchangeMessages(t *testing.T) {
	app, s, srv := testApp(t)
	if err := s.Send("echo before join"); err != nil {
		t.Fatal(err)
	}

	if status, _ := join(t, srv.URL, s.sid, "ZZZZZZ"); status != http.StatusForbidden {
		t.Fatalf("wrong code: got %d, want 403", status)
	}
	status, keys := join(t, srv.URL, s.sid, s.State().Code)
	if status != 200 {
		t.Fatalf("right code: got %d", status)
	}
	if st := s.State().Status; st != "joined" {
		t.Fatalf("status %q, want joined", st)
	}
	if status, _ := join(t, srv.URL, s.sid, s.State().Code); status != http.StatusConflict {
		t.Fatalf("second device: got %d, want 409", status)
	}

	// The guest sees what the host sent, including what predates the join.
	events := pollEvents(t, srv.URL, keys, 0)
	if len(events) != 1 || events[0].Body != "echo before join" || events[0].Dir != "out" {
		t.Fatalf("unexpected events %+v", events)
	}

	// The guest sends back; it lands in the thread and in history.
	box, _ := seal(keys.c2s, "c2s", map[string]string{"body": "<b>reply</b>"})
	if resp, _ := postJSON(t, srv.URL+"/api/send", box, keys.token); resp.StatusCode != 200 {
		t.Fatalf("send: got %d", resp.StatusCode)
	}
	if resp, _ := postJSON(t, srv.URL+"/api/send", box, keys.token); resp.StatusCode != http.StatusConflict {
		t.Fatalf("replayed message: got %d, want 409", resp.StatusCode)
	}
	msgs, _ := app.store.SessionMessages(s.dbID)
	if len(msgs) != 2 || msgs[1].Dir != "in" || msgs[1].Body != "<b>reply</b>" {
		t.Fatalf("history %+v", msgs)
	}

	// Deleting on the host removes it from history and from the guest's log.
	if err := app.DeleteMessage(msgs[0].ID); err != nil {
		t.Fatal(err)
	}
	events = pollEvents(t, srv.URL, keys, 0)
	for _, e := range events {
		if e.Body == "echo before join" {
			t.Fatal("deleted message is still served")
		}
	}

	s.End("stopped")
	events = pollEvents(t, srv.URL, keys, events[len(events)-1].Seq)
	if len(events) != 1 || events[0].T != "end" {
		t.Fatalf("want end event, got %+v", events)
	}
	if resp, _ := postJSON(t, srv.URL+"/api/send", box, keys.token); resp.StatusCode != http.StatusGone {
		t.Fatalf("send after end: got %d, want 410", resp.StatusCode)
	}
}

func TestInboundLimits(t *testing.T) {
	_, s, srv := testApp(t)
	_, keys := join(t, srv.URL, s.sid, s.State().Code)

	send := func(body, token string, key []byte) int {
		box, _ := seal(key, "c2s", map[string]string{"body": body})
		resp, _ := postJSON(t, srv.URL+"/api/send", box, token)
		return resp.StatusCode
	}
	if got := send(strings.Repeat("a", maxInboundBytes+1), keys.token, keys.c2s); got != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize: got %d, want 413", got)
	}
	if got := send("hi", "bogus", keys.c2s); got != http.StatusUnauthorized {
		t.Fatalf("bad token: got %d, want 401", got)
	}
	if got := send("hi", keys.token, keys.s2c); got != http.StatusUnauthorized {
		t.Fatalf("wrong key: got %d, want 401", got)
	}
	if got := send("   ", keys.token, keys.c2s); got != http.StatusBadRequest {
		t.Fatalf("blank: got %d, want 400", got)
	}
	for i := 0; i < inboundPerMinute; i++ {
		if got := send("ok", keys.token, keys.c2s); got != 200 {
			t.Fatalf("message %d: got %d", i, got)
		}
	}
	if got := send("one too many", keys.token, keys.c2s); got != http.StatusTooManyRequests {
		t.Fatalf("rate limit: got %d, want 429", got)
	}
}

func TestLockoutAndNewCode(t *testing.T) {
	_, s, srv := testApp(t)
	for i := 0; i < maxJoinAttempts; i++ {
		if status, _ := join(t, srv.URL, s.sid, "ZZZZZZ"); status != http.StatusForbidden {
			t.Fatalf("attempt %d: got %d, want 403", i, status)
		}
	}
	if status, _ := join(t, srv.URL, s.sid, s.State().Code); status != http.StatusLocked {
		t.Fatalf("after lockout the right code must be refused too: got %d", status)
	}
	old := s.State().Code
	if err := s.NewCode(); err != nil {
		t.Fatal(err)
	}
	if s.State().Code == old {
		t.Fatal("code did not change")
	}
	if status, _ := join(t, srv.URL, s.sid, s.State().Code); status != 200 {
		t.Fatalf("new code: got %d", status)
	}
}

func TestGuestCannotReachHistoryOrAdmin(t *testing.T) {
	_, _, srv := testApp(t)
	for _, path := range []string{"/api/history", "/api/history/1", "/api/message/1", "/admin.js", "/api/end", "/api/newcode", "/api/start", "/api/quit"} {
		for _, method := range []string{"GET", "POST", "DELETE"} {
			req, _ := http.NewRequest(method, srv.URL+path, nil)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusMethodNotAllowed {
				t.Errorf("%s %s on the guest surface: got %d", method, path, resp.StatusCode)
			}
		}
	}
}

func TestAdminPageNeedsTokenAndLoopbackHost(t *testing.T) {
	app, _, _ := testApp(t)
	h := app.adminHandler()
	do := func(host, cookie, target string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", target, nil)
		req.Host = host
		if cookie != "" {
			req.AddCookie(&http.Cookie{Name: adminCookie, Value: cookie})
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	if got := do("127.0.0.1:8091", "", "/api/history").Code; got != http.StatusForbidden {
		t.Errorf("no cookie: got %d, want 403", got)
	}
	if got := do("127.0.0.1:8091", "wrong", "/api/history").Code; got != http.StatusForbidden {
		t.Errorf("wrong cookie: got %d, want 403", got)
	}
	if got := do("evil.example:8091", "admintoken", "/api/history").Code; got != http.StatusForbidden {
		t.Errorf("rebinding host: got %d, want 403", got)
	}
	if got := do("127.0.0.1:8091", "admintoken", "/api/history").Code; got != http.StatusOK {
		t.Errorf("valid cookie: got %d, want 200", got)
	}
	rec := do("127.0.0.1:8091", "", "/?t=admintoken")
	if rec.Code != http.StatusSeeOther || !strings.Contains(rec.Header().Get("Set-Cookie"), adminCookie+"=admintoken") {
		t.Errorf("token link should set the cookie and redirect, got %d %q", rec.Code, rec.Header().Get("Set-Cookie"))
	}
	if got := do("127.0.0.1:8091", "", "/?t=nope").Code; got != http.StatusForbidden {
		t.Errorf("bad token link: got %d, want 403", got)
	}
}

func TestHistorySearchAndDelete(t *testing.T) {
	app, s, _ := testApp(t)
	s.Send("kubectl get pods")
	s.Send("100%_literal")
	s.End("stopped")

	rows, _ := app.store.ListSessions("kubectl")
	if len(rows) != 1 || rows[0].Count != 2 || rows[0].Preview != "kubectl get pods" {
		t.Fatalf("search: %+v", rows)
	}
	if rows, _ := app.store.ListSessions("%"); len(rows) != 1 || rows[0].Preview != "100%_literal" {
		t.Fatalf("%% must match literally: %+v", rows)
	}
	if rows, _ := app.store.ListSessions("nothing-like-this"); len(rows) != 0 {
		t.Fatalf("unexpected match: %+v", rows)
	}
	if err := app.store.DeleteSession(s.dbID); err != nil {
		t.Fatal(err)
	}
	if rows, _ := app.store.ListSessions(""); len(rows) != 0 {
		t.Fatalf("session not deleted: %+v", rows)
	}
}

func TestEmptySessionLeavesNoHistory(t *testing.T) {
	app, s, _ := testApp(t)
	s.End("stopped")
	if rows, _ := app.store.ListSessions(""); len(rows) != 0 {
		t.Fatalf("an empty session should not be kept: %+v", rows)
	}
}

func TestDeleteAllSparesTheLiveSession(t *testing.T) {
	app, s, _ := testApp(t)
	old, _ := app.store.NewSession("lan")
	app.store.AddMessage(old, "out", "old secret", nowMs())
	app.store.EndSession(old)
	s.Send("still live")

	req := httptest.NewRequest("DELETE", "/api/history", nil)
	req.Host = "127.0.0.1:8091"
	req.AddCookie(&http.Cookie{Name: adminCookie, Value: "admintoken"})
	rec := httptest.NewRecorder()
	app.adminHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete all: got %d", rec.Code)
	}
	rows, _ := app.store.ListSessions("")
	if len(rows) != 1 || rows[0].ID != s.dbID || rows[0].Count != 1 {
		t.Fatalf("want only the live session left, got %+v", rows)
	}
}

// A session started and ended through the app returns it to idle, ready for
// the next one, with the guest listener closed.
func TestAppRunsSessionsBackToBack(t *testing.T) {
	store, err := openStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := lanIP(); err != nil {
		t.Skip("no LAN address on this machine")
	}
	app := newApp(store, "127.0.0.1:0", 18090)
	waitPhase := func(want string) {
		t.Helper()
		for i := 0; i < 100; i++ {
			if st, _, _ := app.Snapshot(); st.Phase == want {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		st, _, _ := app.Snapshot()
		t.Fatalf("phase %q (error %q), want %q", st.Phase, st.Error, want)
	}
	for round := 0; round < 2; round++ {
		if err := app.Start("lan", "hello"); err != nil {
			t.Fatal(err)
		}
		waitPhase("live")
		if err := app.Start("lan", ""); err != errNotIdle {
			t.Fatalf("second start while live: got %v", err)
		}
		s, _ := app.Session()
		resp, err := http.Get(s.url + "/api/hello")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		s.End("stopped")
		waitPhase("idle")
		if _, err := http.Get(s.url + "/api/hello"); err == nil {
			t.Fatal("guest listener is still up after the session ended")
		}
	}
	if rows, _ := store.ListSessions(""); len(rows) != 2 {
		t.Fatalf("want 2 sessions in history, got %+v", rows)
	}
}

func TestHostURLGuessesScheme(t *testing.T) {
	for in, want := range map[string]string{
		"192.168.1.20:8090":         "http://192.168.1.20:8090",
		"192.168.1.20":              "http://192.168.1.20",
		"localhost:8090":            "http://localhost:8090",
		"box.tail1234.ts.net":       "https://box.tail1234.ts.net",
		"https://box.ts.net/":       "https://box.ts.net",
		"http://box.internal:8090/": "http://box.internal:8090",
	} {
		if got := hostURL(in); got != want {
			t.Errorf("hostURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCleanForTerminalStripsControlCodes(t *testing.T) {
	in := "ok\x1b[31m red\x1b]0;title\x07\r\n\ttab \u009b2J café"
	want := "ok[31m red]0;title\n\ttab 2J café"
	if got := cleanForTerminal(in); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// The terminal guest's own client code, against a real guest surface.
func TestTerminalGuestJoinsSendsAndReads(t *testing.T) {
	t.Setenv("DROP_GUEST_DIR", t.TempDir())
	app, s, srv := testApp(t)
	s.Send("first")
	s.Send("exact \x1b[1m bytes\n")

	c := &guestClient{base: srv.URL}
	sid, status, err := c.hello()
	if err != nil || status != "waiting" {
		t.Fatalf("hello: %v %q", err, status)
	}
	if err := c.join(sid, "ZZZZZZ"); err != errWrongCode {
		t.Fatalf("wrong code: got %v", err)
	}
	if err := c.join(sid, s.State().Code); err != nil {
		t.Fatal(err)
	}

	// A later command finds the saved session and needs no code.
	c2, err := joinedClient()
	if err != nil {
		t.Fatal(err)
	}
	events, err := c2.events(0, false)
	if err != nil || len(events) != 2 || events[1].Body != "exact \x1b[1m bytes\n" {
		t.Fatalf("events: %v %+v", err, events)
	}
	if events, err := c2.events(events[1].Seq, false); err != nil || len(events) != 0 {
		t.Fatalf("wait=0 with nothing new should return at once and empty: %v %+v", err, events)
	}
	if err := c2.send("uptime: 3 days"); err != nil {
		t.Fatal(err)
	}
	msgs, _ := app.store.SessionMessages(s.dbID)
	if len(msgs) != 3 || msgs[2].Dir != "in" || msgs[2].Body != "uptime: 3 days" {
		t.Fatalf("history %+v", msgs)
	}
	if err := c2.send(strings.Repeat("a", maxInboundBytes+1)); err == nil {
		t.Fatal("oversize message should be refused")
	}

	// Once the host ends the session the saved keys are dropped.
	s.End("stopped")
	if err := over(c2.send("too late")); err != errSessionOver {
		t.Fatalf("send after end: got %v", err)
	}
	if loadGuestState() != nil {
		t.Fatal("session file should be removed once the session is over")
	}
}

func TestHostServesBundledClient(t *testing.T) {
	_, _, srv := testApp(t)
	if len(bundledClients()) == 0 {
		t.Skip("clients not built; run make")
	}
	resp, err := http.Get(srv.URL + "/get/linux-x86_64")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	head := make([]byte, 4)
	resp.Body.Read(head)
	if resp.StatusCode != 200 || string(head) != "\x7fELF" {
		t.Fatalf("want a Linux executable, got status %d and %q", resp.StatusCode, head)
	}
	if resp, _ := http.Get(srv.URL + "/get/plan9-mips"); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown platform: got %d", resp.StatusCode)
	}
}
