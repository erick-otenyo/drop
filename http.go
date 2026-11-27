//go:build !guestonly

package main

import (
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"
)

//go:embed web
var webFS embed.FS

const (
	pollHold     = 25 * time.Second
	maxGuestBody = 1 << 20
	adminCookie  = "drop_admin"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeOK(w http.ResponseWriter) { writeJSON(w, http.StatusOK, map[string]bool{"ok": true}) }

func writeErr(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, errEnded), errors.Is(err, errNoSession):
		status = http.StatusGone
	case errors.Is(err, errBusy), errors.Is(err, errReplay), errors.Is(err, errNotIdle):
		status = http.StatusConflict
	case errors.Is(err, errLocked):
		status = http.StatusLocked
	case errors.Is(err, errWrongCode):
		status = http.StatusForbidden
	case errors.Is(err, errAuth):
		status = http.StatusUnauthorized
	case errors.Is(err, errTooBig):
		status = http.StatusRequestEntityTooLarge
	case errors.Is(err, errRate):
		status = http.StatusTooManyRequests
	case errors.Is(err, errBadText):
		status = http.StatusBadRequest
	}
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func readJSON(w http.ResponseWriter, r *http.Request, limit int64, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return false
	}
	return true
}

// secure sets the headers every response gets: nothing is cached, nothing
// loads from elsewhere, and no inline script runs.
func secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func asset(name, contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b, err := webFS.ReadFile("web/" + name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", contentType)
		w.Write(b)
	}
}

const (
	typeHTML = "text/html; charset=utf-8"
	typeJS   = "text/javascript; charset=utf-8"
	typeCSS  = "text/css; charset=utf-8"
)

func queryInt(r *http.Request, name string) int64 {
	n, _ := strconv.ParseInt(r.URL.Query().Get(name), 10, 64)
	return n
}

func pathID(r *http.Request) int64 {
	n, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return n
}

// ---- Guest surface: everything the other computer can reach ----

func guestHandler(s *Session) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", asset("guest.html", typeHTML))
	mux.HandleFunc("GET /guest.js", asset("guest.js", typeJS))
	mux.HandleFunc("GET /vendor.js", asset("vendor.js", typeJS))
	mux.HandleFunc("GET /common.js", asset("common.js", typeJS))
	mux.HandleFunc("GET /style.css", asset("style.css", typeCSS))

	// The terminal client, for guests with no browser.
	mux.HandleFunc("GET /get/{platform}", func(w http.ResponseWriter, r *http.Request) {
		b, ok := clientBinary(r.PathValue("platform"))
		if !ok {
			http.Error(w, "no client for that platform; this host has linux-amd64 and linux-arm64\n", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(b)
	})

	mux.HandleFunc("GET /api/hello", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"sid": s.sid, "status": s.GuestStatus()})
	})

	mux.HandleFunc("POST /api/join", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			X string `json:"x"`
		}
		if !readJSON(w, r, 4096, &req) {
			return
		}
		X, err := base64.StdEncoding.DecodeString(req.X)
		if err != nil {
			writeErr(w, errBadText)
			return
		}
		id, Y, err := s.JoinStart(X)
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"id": id, "y": base64.StdEncoding.EncodeToString(Y)})
	})

	mux.HandleFunc("POST /api/confirm", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID  string `json:"id"`
			MAC string `json:"mac"`
		}
		if !readJSON(w, r, 4096, &req) {
			return
		}
		mac, err := base64.StdEncoding.DecodeString(req.MAC)
		if err != nil {
			writeErr(w, errWrongCode)
			return
		}
		hostMac, err := s.JoinConfirm(req.ID, mac)
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"mac": base64.StdEncoding.EncodeToString(hostMac)})
	})

	mux.HandleFunc("POST /api/send", func(w http.ResponseWriter, r *http.Request) {
		var box sealedBox
		if !readJSON(w, r, maxGuestBody, &box) {
			return
		}
		if err := s.Receive(r.Header.Get("X-Drop-Token"), box); err != nil {
			writeErr(w, err)
			return
		}
		writeOK(w)
	})

	mux.HandleFunc("GET /api/poll", func(w http.ResponseWriter, r *http.Request) {
		keys, err := s.GuestKeys(r.Header.Get("X-Drop-Token"))
		if err != nil {
			writeErr(w, err)
			return
		}
		after := queryInt(r, "after")
		noWait := r.URL.Query().Get("wait") == "0"
		deadline := time.NewTimer(pollHold)
		defer deadline.Stop()
		var events []Event
		for {
			var changed <-chan struct{}
			events, _, _, changed = s.EventsAfter(after)
			if len(events) > 0 || noWait {
				break
			}
			select {
			case <-changed:
				continue
			case <-deadline.C:
			case <-r.Context().Done():
			}
			break
		}
		box, err := seal(keys.s2c, "s2c", events)
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"box": box})
	})
	return secure(mux)
}

// ---- Admin surface: the host's own page, loopback only ----

func (a *App) adminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", asset("admin.html", typeHTML))
	mux.HandleFunc("GET /admin.js", asset("admin.js", typeJS))
	mux.HandleFunc("GET /common.js", asset("common.js", typeJS))
	mux.HandleFunc("GET /style.css", asset("style.css", typeCSS))

	// One long poll carries both app-level changes (a session starting or
	// ending) and the live session's thread.
	mux.HandleFunc("GET /api/poll", func(w http.ResponseWriter, r *http.Request) {
		appVer, sessVer, after, tracked := queryInt(r, "av"), queryInt(r, "sv"), queryInt(r, "after"), queryInt(r, "sid")
		deadline := time.NewTimer(pollHold)
		defer deadline.Stop()
		for {
			st, s, appChanged := a.Snapshot()
			events := []Event{}
			var sessChanged <-chan struct{}
			ready := st.Version != appVer
			if s != nil {
				if s.dbID != tracked {
					after, sessVer = 0, -1
				}
				var ver int64
				events, _, ver, sessChanged = s.EventsAfter(after)
				ready = ready || len(events) > 0 || ver != sessVer
				ss := s.State()
				st.Session = &ss
			}
			done := ready
			if !done {
				select {
				case <-appChanged:
				case <-sessChanged:
				case <-deadline.C:
					done = true
				case <-r.Context().Done():
					done = true
				}
			}
			if done {
				writeJSON(w, http.StatusOK, map[string]any{"app": st, "events": events})
				return
			}
		}
	})

	mux.HandleFunc("POST /api/start", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Mode string `json:"mode"`
		}
		if !readJSON(w, r, 1024, &req) {
			return
		}
		if err := a.Start(req.Mode, ""); err != nil {
			writeErr(w, err)
			return
		}
		writeOK(w)
	})
	mux.HandleFunc("POST /api/cancel", func(w http.ResponseWriter, r *http.Request) {
		a.CancelStart()
		writeOK(w)
	})
	mux.HandleFunc("POST /api/quit", func(w http.ResponseWriter, r *http.Request) {
		writeOK(w)
		a.Quit()
	})

	live := func(fn func(s *Session, w http.ResponseWriter, r *http.Request) error) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			s, err := a.Session()
			if err == nil {
				err = fn(s, w, r)
			}
			if err != nil {
				writeErr(w, err)
				return
			}
			writeOK(w)
		}
	}
	mux.HandleFunc("POST /api/send", live(func(s *Session, w http.ResponseWriter, r *http.Request) error {
		var req struct {
			Body string `json:"body"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxOutboundBytes*7)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return errBadText
		}
		return s.Send(req.Body)
	}))
	mux.HandleFunc("POST /api/end", live(func(s *Session, w http.ResponseWriter, r *http.Request) error {
		s.End("stopped")
		return nil
	}))
	mux.HandleFunc("POST /api/newcode", live(func(s *Session, w http.ResponseWriter, r *http.Request) error {
		return s.NewCode()
	}))

	mux.HandleFunc("GET /api/history", func(w http.ResponseWriter, r *http.Request) {
		rows, err := a.store.ListSessions(r.URL.Query().Get("q"))
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, rows)
	})
	mux.HandleFunc("DELETE /api/history", func(w http.ResponseWriter, r *http.Request) {
		if err := a.store.DeleteAllExcept(a.liveID()); err != nil {
			writeErr(w, err)
			return
		}
		writeOK(w)
	})
	mux.HandleFunc("GET /api/history/{id}", func(w http.ResponseWriter, r *http.Request) {
		rows, err := a.store.SessionMessages(pathID(r))
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, rows)
	})
	mux.HandleFunc("DELETE /api/history/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := pathID(r)
		if id == a.liveID() {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "end the session before deleting it"})
			return
		}
		if err := a.store.DeleteSession(id); err != nil {
			writeErr(w, err)
			return
		}
		writeOK(w)
	})
	mux.HandleFunc("DELETE /api/message/{id}", func(w http.ResponseWriter, r *http.Request) {
		if err := a.DeleteMessage(pathID(r)); err != nil {
			writeErr(w, err)
			return
		}
		writeOK(w)
	})
	return secure(a.adminOnly(mux))
}

// adminOnly keeps the admin page to this computer's own browser. The Host
// check stops DNS rebinding, the token stops other local users and programs,
// and the SameSite cookie stops other websites from driving the API.
func (a *App) adminOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != a.adminHost {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		same := func(got string) bool {
			return subtle.ConstantTimeCompare([]byte(got), []byte(a.adminToken)) == 1
		}
		if t := r.URL.Query().Get("t"); r.URL.Path == "/" && t != "" {
			if !same(t) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: adminCookie, Value: t, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		c, err := r.Cookie(adminCookie)
		if err != nil || !same(c.Value) {
			http.Error(w, "Open the link that drop printed in your terminal.", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
