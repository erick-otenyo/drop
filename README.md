# drop

Share text between this computer (the **host**) and the computer in front of
you (the **guest**), without SSH, pastebin, or installing anything on the guest.

```
drop                  # open the admin page: start sessions, browse history
drop lan              # open it with a LAN session already started
drop net              # open it with an internet session (Tailscale Funnel)
pbpaste | drop lan    # start with piped text as the first message
```

`drop` serves an admin page on 127.0.0.1 that stays up until you quit it
(Ctrl-C or the Quit button). From there you start a LAN or internet session,
which shows an address and a 6-character code. On the guest, open the address
in a browser and enter the code. Both sides can then post text to a live
thread. A session ends with the End session button or after 15 idle minutes;
the admin page then returns to the home view with that session at the top of
the history.

The admin page also holds the history: search, copy a whole session, delete a
message, a session, or everything.

## A guest with no browser

For a headless machine (an Ubuntu server, say), the guest joins from its
terminal. While a session is waiting, the admin page shows the two commands
under "Guest has no browser?":

```
curl -fo drop http://<host address>/get/linux-$(uname -m) && chmod +x drop   # first time only
./drop join <host address>                                                  # asks for the code
```

The host serves the client itself (Linux, Intel/AMD and ARM 64-bit; no
packages, no root), and the admin page lists the checksums to compare against
`sha256sum drop`. Once joined:

```
./drop join               # live thread: host messages print, typed lines are sent
                          # Ctrl-D detaches; run it again to reattach
some-command | ./drop send
./drop send some text
./drop last > config.yml  # latest host message, exactly as sent
./drop leave              # forget the session on this machine
```

The terminal guest uses the same handshake, encryption and limits as the
browser. It never runs what it receives. In the live thread, control codes are
stripped before printing; `drop last` writes the exact text. The session keys
sit in an owner-only file (`$XDG_RUNTIME_DIR/drop` or the user cache folder)
until the session ends or you run `drop leave`. What was printed stays in the
terminal's scrollback.

## Install

```
make && cp drop /usr/local/bin/
```

`make` builds the Linux terminal clients first and bundles them into `drop`.
A plain `go build` also works, but that host has no clients to serve.

Internet mode needs Tailscale with HTTPS certificates and Funnel enabled for
your tailnet (one time, in the Tailscale admin console). If they are not, the
admin page shows the link Tailscale gives for enabling them.

The host is tested on macOS; it also builds for Linux, where hosting has not
been tested. The terminal guest is tested on Ubuntu 24.04 (ARM 64-bit).

## How it protects what you send

- **Join code.** The code is never sent over the network. Both sides run a
  password-authenticated key exchange (CPace over ristretto255); a wrong guess
  costs one of 5 attempts and teaches the guesser nothing. After 5, the session
  locks until you make a new code on the host.
- **Encryption.** Every message is encrypted (XChaCha20-Poly1305) with keys from
  that exchange, in both modes. On the LAN, where the page is plain HTTP, this
  hides messages from anyone sniffing the network. It does not stop someone who
  can tamper with the network and rewrite the page itself; on a network you
  distrust that much, use internet mode, which adds real HTTPS ending on the host.
- **One guest.** The first browser to join owns the session; no one else can.
- **Inbound text is inert.** It is shown as plain text, capped at 64 KB and
  30 messages a minute, and never copied to the clipboard for you.
- **Nothing left on the guest.** Pages are served `no-store`. The
  thread is held in memory, with the session keys in the tab's sessionStorage
  so a reload works; both are wiped when the session ends or the tab closes.
- **History stays on the host.** Messages are stored as plain text in
  `history.db` (mode 0600) in the user config folder
  (`~/Library/Application Support/drop` on macOS, `~/.config/drop` on Linux)
  until you delete them. Only the admin page, on 127.0.0.1 behind a per-run
  token, can read it; the guest surface has no route to it.

## Layout

| File | What it holds |
| --- | --- |
| `main.go` | CLI, Funnel child process, platform helpers |
| `guestcli.go` | The terminal guest: `join`, `send`, `last`, `leave` |
| `main_guest.go` | Entry point of the slim guest-only client (`-tags guestonly`) |
| `clients.go`, `clients/` | The bundled Linux clients and how they are served |
| `proto.go` | What host and terminal guest share about the protocol |
| `app.go` | The long-lived host process: starts and tears down sessions |
| `session.go` | The live session: join attempts, event log, limits, idle timeout |
| `pake.go` | Key exchange and message encryption (host half) |
| `http.go` | The guest surface and the admin surface |
| `store.go` | SQLite history |
| `web/` | Embedded pages; `vendor.js` is the browser crypto bundle |
| `websrc/` | Source for `vendor.js` |

Rebuild `web/vendor.js` after changing `websrc/crypto-entry.js`:

```
cd websrc && npm install && npx esbuild crypto-entry.js --bundle --minify \
  --format=iife --global-name=DropCrypto --target=es2020 --outfile=../web/vendor.js
```

Tests: `make test`
