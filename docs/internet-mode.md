# Internet mode

Internet mode lets a guest reach a session from anywhere, not just the local
network. It uses [Tailscale Funnel](https://tailscale.com/kb/1223/funnel) to
give the host a public HTTPS address for as long as the session lasts. The
guest needs nothing from Tailscale: only a browser, or the terminal client.

> Internet mode has had much less testing than LAN mode. Starting, cancelling
> and tearing down the Funnel are exercised; a full session through a live
> Funnel should be treated as new ground.

## One-time setup

The host needs the Tailscale app or CLI, signed in to a tailnet. In the
Tailscale admin console:

1. **Enable MagicDNS and HTTPS certificates** (DNS page). Funnel serves on the
   machine's `ts.net` name and needs a certificate for it.
2. **Allow Funnel for the host.** The quickest way is to run `tailscale funnel
   8090` once on the host: if Funnel is not allowed, Tailscale prints a link
   that turns it on. The manual equivalent is a node attribute in the tailnet
   policy file:

   ```json
   "nodeAttrs": [
     { "target": ["autogroup:member"], "attr": ["funnel"] }
   ]
   ```

To check, run `tailscale funnel 8090` on the host. It should print an
`https://<machine>.<tailnet>.ts.net` address. Stop it with Ctrl-C.

## Using it

Start a session with `drop net`, or with **Start internet session** on the
admin page. The page shows the address and the code.

| Guest | What to do |
| --- | --- |
| Browser | Open `https://<machine>.<tailnet>.ts.net` and enter the code |
| Terminal | `./drop join <machine>.<tailnet>.ts.net`, then enter the code |

A terminal guest that does not have the client yet can fetch it over the same
address: `curl -fo drop https://<machine>.<tailnet>.ts.net/get/linux-$(uname -m)`.

The first start on a machine can sit on "Starting internet session…" for up
to a minute while Tailscale issues the certificate.

## How it is wired

```
guest ──HTTPS──▶ Tailscale Funnel relay ──▶ tailscaled on the host ──HTTP──▶ drop
                 (passes encrypted bytes)    (ends TLS)                      127.0.0.1:8090
```

Starting a session in internet mode (`App.bringUp` in `app.go`):

1. `tailscale status --json` is read for the backend state and the machine's
   DNS name. If Tailscale is missing or not connected, the start fails with a
   message on the admin page.
2. The guest listener is bound to **`127.0.0.1:<port>`** (default 8090), not to
   a LAN address. In this mode the session is reachable only through Funnel.
3. `tailscale funnel <port>` is started as a foreground child process
   (`startFunnel` in `main.go`). Foreground means the Funnel exists only while
   that process lives; nothing is written to Tailscale's persistent serve
   configuration.
4. The child's output is read line by line. A line containing
   `https://<dns name>` means the Funnel is up, and the session goes live.
   Any other line is shown on the admin page as a notice, with links made
   clickable. This is how the "Funnel is not enabled" message and its enable
   link reach the user.
5. While waiting, **Cancel** on the admin page stops the child and returns to
   idle. If the child exits by itself, the start fails with an error.

Ending a session, cancelling a start, or quitting drop stops the Funnel:

- The child runs in its own process group, because the `tailscale` command can
  be a shell wrapper around the real binary. The whole group gets `SIGINT`, then
  `SIGKILL` if it has not exited within 3 seconds.
- The guest listener stays up for 1.5 seconds after the session ends, so the
  guest can collect the end event and wipe its page, then closes.

Nothing else differs from LAN mode. The guest page, the terminal client, the
join handshake and the message encryption are the same code.

## What protects the session

- **TLS ends on the host.** Funnel's relay forwards encrypted bytes; the
  certificate's private key stays in `tailscaled` on the host.
- **The join code is never sent.** Host and guest run the same
  password-authenticated key exchange as in LAN mode, inside the TLS
  connection, and every message is encrypted with the keys it produces.
  Tailscale's relay could not read messages even if TLS were stripped.
- **The address is public while the session is live.** Anyone can load the
  join page. They cannot join without the code, 5 wrong codes lock the
  session, and once a guest has joined no one else can.
- **The address names the machine and tailnet.** `<machine>.<tailnet>.ts.net`
  is visible to the guest and, like every public certificate, is recorded in
  certificate transparency logs.
- **The admin page is never exposed.** It listens on a different port, on
  127.0.0.1 only, and is not part of what Funnel forwards.

## Limits and troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| "internet mode needs Tailscale…" | The `tailscale` command is not on the PATH, or Tailscale is not running |
| "Tailscale is not connected" | Run `tailscale up` |
| Notice saying Funnel is not enabled | Follow the link in the notice, then start again |
| "Tailscale Funnel did not start" | HTTPS certificates or the Funnel attribute are missing; redo the one-time setup |
| "port 8090 is taken" | Something else is using the guest port; restart drop with `--port` |
| Stuck on "Starting…" | Certificate still being issued, or Tailscale is waiting for Funnel to be enabled; check for a notice, or Cancel |

- Funnel serves the session on public port 443. Tailscale applies its own
  bandwidth limits to Funnel traffic, which do not matter for text.
- If drop is killed outright (`kill -9`), it cannot stop the child, and a
  `tailscale funnel` process may be left running. Stop it with
  `tailscale funnel reset`, or end the process.
- An existing Tailscale serve or Funnel configuration on the host's port 443
  may conflict with the one drop starts.
