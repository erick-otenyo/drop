//go:build !guestonly

// drop shares text between this computer (the host) and one other computer's
// browser (the guest), over the LAN or over the internet through Tailscale
// Funnel.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	qrcode "github.com/skip2/go-qrcode"
)

const usage = `drop - share text with the computer in front of you

  drop            open the admin page: start sessions, browse history
  drop lan        open it with a session started on the local network
  drop net        open it with a session started over the internet
                  (Tailscale Funnel)

  pbpaste | drop lan    start with piped text as the first message

  drop join <address>   join someone else's session from this terminal
                        (see "drop help" for send, last and leave)

Flags:
  --port N         port the guest connects to (default 8090)
  --admin-port N   port for the admin page on this computer (default 8091)
  --no-open        do not open the admin page in a browser
`

func main() {
	args := os.Args[1:]
	mode := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		switch args[0] {
		case "lan", "net":
			mode = args[0]
		case "history": // kept as an alias for plain `drop`
		case "join", "send", "last", "leave":
			if err := runGuestCommand(args[0], args[1:]); err != nil {
				fmt.Fprintln(os.Stderr, "drop:", err)
				os.Exit(1)
			}
			return
		case "help":
			fmt.Print(usage + "\n" + guestUsage)
			return
		default:
			fmt.Fprint(os.Stderr, usage)
			os.Exit(2)
		}
		args = args[1:]
	}
	if err := run(mode, args); err != nil {
		fmt.Fprintln(os.Stderr, "drop:", err)
		os.Exit(1)
	}
}

type runInfo struct {
	URL string `json:"url"`
	PID int    `json:"pid"`
}

func newServer(h http.Handler) *http.Server {
	return &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute}
}

func run(mode string, args []string) error {
	fs := flag.NewFlagSet("drop", flag.ExitOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	port := fs.Int("port", 8090, "")
	adminPort := fs.Int("admin-port", 8091, "")
	noOpen := fs.Bool("no-open", false, "")
	fs.Parse(args)

	dir, err := dataDir()
	if err != nil {
		return err
	}
	runFile := filepath.Join(dir, "run.json")
	adminHost := fmt.Sprintf("127.0.0.1:%d", *adminPort)
	ln, err := net.Listen("tcp", adminHost)
	if err != nil {
		// Most likely drop is already running: send the user to its page.
		var info runInfo
		if b, rerr := os.ReadFile(runFile); rerr == nil && json.Unmarshal(b, &info) == nil && info.URL != "" {
			fmt.Println("drop is already running. Its admin page:", info.URL)
			if !*noOpen {
				openBrowser(info.URL)
			}
			return nil
		}
		return fmt.Errorf("port %d is taken; pass --admin-port to use another", *adminPort)
	}
	defer ln.Close()

	store, err := openStore(dir)
	if err != nil {
		return err
	}
	defer store.Close()

	app := newApp(store, adminHost, *port)
	app.onLive = announce
	srv := newServer(app.adminHandler())
	go srv.Serve(ln)

	adminURL := fmt.Sprintf("http://%s/?t=%s", adminHost, app.adminToken)
	if b, err := json.Marshal(runInfo{URL: adminURL, PID: os.Getpid()}); err == nil {
		os.WriteFile(runFile, b, 0o600)
		defer os.Remove(runFile)
	}
	fmt.Println("Admin page:", adminURL)
	fmt.Println("Ctrl-C quits drop.")
	if !*noOpen {
		openBrowser(adminURL)
	}
	if mode != "" {
		if err := app.Start(mode, readPipedStdin()); err != nil {
			return err
		}
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	select {
	case <-sig:
	case <-app.quit:
	}
	fmt.Println("\nQuitting.")
	app.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	srv.Shutdown(ctx)
	return nil
}

// announce prints what the guest needs, for people driving drop from the
// terminal rather than the admin page.
func announce(s State) {
	addr := strings.TrimPrefix(strings.TrimPrefix(s.URL, "https://"), "http://")
	fmt.Printf("\n  On the other computer, open:   %s\n", addr)
	fmt.Printf("  Then enter the code:           %s-%s\n\n", s.Code[:3], s.Code[3:])
	if qr, err := qrcode.New(s.URL+"/#"+s.Code, qrcode.Low); err == nil {
		fmt.Print(qr.ToSmallString(false))
	}
}

// readPipedStdin returns what was piped in, or "" when stdin is a terminal or
// empty. Piping is how a session is started with its first message.
func readPipedStdin() string {
	fi, err := os.Stdin.Stat()
	if err != nil || fi.Mode()&os.ModeCharDevice != 0 {
		return ""
	}
	if fi.Mode()&os.ModeNamedPipe == 0 && !fi.Mode().IsRegular() {
		return ""
	}
	b, err := io.ReadAll(io.LimitReader(os.Stdin, maxOutboundBytes))
	if err != nil || strings.TrimSpace(string(b)) == "" {
		return ""
	}
	return strings.TrimRight(string(b), "\n")
}

// lanIP picks the address other machines on the local network can reach:
// a private IPv4 address on a real (not tunnel, not loopback) interface.
func lanIP() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&(net.FlagLoopback|net.FlagPointToPoint) != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if ip := ipn.IP.To4(); ip != nil && ip.IsPrivate() {
				return ip.String(), nil
			}
		}
	}
	return "", errors.New("no local network address found; is this computer connected to a network?")
}

func tailscaleDNSName() (string, error) {
	out, err := exec.Command("tailscale", "status", "--json").Output()
	if err != nil {
		return "", errors.New("internet mode needs Tailscale, and the tailscale command is not available or not running")
	}
	var st struct {
		BackendState string
		Self         struct{ DNSName string }
	}
	if err := json.Unmarshal(out, &st); err != nil {
		return "", err
	}
	name := strings.TrimSuffix(st.Self.DNSName, ".")
	if st.BackendState != "Running" || name == "" {
		return "", errors.New("Tailscale is not connected; run `tailscale up` first")
	}
	return name, nil
}

// startFunnel runs `tailscale funnel <port>` in the foreground as a child, so
// the Funnel disappears with the session. It returns once Tailscale reports
// the public address, passing anything Tailscale says in the meantime to logf
// (such as the link for enabling Funnel on the tailnet).
func startFunnel(port int, dnsName string, cancel <-chan struct{}, logf func(string)) (stop func(), err error) {
	cmd := exec.Command("tailscale", "funnel", fmt.Sprint(port))
	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = pw, pw
	// Own process group: the tailscale command can be a shell wrapper, so
	// signals must reach the real binary underneath it as well.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("could not start tailscale funnel: %w", err)
	}
	exited := make(chan struct{})
	go func() { cmd.Wait(); pw.Close(); close(exited) }()
	stop = func() {
		syscall.Kill(-cmd.Process.Pid, syscall.SIGINT)
		select {
		case <-exited:
		case <-time.After(3 * time.Second):
			syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
	}
	ready := make(chan struct{})
	go func() {
		isReady := false
		sc := bufio.NewScanner(pr)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if isReady {
				continue
			}
			if strings.Contains(line, "https://"+dnsName) {
				isReady = true
				close(ready)
			} else if line != "" {
				logf(line)
			}
		}
	}()
	select {
	case <-ready:
		return stop, nil
	case <-exited:
		return nil, errors.New("Tailscale Funnel did not start. Funnel and HTTPS certificates must be enabled for your tailnet")
	case <-cancel:
		stop()
		return nil, errCancelled
	}
}

// notifyInbound tells the user a message arrived. It deliberately says nothing
// about the content, which may be sensitive.
func notifyInbound() {
	const text = "New message from the guest"
	switch runtime.GOOS {
	case "darwin":
		exec.Command("osascript", "-e", `display notification "`+text+`" with title "drop"`).Run()
	case "linux":
		exec.Command("notify-send", "drop", text).Run()
	}
}

func openBrowser(url string) {
	switch runtime.GOOS {
	case "darwin":
		exec.Command("open", url).Start()
	case "linux":
		exec.Command("xdg-open", url).Start()
	}
}
