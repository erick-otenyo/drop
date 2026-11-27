//go:build !guestonly

package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"io"
	"sort"
	"strings"
	"sync"
)

// The terminal-guest clients, built and gzipped by `make` before the host is
// compiled. A host built without them simply has none to offer.
//
//go:embed clients
var clientFS embed.FS

// ClientInfo describes one bundled client, for the admin page.
type ClientInfo struct {
	Platform string `json:"platform"` // e.g. linux-amd64
	SHA256   string `json:"sha256"`
	Size     int    `json:"size"`
}

var (
	clientsOnce sync.Once
	clientBins  = map[string][]byte{}
	clientList  []ClientInfo
)

func loadClients() {
	clientsOnce.Do(func() {
		entries, _ := clientFS.ReadDir("clients")
		for _, e := range entries {
			name := e.Name()
			if !strings.HasPrefix(name, "drop-") || !strings.HasSuffix(name, ".gz") {
				continue
			}
			f, err := clientFS.Open("clients/" + name)
			if err != nil {
				continue
			}
			zr, err := gzip.NewReader(f)
			if err != nil {
				continue
			}
			var buf bytes.Buffer
			if _, err := io.Copy(&buf, zr); err != nil {
				continue
			}
			platform := strings.TrimSuffix(strings.TrimPrefix(name, "drop-"), ".gz")
			sum := sha256.Sum256(buf.Bytes())
			clientBins[platform] = buf.Bytes()
			clientList = append(clientList, ClientInfo{Platform: platform, SHA256: hex.EncodeToString(sum[:]), Size: buf.Len()})
		}
		sort.Slice(clientList, func(i, j int) bool { return clientList[i].Platform < clientList[j].Platform })
	})
}

// bundledClients lists the clients this host can serve.
func bundledClients() []ClientInfo {
	loadClients()
	return clientList
}

// clientBinary returns the client for a platform. It accepts what `uname -m`
// prints, so the download command can be the same on every machine.
func clientBinary(platform string) ([]byte, bool) {
	loadClients()
	platform = strings.NewReplacer("x86_64", "amd64", "aarch64", "arm64").Replace(strings.ToLower(platform))
	b, ok := clientBins[platform]
	return b, ok
}
