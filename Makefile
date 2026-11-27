# `make` builds the terminal-guest clients, then the host with them bundled.
CLIENT_FLAGS = -tags guestonly -trimpath -ldflags "-s -w"

drop: clients $(wildcard *.go) $(wildcard web/*)
	go build -o drop .

clients: clients/drop-linux-amd64.gz clients/drop-linux-arm64.gz

clients/drop-linux-%.gz: guestcli.go main_guest.go pake.go proto.go go.mod
	CGO_ENABLED=0 GOOS=linux GOARCH=$* go build $(CLIENT_FLAGS) -o clients/drop-linux-$* .
	gzip -9 -f clients/drop-linux-$*

test:
	go test ./...

.PHONY: clients test
