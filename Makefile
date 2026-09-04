BINARY  := nullbox
PKG     := ./cmd/nullbox
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/JorgeCarvalhoPT/nullbox/internal/buildinfo.Version=$(VERSION)

.PHONY: build install uninstall test fmt vet snapshot clean

build: ## build ./nullbox with the version stamped in
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) $(PKG)

install: ## go install into $GOBIN / $GOPATH/bin
	go install -ldflags "$(LDFLAGS)" $(PKG)

uninstall: ## remove the go-installed binary (state kept; use ./uninstall.sh --purge to wipe it)
	rm -f "$$(go env GOBIN)/$(BINARY)" "$$(go env GOPATH)/bin/$(BINARY)"

test: ## run the full test suite
	go test ./...

fmt: ## gofmt the tree
	gofmt -w .

vet: ## go vet
	go vet ./...

snapshot: ## local GoReleaser build (no publish); needs goreleaser installed
	goreleaser release --snapshot --clean

clean:
	rm -f $(BINARY)
	rm -rf dist
