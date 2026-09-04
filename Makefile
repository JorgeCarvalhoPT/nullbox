BINARY  := nullbox
PKG     := ./cmd/nullbox
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/JorgeCarvalhoPT/nullbox/internal/buildinfo.Version=$(VERSION)

.PHONY: build install test fmt vet snapshot clean

build: ## build ./nullbox with the version stamped in
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) $(PKG)

install: ## go install into $GOBIN / $GOPATH/bin
	go install -ldflags "$(LDFLAGS)" $(PKG)

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
