// Package buildinfo carries the version stamped into the binary at build time.
package buildinfo

// Version is overridden at build time via:
//
//	-ldflags "-X github.com/JorgeCarvalhoPT/nullbox/internal/buildinfo.Version=<v>"
//
// GoReleaser sets it on release; `make build` sets it from `git describe`; a
// plain `go build` leaves it "dev".
var Version = "dev"
