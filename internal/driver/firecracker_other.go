//go:build !linux

package driver

import "github.com/JorgeCarvalhoPT/nullbox/internal/model"

// On non-Linux hosts the firecracker driver is a stub: it can be named and
// Preflight explains the requirement, but it cannot run (Firecracker needs
// Linux + KVM). The real driver is firecracker_linux.go.
func init() {
	register(&stubDriver{
		name:  model.DriverFirecracker,
		needs: "a Linux host with KVM (/dev/kvm), nftables and Firecracker — you are not on Linux",
	})
}
