package driver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"
)

// Firecracker microVM addressing. The guest sits on a private /30 with the host
// TAP as its gateway, so guest egress arrives on the host TAP and is routed
// (and, per the compiled forward chain, filtered + masqueraded) by the host.
const (
	fcHostTapIP = "172.16.0.1"
	fcGuestIP   = "172.16.0.2"
	fcNetmask   = "255.255.255.252"
	fcTapCIDR   = "172.16.0.1/30"
	fcGuestMAC  = "06:00:AC:10:00:02"
)

// Config is everything the Firecracker booter needs. Built from env + defaults
// on the Linux host; the pure builders/tests construct it directly.
type Config struct {
	FirecrackerBin  string
	KernelImagePath string // uncompressed vmlinux (ELF)
	RootfsPath      string // bootable ext4
	VCPUs           int
	MemMiB          int
	RunDir          string // per-engagement sockets/logs
	GuestIP         string
	HostTapIP       string
	Netmask         string
	GuestMAC        string
	UplinkIface     string // masquerade output iface (empty => any non-tap)
	ResolverIP      string // optional: restrict guest DNS to this resolver
	VsockUDS        string // optional control channel
}

func (c Config) firecrackerBin() string {
	if c.FirecrackerBin != "" {
		return c.FirecrackerBin
	}
	return "firecracker"
}

// --- request bodies (exact Firecracker API field names) ---

type machineConfigBody struct {
	VCPUCount  int  `json:"vcpu_count"`
	MemSizeMiB int  `json:"mem_size_mib"`
	SMT        bool `json:"smt"`
}

type bootSourceBody struct {
	KernelImagePath string `json:"kernel_image_path"`
	BootArgs        string `json:"boot_args"`
}

type driveBody struct {
	DriveID      string `json:"drive_id"`
	PathOnHost   string `json:"path_on_host"`
	IsRootDevice bool   `json:"is_root_device"`
	IsReadOnly   bool   `json:"is_read_only"`
}

type netIfaceBody struct {
	IfaceID     string `json:"iface_id"`
	HostDevName string `json:"host_dev_name"`
	GuestMAC    string `json:"guest_mac,omitempty"`
}

type vsockBody struct {
	GuestCID int    `json:"guest_cid"`
	UDSPath  string `json:"uds_path"`
}

type actionBody struct {
	ActionType string `json:"action_type"`
}

// buildBootArgs composes the kernel command line. The ip= field sets the guest's
// static address and default gateway (= the host TAP IP), which is how guest
// egress reaches the host to be filtered.
//
//	ip=<client-ip>::<gw-ip>:<netmask>:<hostname>:<device>:<autoconf>
func buildBootArgs(c Config) string {
	return fmt.Sprintf("console=ttyS0 reboot=k panic=1 pci=off ip=%s::%s:%s::eth0:off",
		c.GuestIP, c.HostTapIP, c.Netmask)
}

// fcAPI drives the Firecracker configuration API over its unix socket.
type fcAPI struct {
	c    *http.Client
	sock string
}

func newFCAPI(sock string) *fcAPI {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		},
	}
	return &fcAPI{c: &http.Client{Transport: tr, Timeout: 5 * time.Second}, sock: sock}
}

// put issues a PUT with a JSON body. Firecracker replies 204 on success and 400
// with {"fault_message": ...} on error.
func (a *fcAPI) put(path string, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPut, "http://localhost"+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := a.c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil
	}
	var f struct {
		FaultMessage string `json:"fault_message"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&f)
	return fmt.Errorf("firecracker PUT %s: %d %s", path, resp.StatusCode, f.FaultMessage)
}

// configure runs the full pre-boot API sequence, in order, against the socket.
func (a *fcAPI) configure(cfg Config, tap string) error {
	mac := cfg.GuestMAC
	if mac == "" {
		mac = fcGuestMAC
	}
	if err := a.put("/machine-config", machineConfigBody{VCPUCount: cfg.VCPUs, MemSizeMiB: cfg.MemMiB, SMT: false}); err != nil {
		return err
	}
	if err := a.put("/boot-source", bootSourceBody{KernelImagePath: cfg.KernelImagePath, BootArgs: buildBootArgs(cfg)}); err != nil {
		return err
	}
	if err := a.put("/drives/rootfs", driveBody{DriveID: "rootfs", PathOnHost: cfg.RootfsPath, IsRootDevice: true, IsReadOnly: false}); err != nil {
		return err
	}
	if err := a.put("/network-interfaces/eth0", netIfaceBody{IfaceID: "eth0", HostDevName: tap, GuestMAC: mac}); err != nil {
		return err
	}
	if cfg.VsockUDS != "" {
		if err := a.put("/vsock", vsockBody{GuestCID: 3, UDSPath: cfg.VsockUDS}); err != nil {
			return err
		}
	}
	return nil
}

// start issues InstanceStart — always last.
func (a *fcAPI) start() error {
	return a.put("/actions", actionBody{ActionType: "InstanceStart"})
}
