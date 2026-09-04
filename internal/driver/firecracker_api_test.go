package driver

import (
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// fakeFirecracker serves the API over a unix socket, recording requests.
type fakeFirecracker struct {
	mu     sync.Mutex
	seq    []string
	bodies []string
	status int
	fault  string
	srv    *http.Server
}

func startFakeFC(t *testing.T) (*fakeFirecracker, string) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "fc.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeFirecracker{status: http.StatusNoContent}
	f.srv = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.seq = append(f.seq, r.Method+" "+r.URL.Path)
		f.bodies = append(f.bodies, string(b))
		st, fault := f.status, f.fault
		f.mu.Unlock()
		if st != http.StatusNoContent {
			w.WriteHeader(st)
			_, _ = w.Write([]byte(`{"fault_message":"` + fault + `"}`))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})}
	go f.srv.Serve(ln)
	t.Cleanup(func() { _ = f.srv.Close() })
	return f, sock
}

func TestFCAPIConfigureSequence(t *testing.T) {
	f, sock := startFakeFC(t)
	a := newFCAPI(sock)
	cfg := Config{
		VCPUs: 2, MemMiB: 1024,
		KernelImagePath: "/opt/nullbox/vmlinux", RootfsPath: "/opt/nullbox/rootfs.ext4",
		GuestIP: fcGuestIP, HostTapIP: fcHostTapIP, Netmask: fcNetmask,
	}
	if err := a.configure(cfg, "nbx-acme"); err != nil {
		t.Fatal(err)
	}
	if err := a.start(); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"PUT /machine-config", "PUT /boot-source", "PUT /drives/rootfs",
		"PUT /network-interfaces/eth0", "PUT /actions",
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if strings.Join(f.seq, ",") != strings.Join(want, ",") {
		t.Fatalf("api sequence = %v, want %v", f.seq, want)
	}
	if !strings.Contains(f.bodies[0], `"vcpu_count":2`) || !strings.Contains(f.bodies[0], `"mem_size_mib":1024`) {
		t.Errorf("machine-config body wrong: %s", f.bodies[0])
	}
	if !strings.Contains(f.bodies[1], "ip=172.16.0.2::172.16.0.1:255.255.255.252::eth0:off") {
		t.Errorf("boot-source ip= wrong: %s", f.bodies[1])
	}
	if !strings.Contains(f.bodies[3], `"host_dev_name":"nbx-acme"`) {
		t.Errorf("net iface host_dev_name wrong: %s", f.bodies[3])
	}
	if !strings.Contains(f.bodies[4], `"action_type":"InstanceStart"`) {
		t.Errorf("action body wrong: %s", f.bodies[4])
	}
}

func TestFCAPIFaultSurfaces(t *testing.T) {
	f, sock := startFakeFC(t)
	f.mu.Lock()
	f.status = http.StatusBadRequest
	f.fault = "bad kernel"
	f.mu.Unlock()
	a := newFCAPI(sock)
	err := a.put("/boot-source", bootSourceBody{KernelImagePath: "/nope"})
	if err == nil || !strings.Contains(err.Error(), "bad kernel") {
		t.Errorf("expected fault message surfaced, got %v", err)
	}
}

func TestBuildBootArgs(t *testing.T) {
	got := buildBootArgs(Config{GuestIP: fcGuestIP, HostTapIP: fcHostTapIP, Netmask: fcNetmask})
	want := "console=ttyS0 reboot=k panic=1 pci=off ip=172.16.0.2::172.16.0.1:255.255.255.252::eth0:off"
	if got != want {
		t.Errorf("buildBootArgs = %q, want %q", got, want)
	}
}
