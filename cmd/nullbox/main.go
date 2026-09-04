// Command nullbox provisions pentest sandboxes for AI agents from an Engagement
// manifest ("scope as code"). See the package READMEs for the architecture.
//
// Phase 0 commands that work anywhere, no host VMM required:
//
//	nullbox validate <manifest>   parse + validate, print a summary
//	nullbox render   <manifest>   compile the manifest to its nftables egress policy
//
// Commands that dispatch to a VMM driver (need a host with the backend):
//
//	nullbox up    <manifest>      provision + start the engagement sandbox
//	nullbox shell <manifest>      attach an interactive shell in the sandbox
//	nullbox kill  <manifest>      flush the egress policy immediately (panic button)
//	nullbox down  <manifest>      stop + remove the sandbox
//	nullbox list                  show known engagements
package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/JorgeCarvalhoPT/nullbox/internal/buildinfo"
	"github.com/JorgeCarvalhoPT/nullbox/internal/console"
	"github.com/JorgeCarvalhoPT/nullbox/internal/driver"
	"github.com/JorgeCarvalhoPT/nullbox/internal/manifest"
	"github.com/JorgeCarvalhoPT/nullbox/internal/model"
	"github.com/JorgeCarvalhoPT/nullbox/internal/nflog"
	"github.com/JorgeCarvalhoPT/nullbox/internal/policy"
	"github.com/JorgeCarvalhoPT/nullbox/internal/store"
	"github.com/JorgeCarvalhoPT/nullbox/internal/template"
	"github.com/JorgeCarvalhoPT/nullbox/internal/tui"
	"gopkg.in/yaml.v3"
)

const usage = `nullbox — a sandbox for AI pentesting agents (scope as code)

usage: nullbox [command] [args]
       nullbox                 launch the in-terminal interface (TUI)

  tui                   launch the in-terminal interface explicitly
  validate <manifest>   parse + validate a manifest, print a summary
  render   <manifest>   compile a manifest to its nftables egress policy (stdout)
  up       <manifest>   provision + start the engagement sandbox (records it)
  shell    <name>       attach an interactive shell in the sandbox
  kill     <name>       flush the egress policy immediately (panic button)
  down     <name>       stop + remove the sandbox
  list                  show known engagements
  console  [--addr]     serve the web console (default 127.0.0.1:7788)
  template <sub>        config presets: list | show <name> | save <name> <manifest>
  version               print the version
`

func main() {
	if len(os.Args) < 2 {
		// Bare `nullbox` launches the in-terminal interface.
		if err := tui.Run(); err != nil {
			fmt.Fprintln(os.Stderr, "nullbox: "+err.Error())
			os.Exit(1)
		}
		return
	}
	var err error
	switch os.Args[1] {
	case "tui":
		err = tui.Run()
	case "validate":
		err = cmdValidate(os.Args[2:])
	case "render":
		err = cmdRender(os.Args[2:])
	case "up":
		err = cmdUp(os.Args[2:])
	case "shell":
		err = cmdLifecycle("shell", os.Args[2:])
	case "kill":
		err = cmdLifecycle("kill", os.Args[2:])
	case "down":
		err = cmdLifecycle("down", os.Args[2:])
	case "list":
		err = cmdList(os.Args[2:])
	case "console":
		err = cmdConsole(os.Args[2:])
	case "template":
		err = cmdTemplate(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Println("nullbox " + buildinfo.Version)
		return
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	default:
		err = fmt.Errorf("unknown command %q (try `nullbox help`)", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "nullbox: "+err.Error())
		os.Exit(1)
	}
}

func requireManifestArg(args []string) (string, error) {
	if len(args) < 1 {
		return "", fmt.Errorf("missing <manifest> path")
	}
	return args[0], nil
}

func cmdValidate(args []string) error {
	path, err := requireManifestArg(args)
	if err != nil {
		return err
	}
	e, err := manifest.Load(path)
	if err != nil {
		return err
	}
	d, derr := driver.Select(e)
	drvName := "unresolved"
	if derr == nil {
		drvName = string(d.Name())
	}
	fmt.Printf("OK  %s\n", path)
	fmt.Printf("  engagement : %s (client: %s)\n", e.Metadata.Name, e.Metadata.Client)
	fmt.Printf("  authorization: %s\n", e.Metadata.Authorization.Ref)
	fmt.Printf("  window ends : %s\n", e.Spec.Window.End)
	fmt.Printf("  profile     : %s   driver: %s\n", e.Spec.Network.Profile, drvName)
	fmt.Printf("  image       : %s\n", imageRef(e))
	fmt.Printf("  scope       : %d allow, %d deny  (metadata denied: %v)\n",
		len(e.Spec.Scope.Allow), len(e.Spec.Scope.Deny), e.Spec.Network.DenyMetadataEnabled())
	return nil
}

func cmdRender(args []string) error {
	path, err := requireManifestArg(args)
	if err != nil {
		return err
	}
	e, err := manifest.Load(path)
	if err != nil {
		return err
	}
	rs, err := policy.Compile(e)
	if err != nil {
		return err
	}
	fmt.Print(rs.NFT)
	if len(rs.UnresolvedHosts) > 0 {
		fmt.Fprintf(os.Stderr, "\n# note: %d host target(s) need DNS resolution at apply time (phase 1):\n", len(rs.UnresolvedHosts))
		for _, h := range rs.UnresolvedHosts {
			fmt.Fprintf(os.Stderr, "#   %s ports=%v\n", h.Host, h.Ports)
		}
	}
	return nil
}

func cmdUp(args []string) error {
	fs := flag.NewFlagSet("up", flag.ContinueOnError)
	workspace := fs.String("workspace", "", "host path to mount read-only as the target codebase (overrides manifest)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	path, err := requireManifestArg(fs.Args())
	if err != nil {
		return err
	}
	e, err := manifest.Load(path)
	if err != nil {
		return err
	}
	rs, err := policy.Compile(e)
	if err != nil {
		return err
	}
	d, err := driver.Select(e)
	if err != nil {
		return err
	}
	if err := d.Preflight(e.Spec.Network.Profile); err != nil {
		return err
	}
	ws := e.Spec.Workspace
	if *workspace != "" {
		ws = *workspace
	}
	st, err := d.Up(driver.UpSpec{Engagement: e, Ruleset: rs, ImageRef: imageRef(e), Workspace: ws})
	if err != nil {
		return err
	}
	abs, _ := filepath.Abs(path)
	rec := store.Record{
		Name:         e.Metadata.Name,
		Client:       e.Metadata.Client,
		Driver:       string(d.Name()),
		Profile:      string(e.Spec.Network.Profile),
		ImageRef:     imageRef(e),
		Workspace:    ws,
		ManifestPath: abs,
		AuthRef:      e.Metadata.Authorization.Ref,
		WindowEnd:    e.Spec.Window.End,
		CreatedAt:    time.Now(),
		State:        st.State,
		MCPPort:      st.MCPPort,
		Scope:        scopeEntries(e),
	}
	if err := store.Save(rec); err != nil {
		return fmt.Errorf("engagement started but recording it failed: %w", err)
	}
	fmt.Printf("engagement %q up via %s (state: %s)\n", st.Name, st.Driver, st.State)
	return nil
}

func cmdLifecycle(op string, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("missing <engagement-name> (see `nullbox list`)")
	}
	name := args[0]
	rec, err := store.Load(name)
	if err != nil {
		return err
	}
	d, err := driver.Get(model.Driver(rec.Driver))
	if err != nil {
		return err
	}
	switch op {
	case "shell":
		return d.Shell(name)
	case "kill":
		if err := d.Kill(name); err != nil {
			return err
		}
		fmt.Printf("engagement %q egress flushed\n", name)
		return nil
	case "down":
		if err := d.Down(name); err != nil {
			return err
		}
		if err := store.Delete(name); err != nil {
			return err
		}
		fmt.Printf("engagement %q down\n", name)
		return nil
	}
	return fmt.Errorf("unknown lifecycle op %q", op)
}

func cmdList(_ []string) error {
	recs, err := store.List()
	if err != nil {
		return err
	}
	if len(recs) == 0 {
		fmt.Println("no engagements (start one with `nullbox up <manifest>`)")
		return nil
	}
	fmt.Printf("%-22s %-12s %-8s %-9s %s\n", "NAME", "DRIVER", "PROFILE", "STATE", "WINDOW-END")
	for _, r := range recs {
		fmt.Printf("%-22s %-12s %-8s %-9s %s\n", r.Name, r.Driver, r.Profile, r.State, r.WindowEnd)
	}
	return nil
}

// imageRef resolves the guest OCI image — ANY AI pentesting agent. If the
// manifest names one (spec.image), it wins; nullbox does not care which agent
// runs inside. Otherwise a built-in default guest is chosen by infraTools: the
// full variant carries the Kali infra domain (masscan, netexec, responder…) for
// routed/l2, thin is web + codebase only.
func imageRef(e *model.Engagement) string {
	if e.Spec.Image != "" {
		return e.Spec.Image
	}
	if e.Spec.Capabilities.InfraTools {
		return "nullbox/guest:full"
	}
	return "nullbox/guest:thin"
}

// scopeEntries renders the manifest's allow/deny targets for display in the
// console, so the operator sees the authorized surface without the manifest.
func scopeEntries(e *model.Engagement) []store.ScopeEntry {
	var out []store.ScopeEntry
	add := func(ts []model.Target, kind string) {
		for _, t := range ts {
			out = append(out, store.ScopeEntry{Target: targetStr(t), Kind: kind})
		}
	}
	add(e.Spec.Scope.Allow, "allow")
	add(e.Spec.Scope.Deny, "deny")
	return out
}

func targetStr(t model.Target) string {
	base := t.CIDR
	if base == "" {
		base = t.Host
	}
	if len(t.Ports) > 0 {
		parts := make([]string, len(t.Ports))
		for i, p := range t.Ports {
			parts[i] = strconv.Itoa(p)
		}
		base += ":" + strings.Join(parts, ",")
	}
	return base
}

func cmdConsole(args []string) error {
	fs := flag.NewFlagSet("console", flag.ContinueOnError)
	addr := fs.String("addr", "127.0.0.1:7788", "listen address (loopback by default)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	// Live nftables egress feed (Linux + CAP_NET_ADMIN). Off Linux, or without
	// the capability, degrade to state-only and let the UI simulate.
	var feed console.Feed
	if r, err := nflog.NewFeed(runningEngagementName(), uint16(policy.NFLOGGroupAccept), uint16(policy.NFLOGGroupDrop)); err == nil {
		feed = r
		defer r.Close()
		fmt.Println("nullbox console: live egress feed active")
	} else {
		fmt.Fprintf(os.Stderr, "nullbox console: live egress feed unavailable (%v); serving state only\n", err)
	}
	srv := console.New(feed)
	fmt.Printf("nullbox console → http://%s\n", *addr)
	return http.ListenAndServe(*addr, srv.Handler())
}

func cmdTemplate(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: nullbox template <list|show|save> ...")
	}
	switch args[0] {
	case "list":
		names, err := template.List()
		if err != nil {
			return err
		}
		if len(names) == 0 {
			fmt.Println("no templates (create one with `nullbox template save <name> <manifest>`)")
			return nil
		}
		for _, n := range names {
			fmt.Println(n)
		}
		return nil
	case "show":
		if len(args) < 2 {
			return fmt.Errorf("usage: nullbox template show <name>")
		}
		t, err := template.Load(args[1])
		if err != nil {
			return err
		}
		b, err := yaml.Marshal(t)
		if err != nil {
			return err
		}
		fmt.Print(string(b))
		return nil
	case "save":
		if len(args) < 3 {
			return fmt.Errorf("usage: nullbox template save <name> <manifest>")
		}
		e, err := manifest.Load(args[2])
		if err != nil {
			return err
		}
		if err := template.Save(template.FromSpec(args[1], e.Spec)); err != nil {
			return err
		}
		fmt.Printf("saved template %q (from %s)\n", args[1], args[2])
		return nil
	default:
		return fmt.Errorf("unknown template subcommand %q (list|show|save)", args[0])
	}
}

// runningEngagementName returns the name events are stamped with — the single
// running engagement (the fixed nft table means one per host in phase 1).
func runningEngagementName() string {
	recs, err := store.List()
	if err != nil {
		return ""
	}
	for _, r := range recs {
		if r.State == "running" {
			return r.Name
		}
	}
	return ""
}
