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
	"time"

	"github.com/JorgeCarvalhoPT/nullbox/internal/buildinfo"
	"github.com/JorgeCarvalhoPT/nullbox/internal/console"
	"github.com/JorgeCarvalhoPT/nullbox/internal/driver"
	"github.com/JorgeCarvalhoPT/nullbox/internal/engage"
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
  run      [flags]      create + boot a sandbox in one line: --name --auth --allow …
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
	case "run":
		err = cmdRun(os.Args[2:])
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
	fmt.Printf("  image       : %s\n", engage.ImageRef(e))
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
	ws := e.Spec.Workspace
	if *workspace != "" {
		ws = *workspace
	}
	abs, _ := filepath.Abs(path)
	st, _, err := engage.Up(e, ws, abs)
	if err != nil {
		return err
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

// cmdRun is the one-liner: build an engagement from flags, optionally inherit a
// template, validate, optionally write a manifest, and boot it — the imperative
// twin of `nullbox up <manifest>` for when you don't want to hand-write YAML.
//
//	nullbox run --name acme --auth SOW-2026-0142 --allow "10.10.0.0/16 app.example.com:443"
func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	name := fs.String("name", "", "engagement name, a DNS label (required)")
	auth := fs.String("auth", "", "authorization reference, e.g. SOW-2026-0142 (required)")
	allow := fs.String("allow", "", "in-scope targets, space-separated: CIDR|host[:port,port] (required)")
	deny := fs.String("deny", "", "out-of-scope carve-outs, space-separated")
	image := fs.String("image", "", "guest OCI image — any AI pentesting agent (default: built-in guest)")
	tmpl := fs.String("template", "", "config preset to inherit (see `nullbox template list`)")
	drv := fs.String("driver", "", "krun|firecracker|clh|kata (default: auto-select for this host)")
	profile := fs.String("profile", "nat", "network profile: nat|routed|l2")
	client := fs.String("client", "", "client label, for the record")
	days := fs.Int("days", 14, "engagement window length in days (from now)")
	until := fs.String("until", "", "window end as RFC3339 (overrides --days)")
	infra := fs.Bool("infra", false, "request the full (infra tools) guest variant")
	workspace := fs.String("workspace", "", "host path mounted read-only as the target codebase")
	save := fs.Bool("save", false, "also write a reusable manifest to ./<name>.yaml")
	noBoot := fs.Bool("no-boot", false, "write the manifest but do not boot (implies --save)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" || *auth == "" || *allow == "" {
		return fmt.Errorf("run needs --name, --auth, and --allow (try `nullbox run --help`)")
	}
	allowT, err := engage.ParseTargets(*allow)
	if err != nil {
		return err
	}
	denyT, err := engage.ParseTargets(*deny)
	if err != nil {
		return err
	}
	end := *until
	if end == "" {
		end = time.Now().Add(time.Duration(*days) * 24 * time.Hour).UTC().Format(time.RFC3339)
	}
	e := &model.Engagement{
		APIVersion: "nullbox/v1", Kind: "Engagement",
		Metadata: model.Metadata{
			Name:          *name,
			Client:        *client,
			Authorization: model.Authorization{Ref: *auth},
		},
		Spec: model.Spec{
			Template:     *tmpl,
			Driver:       model.Driver(*drv),
			Image:        *image,
			Window:       model.Window{End: end},
			Network:      model.Network{Profile: model.Profile(*profile)},
			Capabilities: model.Capabilities{InfraTools: *infra},
			Workspace:    *workspace,
			Scope:        model.Scope{Allow: allowT, Deny: denyT},
		},
	}
	if e.Spec.Template != "" {
		t, err := template.Load(e.Spec.Template)
		if err != nil {
			return err
		}
		t.ApplyTo(&e.Spec)
	}
	if err := e.Validate(); err != nil {
		return err
	}
	manifestPath := ""
	if *save || *noBoot {
		p, err := engage.WriteManifest(e, "", true)
		if err != nil {
			return err
		}
		manifestPath = p
		fmt.Printf("wrote %s\n", p)
	}
	if *noBoot {
		fmt.Printf("engagement %q ready (not booted — run `nullbox up %s` when ready)\n", e.Metadata.Name, manifestPath)
		return nil
	}
	st, _, err := engage.Up(e, e.Spec.Workspace, manifestPath)
	if err != nil {
		return err
	}
	fmt.Printf("engagement %q up via %s (state: %s)\n", st.Name, st.Driver, st.State)
	fmt.Printf("  attach a shell:  nullbox shell %s\n", st.Name)
	return nil
}
