# nullbox

A sandbox for AI pentesting agents. It runs an agent inside a microVM and
**enforces engagement scope as a packet filter**, so the full network toolchain
— raw sockets, UDP, ICMP, L2 — keeps working while every destination stays
deny-by-default and explicitly authorized.

## Install

A Homebrew tap (available once the first release is published):

```bash
brew install JorgeCarvalhoPT/tap/nullbox
```

Or a one-line script:

```bash
curl -fsSL https://raw.githubusercontent.com/JorgeCarvalhoPT/nullbox/main/install.sh | sh
```

Or with Go (works today, no release needed):

```bash
go install github.com/JorgeCarvalhoPT/nullbox/cmd/nullbox@latest
```

From source:

```bash
git clone https://github.com/JorgeCarvalhoPT/nullbox && cd nullbox && make install
```

Then run **`nullbox`** to launch the terminal UI. (`nullbox version` prints the build.)

### Uninstall

```bash
curl -fsSL https://raw.githubusercontent.com/JorgeCarvalhoPT/nullbox/main/uninstall.sh | sh
```

This removes the binary but **keeps your engagement records and evidence** —
for a pentest, that in-scope proof is worth holding on to. Add `--purge` to
also delete the state directory (`<config>/nullbox`):

```bash
curl -fsSL https://raw.githubusercontent.com/JorgeCarvalhoPT/nullbox/main/uninstall.sh | sh -s -- --purge --yes
```

If you installed with Homebrew, use `brew uninstall --cask nullbox` instead; with
Go, `make uninstall`. Stop any running sandboxes (`nullbox down <name>`) first —
uninstalling doesn't tear down live microVMs.

> Releases: `git tag vX.Y.Z && git push --tags` runs the GoReleaser workflow,
> which builds the binaries and updates the Homebrew tap. First-time setup:
> create a `JorgeCarvalhoPT/homebrew-tap` repo and add a `HOMEBREW_TAP_TOKEN`
> secret (a PAT with `repo` scope on that tap).

## How it works

Scope is enforced at a **stateful packet filter (nftables) on the microVM's
egress path** — packets, not streams — so raw scans, UDP, ICMP and L2 all pass
when their destination is in scope, and everything else is dropped and logged.

- **microVM isolation** (libkrun on a laptop, Firecracker / Cloud-Hypervisor on a
  Linux host, Kata on a cluster): a real guest kernel, so the agent's nested
  docker, `/dev/net/tun` and raw sockets work unchanged.
- **nftables egress gate**, compiled from the manifest: deny-by-default,
  deny-wins, cloud metadata (`169.254.169.254`) always denied, per-target port
  scoping, and every other packet logged then dropped.
- **scope-as-code**: one committed Engagement manifest is the single source of
  truth and the authorization record; `window.end` auto-expires egress, so scope
  cannot outlive its authorization.

Run `nullbox` for the terminal UI, or drive it from the command line: `validate`,
`render` (print the compiled nftables policy), `up`, `shell`, `kill`, `down`,
`list`, `console` (web UI), `version`.

## Status

All three phases are implemented. The pure logic is unit-tested and every path
cross-compiles for Linux; the parts that touch a hypervisor or a cluster are
driven through injected seams and table-tested against fakes, but a **live
microVM boot and a live cluster apply can only be verified on real hardware** (a
Linux/KVM host; a Kubernetes cluster with the Kata runtime + a policy-enforcing
CNI). Those paths are marked below, and nothing fakes a boot it cannot perform.

Built and unit-tested off-hardware:

- **policy compiler** → nftables: deny-wins, port-scoping, the guest-egress
  `forward` chain + masquerade, and NFLOG accept/drop groups (`internal/policy`)
- **egress event decoder** (packet → FlowEvent), **engagement store**,
  **terminal UI** + **web console** with a live event stream when on Linux
- **capability-contract generator** (`internal/contract`), **Kata NetworkPolicy
  renderer** with deny-wins via `ipBlock.except`, **tool-Job renderer**
  (`internal/toolrunner`), and the firecracker / krun / kata command layers
- **CLI**: `validate`, `render`, `up`, `shell`, `kill`, `down`, `list`,
  `console`, `version`

Implemented, verified only on real hardware:

- **Phase 1** — Firecracker microVM boot (raw API over the unix socket) on
  Linux/KVM; krun/libkrun boot on a laptop; the NFLOG netlink reader (CAP_NET_ADMIN)
- **Phase 2** — the Kata driver applying manifests to a cluster
- **Phase 3** — injecting the generated contract into the guest, and the sibling
  tool runner (K8s Jobs on the cluster / scoped containers on the laptop)

## Quickstart

```bash
go test ./...                                              # all packages, offline
go run ./cmd/nullbox validate examples/acme-internal.yaml
go run ./cmd/nullbox render   examples/acme-internal.yaml  # the exact egress policy
nullbox                                                    # the terminal UI
```

`render` is the one to look at first — it shows the deny-by-default ruleset the
manifest compiles to: metadata always dropped, deny-wins carve-outs, all-ports
CIDRs in a named set, port-scoped CIDRs as explicit L4 rules, everything else
logged and dropped.

## The manifest is the scope

One YAML file is the single source of truth and the authorization record. See
`examples/`. Key invariants (enforced by `model.Validate`, strict on unknown
keys):

- `metadata.authorization.ref` is **required** — no anonymous scope.
- `spec.window.end` is **required** — egress auto-expires; scope cannot outlive
  authorization.
- `spec.scope.allow` must be non-empty; **deny always wins**; a port-scoped CIDR
  is restricted to those ports and is *not* also opened for all ports.
- `169.254.169.254` + link-local are denied by default (`denyMetadata`), so
  offensive tooling can't reach host/cloud credentials.
- `spec.image` names the guest — **any** AI pentesting agent's OCI image. The
  sandbox treats the agent as a black box; scope is enforced around it, not
  inside it.

## Templates (reusable config)

Scope, window, and authorization are per-engagement, but the *setup* — driver,
guest image, network profile, capabilities, evidence retention — is usually the
same across a client or team. Save it once as a template and reference it:

```bash
# save a preset from an existing manifest (captures the config, not the scope)
nullbox template save acme-standard examples/acme-internal.yaml
nullbox template list
nullbox template show acme-standard
```

Then an engagement states only what's unique to it and inherits the rest:

```yaml
spec:
  template: acme-standard        # driver, image, network, capabilities, evidence
  window: { end: "2026-09-29T23:59:59Z" }
  scope: { allow: [ { cidr: 10.10.0.0/16 } ] }
```

The manifest always wins where it sets a value; the template only fills the
fields left unset. Templates live under `NULLBOX_TEMPLATES` (default
`<user-config>/nullbox/templates`). See `examples/templates/` and
`examples/acme-templated.yaml`.

## Network profiles

| Profile | Gives you | Host |
|---|---|---|
| `nat` | routed TCP/UDP/ICMP-echo | macOS + Linux laptop (krun) |
| `routed` | full raw sockets / UDP / ICMP to CIDRs | Linux host (Firecracker) |
| `l2` | broadcast domain (arp-scan / Responder / mitm6) | Linux host on the target segment |

## Layout

```
cmd/nullbox/        CLI; bare `nullbox` launches the TUI
internal/model/     Engagement schema + validation        (stdlib only)
internal/manifest/  YAML loader
internal/policy/    manifest -> nftables compiler + host resolver  (stdlib only)
internal/store/     engagement registry (name-based lifecycle)
internal/driver/    VMM abstraction: krun, firecracker, clh/kata stubs
internal/tui/       in-terminal UI (bubbletea + lipgloss)
internal/console/   web console (embedded HTML + JSON/SSE API)
examples/           engagement manifests
```

## Remaining (hardware verification + hardening)

The phases are implemented; what's left is proving them on real hardware and a
few hardening items:

- Boot-test the Firecracker path end-to-end on Linux/KVM and confirm the
  `forward` chain drops out-of-scope guest packets (needs a guest kernel + rootfs).
- Per-engagement nft table names + TAP subnets, to allow more than one routed
  engagement per host (today the fixed table means one at a time).
- The guest↔controller `RunnerBroker` transport (vsock / unix socket) that
  carries a `ToolSpec` from the in-guest agent to the sibling tool runner.
- The `l2` profile on a bridge/netdev-family table — the inet `forward` hook does
  not see bridged L2 frames, so l2 filtering needs a bridge table (and a host on
  the target segment).
