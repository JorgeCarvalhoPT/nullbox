# nullbox

A Smith-native pentest sandbox. It runs agent-smith / AI pentest agents inside a
microVM and **enforces engagement scope as a packet filter**, so the full
network toolchain — raw sockets, UDP, ICMP, L2 — keeps working while every
destination stays deny-by-default and explicitly authorized.

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

## Status: Phase 0

Fully working, no host VMM required:

- **manifest schema + validation** (`internal/model`, `internal/manifest`)
- **policy compiler**: manifest → nftables egress ruleset + host resolver (`internal/policy`)
- **engagement store** with name-based lifecycle (`internal/store`)
- **terminal UI** (`internal/tui`) and **web console** (`internal/console`)
- **CLI**: `validate`, `render`, `list`, `console`, `version`

Completed on a host with the VMM:

- **VMM drivers** (`internal/driver`): `krun` preflight is real; the Firecracker
  driver applies the egress policy and implements the kill switch for real, with
  a pluggable microVM boot. `up` / `shell` need a host with the backend installed.

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

## Roadmap

- **Phase 1** — `routed`/`l2` on Firecracker+TAP (the nftables ruleset applies
  here), host DNS resolution for host-form scope entries, evidence flow logging,
  and the real Firecracker microVM boot.
- **Phase 2** — `kata` driver: the same manifest on Kubernetes, a namespace per
  engagement, egress attribution, a shared node image cache.
- **Phase 3** — a generated capability contract from the resolved profile, and a
  Job/sibling-VM tool runner in place of nested docker.
