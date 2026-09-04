#!/bin/sh
# nullbox installer — downloads the latest release binary for your OS/arch.
#
#   curl -fsSL https://raw.githubusercontent.com/JorgeCarvalhoPT/nullbox/main/install.sh | sh
#
# Env overrides:
#   NULLBOX_BINDIR   install location (default: /usr/local/bin)
#   NULLBOX_VERSION  a specific tag, e.g. v0.1.0 (default: latest)
set -eu

OWNER="JorgeCarvalhoPT" # <- replace with your GitHub owner
REPO="nullbox"
BINDIR="${NULLBOX_BINDIR:-/usr/local/bin}"

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"
case "$arch" in
  x86_64 | amd64) arch="amd64" ;;
  arm64 | aarch64) arch="arm64" ;;
  *) echo "nullbox: unsupported architecture: $arch" >&2; exit 1 ;;
esac
case "$os" in
  darwin | linux) ;;
  *) echo "nullbox: unsupported OS: $os -- use 'go install' on this platform" >&2; exit 1 ;;
esac

tag="${NULLBOX_VERSION:-}"
if [ -z "$tag" ]; then
  tag="$(curl -fsSL "https://api.github.com/repos/$OWNER/$REPO/releases/latest" \
    | grep '"tag_name":' | head -1 | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')"
fi
[ -n "$tag" ] || { echo "nullbox: could not resolve the latest release" >&2; exit 1; }
ver="${tag#v}"

url="https://github.com/$OWNER/$REPO/releases/download/$tag/${REPO}_${ver}_${os}_${arch}.tar.gz"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "nullbox: downloading $tag ($os/$arch)…"
curl -fsSL "$url" | tar -xz -C "$tmp"

[ -d "$BINDIR" ] || mkdir -p "$BINDIR" 2>/dev/null || true
if [ -w "$BINDIR" ]; then
  install -m 0755 "$tmp/nullbox" "$BINDIR/nullbox"
else
  echo "nullbox: $BINDIR is not writable, using sudo"
  sudo install -m 0755 "$tmp/nullbox" "$BINDIR/nullbox"
fi

echo "nullbox: installed to $BINDIR/nullbox"
"$BINDIR/nullbox" version || true
echo "nullbox: run 'nullbox' to launch the terminal UI"
