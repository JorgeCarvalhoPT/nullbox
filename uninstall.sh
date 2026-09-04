#!/bin/sh
# nullbox uninstaller — removes the binary; optionally purges state + templates.
#
#   curl -fsSL https://raw.githubusercontent.com/JorgeCarvalhoPT/nullbox/main/uninstall.sh | sh
#
# By default this removes ONLY the binary and LEAVES your engagement records and
# evidence in place — for a pentest, that in-scope proof is worth keeping. Add
# --purge to also delete the state directory.
#
# Flags:
#   --purge     also delete state + templates (engagement records + evidence)
#   --yes, -y   don't prompt for confirmation on --purge
#   --dry-run   print what would be removed, remove nothing
#   --help, -h  show this help
#
# Env overrides (match the installer):
#   NULLBOX_BINDIR      where the binary lives (default: resolved from PATH, else /usr/local/bin)
#   NULLBOX_STATE       state dir to purge (default: <config>/nullbox)
#   NULLBOX_TEMPLATES   templates dir to purge (default: <config>/nullbox/templates)
set -eu

PURGE=0
ASSUME_YES=0
DRY_RUN=0
for arg in "$@"; do
  case "$arg" in
    --purge) PURGE=1 ;;
    --yes | -y) ASSUME_YES=1 ;;
    --dry-run) DRY_RUN=1 ;;
    --help | -h)
      awk 'NR==1{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "$0"
      exit 0
      ;;
    *) echo "nullbox: unknown option: $arg (try --help)" >&2; exit 2 ;;
  esac
done

run() {
  if [ "$DRY_RUN" -eq 1 ]; then
    echo "  would run: $*"
  else
    "$@"
  fi
}

# --- locate the binary -------------------------------------------------------
# If NULLBOX_BINDIR is set, look ONLY there — an explicit location should never
# fall back to removing some other install. Otherwise use PATH, then the default.
bin=""
if [ -n "${NULLBOX_BINDIR:-}" ]; then
  [ -e "${NULLBOX_BINDIR}/nullbox" ] && bin="${NULLBOX_BINDIR}/nullbox"
elif command -v nullbox >/dev/null 2>&1; then
  bin="$(command -v nullbox)"
elif [ -e /usr/local/bin/nullbox ]; then
  bin="/usr/local/bin/nullbox"
fi

# --- Homebrew? defer to brew so we don't corrupt its state -------------------
if [ -n "$bin" ]; then
  real="$bin"
  # resolve one symlink level (Homebrew links into the Cellar/Caskroom)
  if [ -L "$bin" ]; then real="$(readlink "$bin" 2>/dev/null || echo "$bin")"; fi
  case "$real" in
    */Cellar/* | */Caskroom/* | */homebrew/* | */linuxbrew/*)
      echo "nullbox: this looks like a Homebrew install ($bin)."
      echo "         uninstall it with Homebrew so its records stay consistent:"
      echo "           brew uninstall --cask nullbox   # or: brew uninstall nullbox"
      if [ "$PURGE" -eq 1 ]; then
        echo "         (then re-run this script with --purge to remove state)"
      fi
      exit 0
      ;;
  esac
fi

# --- warn about live sandboxes ----------------------------------------------
# Uninstalling does NOT tear down running microVMs. Nudge the operator to stop
# them first so nothing is left orphaned.
if [ -n "$bin" ] && [ -x "$bin" ]; then
  running="$("$bin" list 2>/dev/null | awk 'NR>1 && $4=="running" {print $1}' || true)"
  if [ -n "$running" ]; then
    echo "nullbox: these engagements are still running — stop them first:" >&2
    echo "$running" | sed 's/^/    /' >&2
    echo "    e.g. nullbox down <name>   (or nullbox kill <name> to just cut egress)" >&2
    echo >&2
  fi
fi

# --- remove the binary -------------------------------------------------------
if [ -n "$bin" ] && [ -e "$bin" ]; then
  dir="$(dirname "$bin")"
  if [ -w "$dir" ]; then
    run rm -f "$bin"
  else
    echo "nullbox: $dir is not writable, using sudo"
    run sudo rm -f "$bin"
  fi
  echo "nullbox: removed $bin"
else
  echo "nullbox: no binary found on PATH or in NULLBOX_BINDIR (nothing to remove)"
fi

# --- optionally purge state + templates -------------------------------------
if [ "$PURGE" -eq 1 ]; then
  case "$(uname -s)" in
    Darwin) default_cfg="${HOME}/Library/Application Support/nullbox" ;;
    *) default_cfg="${XDG_CONFIG_HOME:-$HOME/.config}/nullbox" ;;
  esac
  state_dir="${NULLBOX_STATE:-$default_cfg}"
  tpl_dir="${NULLBOX_TEMPLATES:-$default_cfg/templates}"

  targets=""
  [ -e "$state_dir" ] && targets="$state_dir"
  # templates default to a subdir of state; only list separately if outside it.
  case "$tpl_dir" in
    "$state_dir"/*) : ;;
    *) [ -e "$tpl_dir" ] && targets="${targets:+$targets
}$tpl_dir" ;;
  esac

  if [ -z "$targets" ]; then
    echo "nullbox: no state or templates found (nothing to purge)"
  else
    echo "nullbox: --purge will delete engagement records + evidence:"
    echo "$targets" | sed 's/^/    /'
    if [ "$ASSUME_YES" -ne 1 ] && [ "$DRY_RUN" -ne 1 ]; then
      if [ -t 0 ]; then
        printf "nullbox: permanently delete the above? [y/N] "
        read -r reply </dev/tty || reply=""
      else
        # piped (curl | sh) with no TTY: refuse rather than delete silently
        echo "nullbox: refusing to purge without a TTY; re-run with --yes to confirm" >&2
        exit 1
      fi
      case "$reply" in
        y | Y | yes | YES) ;;
        *) echo "nullbox: kept state (binary already removed)"; exit 0 ;;
      esac
    fi
    echo "$targets" | while IFS= read -r t; do
      [ -n "$t" ] && run rm -rf "$t"
    done
    echo "nullbox: purged state + templates"
  fi
else
  echo "nullbox: kept engagement records + evidence (re-run with --purge to delete them)"
fi
