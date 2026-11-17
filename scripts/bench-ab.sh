#!/usr/bin/env bash
#
# Interleaved A/B benchmark of two overlay revisions on the device.
#
# Usage:
#   bench-ab.sh [options] <rev-A> <rev-B>
#
#   <rev>  a git revision of this repository (its overlay/ is used, e.g. HEAD~1,
#          a tag or a commit) or "worktree" (the current overlay/ directory).
#
# Options:
#   --pairs N    interleaved A,B runs (default 6)
#   --rounds R   rounds per run, median reported per run (default 3)
#   --ms M       milliseconds per case and round (default 300)
#   --filter S   only cases whose name contains S (e.g. "ccstream", "1420")
#
# For each revision: a pristine golang.org/x/crypto (version as in
# build-tailscaled.sh) from the module cache gets the overlay applied, and
# bench/sweep is cross-compiled against it. Both binaries are copied to the
# device's /tmp (RAM), run alternately under the benchmark lock, then deleted.
# The comparison (scripts/ab-compare.py) shows medians and, per case, in how
# many pairs B was faster.
#
# Needs: device.env (ROUTER_SSH), .tools/go, python, and the module cache in
# work/gopath (filled by build-tailscaled.sh or setup).
# Output kept in work/ab/<A>_vs_<B>.txt.

set -euo pipefail

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)
WORK="$ROOT/work"
GO="$ROOT/.tools/go/bin/go"
XCRYPTO_VERSION=$(sed -n 's/^XCRYPTO_VERSION=//p' "$SCRIPT_DIR/build-tailscaled.sh")

PAIRS=6 ROUNDS=3 MS=300 FILTER=""
die()  { printf 'bench-ab: ERROR: %s\n' "$*" >&2; exit 1; }
note() { printf '==> %s\n' "$*"; }

POS=()
while [ $# -gt 0 ]; do
    case "$1" in
        --pairs)  PAIRS=$2; shift 2 ;;
        --rounds) ROUNDS=$2; shift 2 ;;
        --ms)     MS=$2; shift 2 ;;
        --filter) FILTER=$2; shift 2 ;;
        -h|--help) sed -n '2,28p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        -*) die "unknown option: $1" ;;
        *)  POS+=("$1"); shift ;;
    esac
done
[ ${#POS[@]} -eq 2 ] || die "usage: bench-ab.sh [options] <rev-A> <rev-B>"
[ -f "$ROOT/device.env" ] || die "device.env missing"
# shellcheck disable=SC1091
. "$ROOT/device.env"
[ -n "${ROUTER_SSH:-}" ] || die "ROUTER_SSH not set in device.env"
[ -x "$GO" ] || die "Go toolchain missing: run scripts/setup-tools.sh"
XC_SRC="$WORK/gopath/pkg/mod/golang.org/x/crypto@$XCRYPTO_VERSION"
[ -f "$XC_SRC/go.mod" ] || die "x/crypto $XCRYPTO_VERSION not in work/gopath (run build-tailscaled.sh --check once)"

export GOPATH="$WORK/gopath" GOCACHE="$WORK/gocache" GOTOOLCHAIN=local GOFLAGS=-mod=mod
export GOOS=linux GOARCH=mipsle GOMIPS=softfloat CGO_ENABLED=0

ssh_dev() { ssh -o BatchMode=yes "$ROUTER_SSH" "$@" 2> >(grep -v -i 'post-quantum\|store now, decrypt later\|openssh.com/pq\|upgraded' >&2); }
safe() { printf '%s' "$1" | tr -c 'A-Za-z0-9._-' '_'; }

# prepare <rev> <label>: overlay copy, patched x/crypto, sweep binary in work/ab/<label>/
prepare() {
    local rev=$1 label=$2 dir="$WORK/ab/$2"
    rm -rf "$dir" && mkdir -p "$dir/overlay" "$dir/bench"
    if [ "$rev" = worktree ]; then
        cp -r "$ROOT/overlay/." "$dir/overlay/"
    else
        git -C "$ROOT" rev-parse --verify -q "$rev^{commit}" >/dev/null || die "unknown revision: $rev"
        git -C "$ROOT" archive "$rev" overlay | tar -x -C "$dir"
    fi
    cp -r "$XC_SRC" "$dir/xc" && chmod -R u+w "$dir/xc"
    "$SCRIPT_DIR/apply-overlay.sh" --overlay-dir "$dir/overlay" "$dir/xc" - >/dev/null
    cp "$ROOT/bench/sweep/main.go" "$dir/bench/"
    cat >"$dir/bench/go.mod" <<EOF
module sweep

go 1.26

require golang.org/x/crypto $XCRYPTO_VERSION

replace golang.org/x/crypto => ../xc
EOF
    (cd "$dir/bench" && "$GO" mod tidy >/dev/null 2>&1 && "$GO" build -trimpath -ldflags='-s -w' -o ../sweep .) \
        || die "build failed for $rev"
    note "$label: built ($rev)"
}

A=$(safe "${POS[0]}") B=$(safe "${POS[1]}")
[ "$A" != "$B" ] || die "the two revisions must differ"
prepare "${POS[0]}" "$A"
prepare "${POS[1]}" "$B"

OUT="$WORK/ab/${A}_vs_${B}.txt"
ssh_dev 'mkdir /tmp/mc.lock' || die "benchmark lock /tmp/mc.lock is held on the device"
cleanup() { ssh_dev "rm -f /tmp/ab-A /tmp/ab-B /tmp/ab.txt; rmdir /tmp/mc.lock" || true; }
trap cleanup EXIT
gzip -c "$WORK/ab/$A/sweep" | ssh_dev 'gunzip -c > /tmp/ab-A && chmod +x /tmp/ab-A'
gzip -c "$WORK/ab/$B/sweep" | ssh_dev 'gunzip -c > /tmp/ab-B && chmod +x /tmp/ab-B'
note "running $PAIRS interleaved pairs on the device (rounds=$ROUNDS, ms=$MS, filter='$FILTER')"
ssh_dev "cd /tmp && : > ab.txt && i=0 && while [ \$i -lt $PAIRS ]; do i=\$((i+1)); \
  echo '## $A' \$i >> ab.txt; ./ab-A $ROUNDS $MS '$FILTER' >> ab.txt 2>&1; \
  echo '## $B' \$i >> ab.txt; ./ab-B $ROUNDS $MS '$FILTER' >> ab.txt 2>&1; done; cat ab.txt" >"$OUT"
python "$SCRIPT_DIR/ab-compare.py" "$OUT" "$A" "$B"
note "raw output: $OUT"
