#!/usr/bin/env bash
#
# Mutation check of the Poly1305 assembly on the device: every carry, fold,
# carry-in and exit-propagation instruction is deleted one at a time
# (scripts/mutants-poly1305.py), and the Mipsle differential tests must fail
# for each mutant.
#
# Usage:
#   mutate-poly1305.sh [<rev>]     <rev>: git revision or "worktree" (default)
#
# First runs the unmutated tests (must pass), then each mutant (must fail).
# Test binaries go to the device's /tmp one at a time, under the benchmark
# lock, and are deleted after each run. Exit status 1 if any mutant survives.
# Takes about 15 s per mutant. Results in work/mutants/results.txt.
#
# Needs: device.env (ROUTER_SSH), .tools/go, python3 (or python), module cache in work/gopath.

set -euo pipefail

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)
WORK="$ROOT/work"
GO="$ROOT/.tools/go/bin/go"
XCRYPTO_VERSION=$(sed -n 's/^XCRYPTO_VERSION=//p' "$SCRIPT_DIR/build-tailscaled.sh")
REV=${1:-worktree}
DIR="$WORK/mutants"

die()  { printf 'mutate-poly1305: ERROR: %s\n' "$*" >&2; exit 1; }
note() { printf '==> %s\n' "$*"; }

case "$REV" in
    -h|--help) sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) die "unknown option $REV" ;;
    worktree) ;;
    *) git -C "$ROOT" rev-parse -q --verify "$REV^{commit}" >/dev/null || die "not a git revision: $REV" ;;
esac

[ -f "$ROOT/device.env" ] || die "device.env missing"
# shellcheck disable=SC1091
. "$ROOT/device.env"
[ -n "${ROUTER_SSH:-}" ] || die "ROUTER_SSH not set in device.env"
XC_SRC="$WORK/gopath/pkg/mod/golang.org/x/crypto@$XCRYPTO_VERSION"
[ -f "$XC_SRC/go.mod" ] || die "x/crypto $XCRYPTO_VERSION not in work/gopath"

export GOPATH="$WORK/gopath" GOCACHE="$WORK/gocache" GOTOOLCHAIN=local GOFLAGS=-mod=mod
export GOOS=linux GOARCH=mipsle GOMIPS=softfloat CGO_ENABLED=0
ssh_dev() { ssh -o BatchMode=yes "$ROUTER_SSH" "$@" 2> >(grep -v -i 'post-quantum\|store now, decrypt later\|openssh.com/pq\|upgraded' >&2); }

rm -rf "$DIR" && mkdir -p "$DIR/overlay" "$DIR/src" "$DIR/bin"
if [ "$REV" = worktree ]; then
    cp -r "$ROOT/overlay/." "$DIR/overlay/"
else
    git -C "$ROOT" archive "$REV" overlay | tar -x -C "$DIR"
fi
cp -r "$XC_SRC" "$DIR/xc" && chmod -R u+w "$DIR/xc"
bash "$SCRIPT_DIR/apply-overlay.sh" --with-tests --overlay-dir "$DIR/overlay" "$DIR/xc" - >/dev/null
ASM="$DIR/xc/internal/poly1305/sum_mipsle.s"
cp "$ASM" "$DIR/sum_mipsle.s.orig"

"$(command -v python3 || command -v python)" "$SCRIPT_DIR/mutants-poly1305.py" "$DIR/sum_mipsle.s.orig" "$DIR/src" | tr -d '\r' >"$DIR/list.txt"
note "$(wc -l <"$DIR/list.txt") mutants; building test binaries"
(cd "$DIR/xc" && "$GO" test -c -trimpath -ldflags='-s -w' -o "$DIR/bin/ok.test" ./internal/poly1305)
for m in "$DIR"/src/m*.s; do
    b=$(basename "$m" .s)
    cp "$m" "$ASM"
    (cd "$DIR/xc" && "$GO" test -c -trimpath -ldflags='-s -w' -o "$DIR/bin/$b.test" ./internal/poly1305)
done
cp "$DIR/sum_mipsle.s.orig" "$ASM"

ssh_dev 'mkdir /tmp/mc.lock' || die "benchmark lock /tmp/mc.lock is held on the device"
trap 'ssh_dev "rm -f /tmp/mut.test /tmp/mut.out; rmdir /tmp/mc.lock" || true' EXIT

# run_one <binary>: prints "rc=<n> crash=<n> <failed tests>" (crash = panic / fatal error / signal lines)
run_one() {
    gzip -c "$1" | ssh_dev "gunzip -c > /tmp/mut.test && chmod +x /tmp/mut.test && cd /tmp && \
      timeout 600 ./mut.test -test.run Mipsle > mut.out 2>&1; echo rc=\$? crash=\$(grep -cE '^(panic:|fatal error:)|signal SIG' mut.out) \$(grep '^--- FAIL' mut.out | awk '{print \$3}'); \
      rm -f mut.test mut.out"
}

r=$(run_one "$DIR/bin/ok.test") || r="rc=255 crash=ssh-failed"
echo "unmutated: $r" | tee "$DIR/results.txt"
case "$r" in rc=0*) ;; *) die "unmutated tests fail: $r" ;; esac

survivors=0 errors=0
while read -r id rest; do
    r=$(run_one "$DIR/bin/$id.test") || r="rc=255 crash=ssh-failed"
    # caught = a test failed or the binary crashed; any other non-zero exit (upload failed, timeout 124,
    # missing binary 127) proves nothing and is reported as ERROR
    case "$r" in
        "rc=0 "*) status=SURVIVED; survivors=$((survivors+1)) ;;
        *" crash="[1-9]*|*" crash="*" "?*) status=caught ;;   # crash lines, or failed test names follow
        *) status=ERROR; errors=$((errors+1)) ;;               # e.g. upload failed (crash= empty), timeout
    esac
    printf '%s %-8s %s | %s\n' "$id" "$status" "$rest" "$r" | tee -a "$DIR/results.txt"
done <"$DIR/list.txt"

note "survivors: $survivors, errors: $errors (results: $DIR/results.txt)"
[ "$survivors" -eq 0 ] && [ "$errors" -eq 0 ]
