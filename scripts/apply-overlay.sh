#!/usr/bin/env bash
#
# Apply the MIPS (mipsle) ChaCha20 / Poly1305 assembly overlay to
#   (a) a golang.org/x/crypto source copy   (used by wireguard-go), and/or
#   (b) a GOROOT copy's vendored x/crypto   (src/vendor/golang.org/x/crypto,
#       used by crypto/tls -> DERP / control connections).
#
# Usage:
#   apply-overlay.sh [options] <xcrypto-dir|-> <goroot-dir|->
#
#   Pass "-" for a target to skip it.
#
# Options:
#   --overlay-dir DIR       overlay root (default: <repo>/overlay). Expected layout:
#                             DIR/chacha20/{chacha_mipsle.go,chacha_mipsle.s,...}
#                             DIR/poly1305/{sum_mipsle.go,sum_mipsle.s,...}
#   --pristine-xcrypto DIR  pristine x/crypto tree; the two target package dirs in
#                           <xcrypto-dir> are restored from it before applying
#   --pristine-goroot DIR   pristine GOROOT; the two vendored package dirs in
#                           <goroot-dir> are restored from it before applying
#   --with-tests            also copy *_test.go files (x/crypto target only)
#
# Rules (per package, chacha20 -> chacha20/, poly1305 -> internal/poly1305/):
#   * copy the overlay's non-test *.go and *.s files into the package dir;
#   * rewrite the //go:build line of the package's "noasm" file
#       chacha20/chacha_noasm.go, internal/poly1305/mac_noasm.go
#     from   //go:build <expr>
#     to     //go:build (<expr>) && (!mipsle || !gc || purego)
#   * a package whose overlay dir is missing or has no non-test .go/.s files is
#     left untouched (its noasm line is NOT rewritten, so mipsle keeps the
#     generic implementation).
# Idempotent: re-running yields the same tree (with --pristine-* it also removes
# files from a previous overlay that no longer exist).

set -euo pipefail

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
OVERLAY_DIR="$SCRIPT_DIR/../overlay"
PRISTINE_XC=""
PRISTINE_GR=""
WITH_TESTS=false
GUARD='(!mipsle || !gc || purego)'

die() { printf 'apply-overlay: ERROR: %s\n' "$*" >&2; exit 1; }
note() { printf 'apply-overlay: %s\n' "$*"; }

POSITIONAL=()
while [ $# -gt 0 ]; do
    case "$1" in
        --overlay-dir)      OVERLAY_DIR=$2; shift 2 ;;
        --pristine-xcrypto) PRISTINE_XC=$2; shift 2 ;;
        --pristine-goroot)  PRISTINE_GR=$2; shift 2 ;;
        --with-tests)       WITH_TESTS=true; shift ;;
        -h|--help)          sed -n '2,35p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        -*) [ "$1" = "-" ] && { POSITIONAL+=("$1"); shift; continue; }
            die "unknown option: $1" ;;
        *)  POSITIONAL+=("$1"); shift ;;
    esac
done
[ ${#POSITIONAL[@]} -eq 2 ] || die "usage: apply-overlay.sh [options] <xcrypto-dir|-> <goroot-dir|->"
XC_DIR=${POSITIONAL[0]}
GR_DIR=${POSITIONAL[1]}

# overlay name | package path inside x/crypto | noasm file
PACKAGES="chacha20|chacha20|chacha_noasm.go
poly1305|internal/poly1305|mac_noasm.go"

# List overlay source files (non-test .go/.s) for one overlay package.
overlay_files() {
    local d="$OVERLAY_DIR/$1" f
    [ -d "$d" ] || return 0
    for f in "$d"/*.go "$d"/*.s; do
        [ -f "$f" ] || continue
        case "$f" in *_test.go) continue ;; esac
        printf '%s\n' "$f"
    done
}

overlay_tests() {
    local d="$OVERLAY_DIR/$1" f
    [ -d "$d" ] || return 0
    for f in "$d"/*_test.go; do
        [ -f "$f" ] && printf '%s\n' "$f"
    done
    return 0
}

restore_dir() { # <pristine-pkg-dir> <target-pkg-dir>
    [ -d "$1" ] || die "pristine package dir missing: $1"
    chmod -R u+w "$2" 2>/dev/null || true
    rm -rf "$2"
    mkdir -p "$2"
    cp -p "$1"/* "$2"/
    chmod -R u+w "$2"
}

guard_noasm() { # <noasm-file>
    local f=$1 line expr
    [ -f "$f" ] || die "noasm file missing: $f"
    line=$(grep -m1 '^//go:build ' "$f") || die "no //go:build line in $f"
    case "$line" in
        *"&& $GUARD") note "  already guarded: $f"; return 0 ;;
    esac
    expr=${line#//go:build }
    # Replace exactly that line (first occurrence), preserving everything else.
    awk -v old="$line" -v new="//go:build ($expr) && $GUARD" \
        'done != 1 && $0 == old { print new; done = 1; next } { print }' "$f" >"$f.tmp"
    mv "$f.tmp" "$f"
    note "  guarded: $f"
    note "    -> $(grep -m1 '^//go:build ' "$f")"
}

# apply_target <label> <xcrypto-root-in-target> <pristine-root-or-empty> <tests:true|false>
apply_target() {
    local label=$1 root=$2 pristine=$3 tests=$4 entry name pkg noasm files f
    [ -d "$root" ] || die "$label: target dir not found: $root"
    note "target $label: $root"
    while IFS= read -r entry; do
        name=${entry%%|*}; entry=${entry#*|}
        pkg=${entry%%|*}; noasm=${entry#*|}
        if [ -n "$pristine" ]; then
            restore_dir "$pristine/$pkg" "$root/$pkg"
        fi
        files=$(overlay_files "$name")
        if [ -z "$files" ]; then
            note "  $name: no overlay files in $OVERLAY_DIR/$name -- skipped (generic code stays)"
            continue
        fi
        while IFS= read -r f; do
            cp "$f" "$root/$pkg/"
            note "  $name: copied $(basename "$f") -> $pkg/"
        done <<<"$files"
        if [ "$tests" = true ]; then
            while IFS= read -r f; do
                [ -n "$f" ] || continue
                cp "$f" "$root/$pkg/"
                note "  $name: copied test $(basename "$f") -> $pkg/"
            done <<<"$(overlay_tests "$name")"
        fi
        guard_noasm "$root/$pkg/$noasm"
    done <<<"$PACKAGES"
}

if [ "$XC_DIR" != "-" ]; then
    [ -f "$XC_DIR/go.mod" ] && grep -q '^module golang.org/x/crypto' "$XC_DIR/go.mod" ||
        die "$XC_DIR is not a golang.org/x/crypto module root"
    apply_target "x/crypto" "$XC_DIR" "$PRISTINE_XC" "$WITH_TESTS"
fi

if [ "$GR_DIR" != "-" ]; then
    [ -f "$GR_DIR/VERSION" ] || die "$GR_DIR does not look like a GOROOT (no VERSION file)"
    pr=""
    [ -n "$PRISTINE_GR" ] && pr="$PRISTINE_GR/src/vendor/golang.org/x/crypto"
    apply_target "GOROOT vendor" "$GR_DIR/src/vendor/golang.org/x/crypto" "$pr" false
fi
