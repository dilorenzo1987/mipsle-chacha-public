#!/usr/bin/env bash
#
# Reproducible build of Tailscale's combined tailscaled+CLI ("tiny" feature set, as
# published by admonstrator/glinet-tailscale-updater) for GL.iNet GL-MG1300
# (linux/mipsle, GOMIPS=softfloat), optionally with the MIPS ChaCha20/Poly1305
# assembly overlay applied to BOTH golang.org/x/crypto (wireguard-go) and the
# x/crypto copy vendored into the Go standard library (crypto/tls, DERP).
#
# Usage: scripts/build-tailscaled.sh [options]
#
#   (default)            overlay build  -> build/tailscaled-mipsle-chacha
#   --no-overlay         baseline build -> build/tailscaled-mipsle-baseline
#                        (pristine GOROOT, no replace directive: build info is
#                        identical to admon's tiny build except the version stamp)
#   --check              prepare everything, then print the GoFiles/SFiles of the
#                        chacha20 / poly1305 packages (x/crypto copy and stdlib
#                        vendored copy) as resolved in tailscaled's real build
#                        graph; does not build
#   --overlay-dir DIR    overlay root (default: <repo>/overlay)
#   --suffix S           version suffix (default: -tiny.mipsle-chacha / -tiny.mipsle-base)
#   --variant NAME       output name build/tailscaled-mipsle-NAME
#   --ref BIN            diff `go version -m` of the result against BIN
#   --pgo FILE           profile-guided optimization with this CPU profile instead of
#                        the default (overlay builds use pgo/2026-11-16_A_mixed90s.pprof,
#                        a 90 s CPU profile of tailscaled on the router under traffic)
#   --no-pgo             overlay build without PGO (baseline builds never use PGO,
#                        so --no-overlay still reproduces admon's build exactly)
#   -h | --help
#
# Everything mutable lives in work/ (cached between runs) and build/ (outputs).

set -euo pipefail

# ---------------------------------------------------------------------------
# Pinned inputs
# ---------------------------------------------------------------------------
TS_REPO=https://github.com/tailscale/tailscale.git
TS_TAG=v1.104.7
TS_COMMIT=cbc74fe48ef1b1649f69a4d9a602319427e25102
ADMON_REPO=https://github.com/admonstrator/glinet-tailscale-updater.git
ADMON_COMMIT=e5aa2936d8000fdebcbccec0c5eeb598819eaeda   # HEAD when admon built 1.104.7 (run 1457)
XCRYPTO_VERSION=v0.58.0
GO_VERSION=go1.27.4

# Feature set from admon's .github/workflows/build-tailscale.yaml
KEEP="dns,osrouter,iptables,netstack,health,logtail,portmapper,usermetrics,useroutes,cli"
KEEP="${KEEP},advertiseexitnode,useexitnode,advertiseroutes"
KEEP="${KEEP},clientmetrics,cliconndiag,doctor"
KEEP="${KEEP},acme,bakedroots,tailnetlock,unixsocketidentity"
KEEP="${KEEP},appconnectors,cachenetmap,colorable,conn25,debug,gro,ipnbus"
KEEP="${KEEP},hujsonconf,lazywg,listenrawdisco,portlist,serve,ssh,useproxy,relayserver"

# Tags exactly as recorded in the reference binary (1.104.7-tiny.by.admon.1457).
EXPECTED_TAGS="ts_include_cli,ts_omit_ace,ts_omit_androidbin,ts_omit_androiddns,ts_omit_aws,ts_omit_bird,ts_omit_captiveportal,ts_omit_capture,ts_omit_clientupdate,ts_omit_cloud,ts_omit_completion,ts_omit_completion_scripts,ts_omit_connreject,ts_omit_debugeventbus,ts_omit_debugportmapper,ts_omit_desktop_sessions,ts_omit_dnsresolvecache,ts_omit_drive,ts_omit_favorites,ts_omit_flashappliance,ts_omit_identityfederation,ts_omit_kube,ts_omit_linkspeed,ts_omit_linuxdnsfight,ts_omit_netlog,ts_omit_networkmanager,ts_omit_oauthkey,ts_omit_outboundproxy,ts_omit_posture,ts_omit_qrcodes,ts_omit_remoteconfig,ts_omit_resolved,ts_omit_routecheck,ts_omit_runtimemetrics,ts_omit_sdnotify,ts_omit_serviceclientprefs,ts_omit_synology,ts_omit_syslog,ts_omit_syspolicy,ts_omit_systray,ts_omit_taildrop,ts_omit_tap,ts_omit_tpm,ts_omit_tundevstats,ts_omit_wakeonlan,ts_omit_webbrowser,ts_omit_webclient"

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)
GO_PRISTINE="$ROOT/.tools/go"
WORK="$ROOT/work"
BUILD="$ROOT/build"
TS_DIR="$WORK/tailscale"
ADMON_DIR="$WORK/admon"
GOROOT_PATCHED="$WORK/goroot-patched"
XC_PATCHED="$WORK/xcrypto-patched"
MODFILE_DIR="$WORK/modfile"
OVERLAY_DIR="$ROOT/overlay"

OVERLAY=true
CHECK=false
SUFFIX=""
VARIANT=""
REF=""
PGO=""

die()  { printf 'build-tailscaled: ERROR: %s\n' "$*" >&2; exit 1; }
note() { printf '==> %s\n' "$*"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --no-overlay)  OVERLAY=false; shift ;;
        --check)       CHECK=true; shift ;;
        --overlay-dir) OVERLAY_DIR=$(CDPATH='' cd -- "$2" && pwd); shift 2 ;;
        --suffix)      SUFFIX=$2; shift 2 ;;
        --variant)     VARIANT=$2; shift 2 ;;
        --ref)         REF=$2; shift 2 ;;
        --pgo)         PGO=$(CDPATH='' cd -- "$(dirname -- "$2")" && pwd)/$(basename -- "$2"); shift 2 ;;
        --no-pgo)      PGO=none; shift ;;
        -h|--help)     sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

if [ "$OVERLAY" = true ]; then
    : "${SUFFIX:=-tiny.mipsle-chacha}"; : "${VARIANT:=chacha}"
    : "${PGO:=$ROOT/pgo/2026-11-16_A_mixed90s.pprof}"
else
    : "${SUFFIX:=-tiny.mipsle-base}";   : "${VARIANT:=baseline}"
fi
[ "$PGO" != none ] || PGO=""

# Native (C:/...) path for arguments handed to go.exe on Windows; identity elsewhere.
native() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s\n' "$1"; fi; }

# ---------------------------------------------------------------------------
# Environment: isolated, local toolchain only
# ---------------------------------------------------------------------------
unset GOROOT GOFLAGS GOWORK GOEXPERIMENT GODEBUG GOOS GOARCH GOMIPS CGO_ENABLED GOENV
export GOENV=off
export GOPATH; GOPATH=$(native "$WORK/gopath")
export GOCACHE; GOCACHE=$(native "$WORK/gocache")
export GOTOOLCHAIN=local
mkdir -p "$WORK" "$BUILD"

[ -x "$GO_PRISTINE/bin/go" ] || [ -x "$GO_PRISTINE/bin/go.exe" ] || die "Go toolchain not found at $GO_PRISTINE"
HOST_GO="$GO_PRISTINE/bin/go"
"$HOST_GO" version | grep -q " $GO_VERSION " || die "expected $GO_VERSION at $GO_PRISTINE, got: $("$HOST_GO" version)"

target_env() { env CGO_ENABLED=0 GOOS=linux GOARCH=mipsle GOMIPS=softfloat "$@"; }

# ---------------------------------------------------------------------------
# 1. Tailscale source at the pinned tag, reset, plus admon's patches
# ---------------------------------------------------------------------------
prepare_tailscale() {
    if [ ! -d "$TS_DIR/.git" ]; then
        note "cloning tailscale $TS_TAG"
        git -c core.autocrlf=false -c advice.detachedHead=false clone -q --depth 1 --branch "$TS_TAG" "$TS_REPO" "$TS_DIR"
    fi
    git -C "$TS_DIR" config core.autocrlf false
    if ! git -C "$TS_DIR" cat-file -e "$TS_COMMIT^{commit}" 2>/dev/null; then
        git -C "$TS_DIR" fetch -q --depth 1 origin "refs/tags/$TS_TAG:refs/tags/$TS_TAG"
    fi
    [ "$(git -C "$TS_DIR" rev-parse "$TS_TAG^{commit}")" = "$TS_COMMIT" ] ||
        die "tag $TS_TAG does not point at $TS_COMMIT"
    git -C "$TS_DIR" reset -q --hard "$TS_COMMIT"
    git -C "$TS_DIR" clean -q -fdx

    if [ ! -d "$ADMON_DIR/.git" ]; then
        note "cloning admonstrator/glinet-tailscale-updater"
        git -c core.autocrlf=false clone -q "$ADMON_REPO" "$ADMON_DIR"
    fi
    git -C "$ADMON_DIR" config core.autocrlf false
    git -C "$ADMON_DIR" cat-file -e "$ADMON_COMMIT^{commit}" 2>/dev/null || git -C "$ADMON_DIR" fetch -q origin
    git -C "$ADMON_DIR" checkout -q --force "$ADMON_COMMIT"
    git -C "$ADMON_DIR" clean -q -fdx

    note "applying admon's GL.iNet patches (admon @ ${ADMON_COMMIT:0:7})"
    TAILSCALE_TAG="$TS_TAG" bash "$ADMON_DIR/scripts/apply-tailscale-patches.sh" \
        --patch-dir "$ADMON_DIR/patches" --source-dir "$TS_DIR" 2>&1 | sed 's/^/    /'
    [ "${PIPESTATUS[0]}" -eq 0 ] || die "admon patch step failed"
    git -C "$TS_DIR" status --short | sed 's/^/    modified: /'

    (cd "$TS_DIR" && "$HOST_GO" mod download) || die "go mod download failed"
}

# ---------------------------------------------------------------------------
# 2. Version stamp (same mechanism as admon: mkversion + suffix)
# ---------------------------------------------------------------------------
compute_version() {
    local out
    out=$(cd "$TS_DIR" && CGO_ENABLED=0 "$HOST_GO" run ./cmd/mkversion) || die "mkversion failed"
    VERSION_SHORT=$(printf '%s\n' "$out" | sed -n 's/^VERSION_SHORT="\{0,1\}\([^"]*\)"\{0,1\}$/\1/p')
    VERSION_LONG=$(printf '%s\n' "$out"  | sed -n 's/^VERSION_LONG="\{0,1\}\([^"]*\)"\{0,1\}$/\1/p')
    [ -n "$VERSION_SHORT" ] && [ -n "$VERSION_LONG" ] || die "could not parse mkversion output:
$out"
    VERSION_SHORT_CUSTOM="${VERSION_SHORT}${SUFFIX}"
    VERSION_LONG_CUSTOM="${VERSION_LONG}${SUFFIX}"
    LDFLAGS="-w -s -X tailscale.com/version.longStamp=${VERSION_LONG_CUSTOM} -X tailscale.com/version.shortStamp=${VERSION_SHORT_CUSTOM}"
    note "version: short=$VERSION_SHORT_CUSTOM long=$VERSION_LONG_CUSTOM"
}

# ---------------------------------------------------------------------------
# 3. Build tags (featuretags must reproduce the reference list)
# ---------------------------------------------------------------------------
compute_tags() {
    local got
    got=$(cd "$TS_DIR" && CGO_ENABLED=0 "$HOST_GO" run ./cmd/featuretags --min --add="$KEEP") ||
        die "featuretags failed"
    got=$(printf '%s' "$got" | tr -d '\r\n')
    [ "$got" = "$EXPECTED_TAGS" ] || die "featuretags output differs from the reference tag list:
got:  $got
want: $EXPECTED_TAGS"
    TAGS=$EXPECTED_TAGS
    note "tags: featuretags --min output matches the reference ($(printf '%s' "$TAGS" | awk -F, '{print NF}') tags)"
}

# ---------------------------------------------------------------------------
# 4. Patched GOROOT + patched x/crypto + overlay + modfile with replace
# ---------------------------------------------------------------------------
prepare_overlay() {
    local stamp xc_src xc_native
    stamp="$("$HOST_GO" version) $(native "$GO_PRISTINE")"
    if [ ! -f "$GOROOT_PATCHED/.mipsle-chacha-source" ] ||
       [ "$(cat "$GOROOT_PATCHED/.mipsle-chacha-source")" != "$stamp" ]; then
        note "creating patched GOROOT copy at $GOROOT_PATCHED (one-time, ~270 MB)"
        rm -rf "$GOROOT_PATCHED"
        cp -r "$GO_PRISTINE" "$GOROOT_PATCHED"
        printf '%s' "$stamp" >"$GOROOT_PATCHED/.mipsle-chacha-source"
    fi

    xc_src=$(cd "$TS_DIR" && "$HOST_GO" mod download -json "golang.org/x/crypto@$XCRYPTO_VERSION" |
             sed -n 's/^[[:space:]]*"Dir": "\(.*\)",$/\1/p' | sed 's/\\\\/\//g')
    [ -n "$xc_src" ] && [ -f "$xc_src/go.mod" ] || die "x/crypto $XCRYPTO_VERSION not found in module cache"
    if command -v cygpath >/dev/null 2>&1; then xc_src=$(cygpath -u "$xc_src"); fi
    XC_PRISTINE=$xc_src
    note "pristine x/crypto: $XC_PRISTINE"
    if [ ! -f "$XC_PATCHED/.mipsle-chacha-source" ] ||
       [ "$(cat "$XC_PATCHED/.mipsle-chacha-source")" != "$XCRYPTO_VERSION" ]; then
        rm -rf "$XC_PATCHED"
        cp -r "$XC_PRISTINE" "$XC_PATCHED"
        chmod -R u+w "$XC_PATCHED"
        printf '%s' "$XCRYPTO_VERSION" >"$XC_PATCHED/.mipsle-chacha-source"
    fi

    note "applying overlay from $OVERLAY_DIR"
    bash "$SCRIPT_DIR/apply-overlay.sh" --overlay-dir "$OVERLAY_DIR" \
        --pristine-xcrypto "$XC_PRISTINE" --pristine-goroot "$GO_PRISTINE" \
        "$XC_PATCHED" "$GOROOT_PATCHED" | sed 's/^/    /'
    [ "${PIPESTATUS[0]}" -eq 0 ] || die "apply-overlay failed"

    # Alternate go.mod outside the git tree: upstream go.mod stays untouched.
    mkdir -p "$MODFILE_DIR"
    cp "$TS_DIR/go.mod" "$MODFILE_DIR/go.mod"
    cp "$TS_DIR/go.sum" "$MODFILE_DIR/go.sum"
    xc_native=$(native "$XC_PATCHED")
    (cd "$TS_DIR" && "$HOST_GO" mod edit -modfile="$(native "$MODFILE_DIR/go.mod")" \
        -replace "golang.org/x/crypto=$xc_native")
    MODFLAG="-modfile=$(native "$MODFILE_DIR/go.mod")"

    GO="$GOROOT_PATCHED/bin/go"
    local gr
    gr=$("$GO" env GOROOT)
    [ "$(native "$gr")" = "$(native "$GOROOT_PATCHED")" ] ||
        die "patched go reports GOROOT=$gr, expected $GOROOT_PATCHED"
    note "go: $GO (GOROOT=$gr), $MODFLAG"
}

# ---------------------------------------------------------------------------
# --check: what actually gets compiled in tailscaled's build graph
# ---------------------------------------------------------------------------
run_check() {
    note "chacha20 / poly1305 packages in the tailscaled build graph (GOARCH=mipsle):"
    (cd "$TS_DIR" && target_env "$GO" list ${MODFLAG:+"$MODFLAG"} -tags="$TAGS" -deps \
        -f '{{.ImportPath}}|{{.Dir}}|{{.GoFiles}}|{{.SFiles}}' ./cmd/tailscaled) |
        grep -E '(^|/)golang.org/x/crypto/(chacha20|internal/poly1305|chacha20poly1305)\|' |
        while IFS='|' read -r ip dir gofiles sfiles; do
            printf '  %s\n      dir:     %s\n      GoFiles: %s\n      SFiles:  %s\n' \
                "$ip" "$dir" "$gofiles" "$sfiles"
        done
    note "importers of the stdlib-vendored chacha20poly1305 in the graph:"
    (cd "$TS_DIR" && target_env "$GO" list ${MODFLAG:+"$MODFLAG"} -tags="$TAGS" -deps \
        -f '{{.ImportPath}} {{join .Imports " "}}' ./cmd/tailscaled) |
        awk '/ vendor\/golang.org\/x\/crypto\/chacha20poly1305( |$)/ {print "  " $1}'
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
prepare_tailscale
compute_tags
compute_version

GO="$HOST_GO"
MODFLAG=""
if [ "$OVERLAY" = true ]; then
    prepare_overlay
else
    note "baseline: pristine GOROOT ($GO_PRISTINE), unmodified go.mod (no replace)"
fi

if [ "$CHECK" = true ]; then
    run_check
    exit 0
fi

OUT="$BUILD/tailscaled-mipsle-$VARIANT"
note "building $OUT"
rm -f "$OUT"
start=$(date +%s)
[ -z "$PGO" ] || { [ -f "$PGO" ] || die "PGO profile not found: $PGO"; note "PGO profile: $PGO"; }
(cd "$TS_DIR" && target_env "$GO" build ${MODFLAG:+"$MODFLAG"} -tags="$TAGS" -trimpath \
    ${PGO:+-pgo="$(native "$PGO")"} -ldflags "$LDFLAGS" -o "$(native "$OUT")" tailscale.com/cmd/tailscaled)
note "build took $(( $(date +%s) - start ))s"

size=$(wc -c <"$OUT" | tr -d ' ')
sha=$(sha256sum "$OUT" | cut -d' ' -f1)
"$HOST_GO" version -m "$OUT" | sed -E '1s/^.*: (go[0-9])/\1/' >"$OUT.buildinfo.txt"
printf '%s  %s\n' "$sha" "$(basename "$OUT")" >"$OUT.sha256"
grep -a -c -F "$VERSION_SHORT_CUSTOM" "$OUT" >/dev/null || die "version stamp $VERSION_SHORT_CUSTOM not found in binary"

note "output:  $OUT"
note "size:    $size bytes"
note "sha256:  $sha"
note "version: $VERSION_SHORT_CUSTOM (stamp found in binary)"
note "build info: $OUT.buildinfo.txt"

if [ -n "$REF" ]; then
    note "go version -m diff vs $REF (< reference, > this build):"
    if diff <("$HOST_GO" version -m "$REF" | sed -E '1s/^.*: (go[0-9])/\1/') "$OUT.buildinfo.txt"; then
        echo "    (identical)"
    fi
fi
