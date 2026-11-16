#!/usr/bin/env bash
# Copyright (c) 2026 netbrains.ch
# SPDX-License-Identifier: BSD-3-Clause
#
# setup-tools.sh - download the Go toolchain the build expects into .tools/go (checksum-verified).
# Go version must match the reference tailscaled build (go version -m shows it).
# Usage: scripts/setup-tools.sh [go-version]   (default 1.27.4)
set -euo pipefail
VER=${1:-1.27.4}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
DEST="$ROOT/.tools"
case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) OS=windows EXT=zip ;;
    Linux) OS=linux EXT=tar.gz ;;
    Darwin) OS=darwin EXT=tar.gz ;;
    *) echo "unsupported OS $(uname -s)" >&2; exit 1 ;;
esac
case "$(uname -m)" in x86_64|amd64) ARCH=amd64 ;; aarch64|arm64) ARCH=arm64 ;; *) echo "unsupported arch" >&2; exit 1 ;; esac
FILE="go$VER.$OS-$ARCH.$EXT"
if [ -x "$DEST/go/bin/go" ] || [ -x "$DEST/go/bin/go.exe" ]; then
    echo "already present: $("$DEST/go/bin/go" version)"; exit 0
fi
mkdir -p "$DEST"; TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
echo "downloading $FILE"
curl -fsSL -o "$TMP/$FILE" "https://go.dev/dl/$FILE"
WANT=$(curl -fsSL "https://go.dev/dl/?mode=json&include=all" | tr ',{' '\n\n' | grep -A10 "\"filename\": *\"$FILE\"" | grep -o '"sha256": *"[0-9a-f]*"' | grep -o '[0-9a-f]\{64\}' | head -1)
GOT=$(sha256sum "$TMP/$FILE" | cut -d' ' -f1)
[ -n "$WANT" ] && [ "$WANT" = "$GOT" ] || { echo "checksum mismatch (want '$WANT', got $GOT)" >&2; exit 1; }
echo "sha256 ok"
if [ "$EXT" = zip ]; then (cd "$DEST" && unzip -q "$TMP/$FILE"); else tar -xzf "$TMP/$FILE" -C "$DEST"; fi
"$DEST/go/bin/go" version
