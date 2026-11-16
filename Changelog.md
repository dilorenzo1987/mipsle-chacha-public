# Changelog

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- MIPS32r2 assembly for ChaCha20 (`overlay/chacha20/`) and Poly1305 (`overlay/poly1305/`) for
  `GOARCH=mipsle`, with differential tests against the generic Go code.
- `scripts/build-tailscaled.sh`: reproducible build of admonstrator's "tiny" tailscaled (byte-identical
  with his version suffix), optionally with the assembly applied to both `golang.org/x/crypto` and the Go
  standard library's vendored copy (used by `crypto/tls`).
- `scripts/apply-overlay.sh`, `scripts/mango-swap.sh` (install on the router with automatic rollback).
- `bench/main.go` crypto micro-benchmark and results for the GL.iNet GL-MG1300 (`results/`).
