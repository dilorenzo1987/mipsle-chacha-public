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
- `scripts/setup-tools.sh`: downloads and checksum-verifies the Go toolchain into `.tools/go`.
- `TestMipsleExitCarry`: covers the final carry propagation of the Poly1305 asm limb by limb.
- `bench/sweep` and `scripts/bench-ab.sh`: interleaved A/B micro-benchmarks of two overlay revisions on the
  device; `scripts/mutate-poly1305.sh`: single-instruction mutation check of the Poly1305 asm.
- Profile-guided optimization: overlay builds use the committed router profile in `pgo/` by default
  (`--no-pgo` to disable, `--pgo FILE` for another profile); baseline builds are unchanged.
- `results/2026-11-17_sweep-e2e-pgo.md`: tuning pass, end-to-end check, tailscaled CPU profile, PGO.

### Changed
- Poly1305 asm: carries between columns are added in the multiply accumulator, the fold moves to the next
  block, unaligned loads are interleaved (about 13 % faster on the MT7621).
- ChaCha20 asm: stall-free feed-forward order on the unaligned path (used by TLS/DERP), same code size.
