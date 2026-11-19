# Changelog

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- MIPS assembly for ChaCha20 (`overlay/chacha20/`, MIPS32r2) and Poly1305 (`overlay/poly1305/`, MIPS32r1) for
  `GOARCH=mipsle`, with differential tests against the generic Go code.
- `scripts/build-tailscaled.sh`: reproducible build of admonstrator's "tiny" tailscaled (byte-identical
  with that build's version suffix), optionally with the assembly applied to both `golang.org/x/crypto` and the Go
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
- `overlay/tailscaled/gomaxprocs_mipsle.go`: tailscaled uses GOMAXPROCS=3 on 4-thread mipsle unless set in the
  environment (about +5 % over a DERP relay on the MT7621); `--no-tailscaled-overlay` to skip.
- `overlay/goroot/atomic_mipsx-lock-striping.patch`: lock striping for Go's 64-bit atomics on 32-bit MIPS,
  applied to the build's toolchain copy (about −4 % CPU per MB on top); `--no-goroot-patch` to skip.
- `overlay/patches/`: source patches applied by overlay builds (`--no-source-patches` to skip). Tailscale: the
  DERP client re-arms its read deadline every eighth of the timeout instead of for every frame. wireguard-go: the
  batch loops of the receive, send and GRO paths no longer iterate maps (2026-11-17).
- `pgo/2026-11-17_merged-mixed-derp.pprof`: two router profiles merged, now the default for overlay builds.
- `overlay/chacha20poly1305/`: ChaCha20-Poly1305 seal/open in one assembly routine for `GOARCH=mipsle`, with a
  differential test and edge vectors for the final Poly1305 reduction (2026-11-19). New, security-critical code:
  see "Status" in the README. `scripts/build-tailscaled.sh --no-aead` (`scripts/apply-overlay.sh --skip NAME`)
  builds without it.
- `bench/cold` and `scripts/bench-ab.sh --bench cold`: cost of one operation with the caches evicted first.
- `sim/`: a strict MIPS32r2 interpreter (`mipsim.py`), checks that run the ChaCha20 assembly and the seal/open
  routine in it (comparison with a reference, memory strictness, mutation check), and `aead_ops.py`, which runs
  Seal/Open of a built tailscaled and counts instructions and instruction-cache lines per operation.
- `scripts/icache-stall.py`: estimates from a CPU profile where tailscaled waits for instruction-cache misses.
- `results/2026-11-19_cache-lines.md`: cost of a cache line on the MT7621, compact ChaCha20, seal/open routine,
  three-way end-to-end A/B, and the two steps of 2026-11-17.

### Changed
- Poly1305 asm: carries between columns are added in the multiply accumulator, the fold moves to the next
  block, unaligned loads are interleaved (about 13 % faster on the MT7621).
- ChaCha20 asm: stall-free feed-forward order on the unaligned path (used by TLS/DERP), same code size.
- Go runtime patch: two memory barriers per 64-bit atomic operation instead of four (2026-11-17).
- Poly1305: `Sum` skips the copy of the state when no partial block is buffered; compile-time check of the
  `macState` layout the assembly assumes (2026-11-17).
- ChaCha20 asm: the ten double rounds are a loop again and the per-call precompute is gone: 1368 instead of 4920
  bytes of code, 29-34 instead of 140-145 instruction-cache lines per call. About 7 % slower when its code is
  already cached, 24-34 % faster when it is not, which is the normal case in real traffic on this router
  (2026-11-19).
- Over a DERP relay the last two crypto changes together: 12.1 -> 14.0 Mbit/s and 14.5 % less CPU time per MB
  (one session; `results/2026-11-19_cache-lines.md`).
- The scripts call their helper scripts through `bash` (they are not marked executable in git); the README's
  commands do the same and name Linux as a build host.
- README: summary with the measured values at the top, results per step.
