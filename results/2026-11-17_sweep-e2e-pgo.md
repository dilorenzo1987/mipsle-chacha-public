# Results: tuning pass, end-to-end check and PGO, GL-MG1300 (Mango 2), 2026-11-16/17

Device and base as in `2026-11-16_gl-mg1300.md`. This file covers the second round: a tuning pass of the
assembly, an end-to-end check of the tuned build on the router, a CPU profile of tailscaled, and a
profile-guided (PGO) build.

## Micro-benchmarks (bench/sweep, 1 thread, median of 5–8 interleaved runs)

Before = overlay as first published (`1.104.7-tiny.mipsle-chacha`). Interleaved before/after pairs on the
device (`scripts/bench-ab.sh`); single runs vary by ~3 %, so small effects were only accepted when consistent
across pairs.

| | before | after | change |
|---|---|---|---|
| Poly1305 1420 B aligned / unaligned | 1210 / 1117 Mbit/s | 1358 / 1294 Mbit/s | −11 % / −14 % time |
| ChaCha20-Poly1305 seal / open 1420 B | 256–273 Mbit/s | 263–279 Mbit/s | −2 … −4 % time |
| 64-byte seal / open | 6.8 / 7.1 µs | unchanged | per-call Go glue dominates |

- Poly1305: carries between columns added inside the multiply accumulator (`MADDU hi, 1`), the final fold
  moved to the start of the next block, unaligned loads interleaved: 73 → 65 instructions per block. Bound
  proof and mutation results in `overlay/poly1305/NOTES.md`.
- ChaCha20: the feed-forward on the unaligned path (used by TLS/DERP) is reordered so no `LWL` directly
  follows its `LWR` into the same register (a measured stall on the 1004Kc). A two-loop variant was ~1 %
  faster still but twice the code and not better end to end (`overlay/chacha20/NOTES.md`).
- The AEAD row above was measured with that two-loop variant; the kept version is ~1 % behind it.

## End to end on the router

Method: the router downloads a 30 MB file over the **DERP** path (from a peer that is only reachable through
a Tailscale DERP relay, so the data is WireGuard inside TLS) and runs a **direct** download/upload through an
exit node over direct UDP (25 MB down, 10 MB up from speed.cloudflare.com). 3 runs per round, median. CPU per
MB = tailscaled's utime+stime (from `/proc/<pid>/stat`) divided by the bytes moved. Each build was installed
with `scripts/mango-swap.sh` and measured after a fresh restart.

| Build | DERP Mbit/s per round | DERP CPU-s/MB | direct ↓ Mbit/s | direct ↑ Mbit/s |
|---|---|---|---|---|
| first published overlay, process up for hours | 11.7 | 1.53 | 21.7 | 17.7 |
| first published overlay, fresh restart | 11.1 | 1.62 | 21.9 | 17.5 |
| two-loop ChaCha20 + new Poly1305, 3 rounds | 10.7 / 10.8 / 10.9 | 1.65–1.68 | 21.0–22.2 | 17.9–18.6 |
| new Poly1305 + old ChaCha20 | 11.3 | 1.62 | 21.3 | 17.8 |
| new Poly1305 + ChaCha20 reorder (kept), 3 rounds | 11.3 / 11.1 / 10.35 | 1.55 / 1.63 / 1.77 | 21.3 / 20.9 / – | 18.5 / 16.9 / 16.7 |
| kept + PGO, 2 rounds | 11.5 / 11.3 | 1.56 / 1.63 | 21.7 / – | 18.9 / 18.0 |

("–": the speed test answered with HTTP 429 after many downloads.)

The same build varies by up to ~9 % between rounds, so the builds are **not separable end to end**. The
micro-benchmark gains are real but do not show at this level, because crypto is now a small part of the work.

## Where tailscaled spends its CPU (90 s profile under the same traffic)

`tailscale debug --cpu-profile`, kept build, alternating DERP download, direct download and upload.
tailscaled used on average 1.6 of the 4 hardware threads.

| | share of tailscaled CPU |
|---|---|
| system calls (TUN `writev` alone: 21 %) | 25 % |
| ChaCha20 + Poly1305 (all callers) | ~8 % |
| samples lost inside emulated 64-bit atomics (`runtime._LostSIGPROFDuringAtomic64`) | 6 % |
| malloc | 1.3 % |
| GC mark | 0.3 % |

- TUN offload is active (TSO/GSO/GRO on the `tailscale0` device), so there is nothing to switch on there.
- GL's init script sets `GOGC=40` / `GOMEMLIMIT=35MiB` when MemTotal is below 128 MB (this router: 117 MB). GC and allocation cost
  under 2 % of tailscaled's CPU, so tuning these cannot give a measurable gain; left as is.

## PGO

The build pipeline uses this profile (`pgo/2026-11-16_A_mixed90s.pprof`) for profile-guided optimization by
default (`--no-pgo` turns it off; baseline builds never use it, so they still reproduce admonstrator's release
byte for byte). The PGO build looked a little better in every comparison above (DERP 11.5 / 11.3 vs 11.3 /
11.1 / 10.35 Mbit/s), but a closer look (next section) puts the gain at about 0–1 %: harmless, kept as the
default, but not a measurable improvement. The binary is 65 KB smaller (27,001,023 vs 27,066,559 bytes).

## Follow-up (2026-11-17): where the round-to-round spread comes from

DERP download only, warm-up run discarded, builds interleaved (each segment = install + restart, then 4 runs):

- Within one running process, runs agree to about 1 % (10 back-to-back runs: 10.0 Mbit/s ± 0.5 %).
- In every measurement on both days, Mbit/s × CPU-s/MB ≈ 18: tailscaled always uses about 2.25 CPUs. The
  DERP path is CPU-bound; throughput is that CPU budget divided by the CPU cost per MB.
- The CPU cost per MB is fixed for the life of a tailscaled process but differs from one start to the next
  (1.53–1.80 CPU-s/MB across all starts in these sessions, independent of the build). That is the whole
  spread. A later check with plain restarts of the same binary (no binary swap in between) stayed within
  1.60–1.68; the expensive starts all came right after a new binary had been installed.
- Compared at a similar cost level, PGO and the plain build differ by about 0–1 %.

| segment | build | Mbit/s | CPU-s/MB |
|---|---|---|---|
| 1 | plain | 9.99 | 1.80 |
| 2 | PGO | 10.90 | 1.66 |
| 3 | plain | 10.92 | 1.66 |
| 4 | PGO | 10.84 | 1.65 |
| 5 | plain | 10.20 | 1.78 |
| 6 | PGO | 10.98 | 1.62 |

The "lost samples inside emulated 64-bit atomics" bucket above (6 %) is Go's single process-wide spinlock for
64-bit atomic operations on 32-bit MIPS (no 64-bit LL/SC): on this CPU one such operation costs ~265 ns, and
operations on unrelated variables from different threads serialize on that one lock.

The PGO build measured here: `1.104.7-tiny.mipsle-chacha.2a-pgo`, sha256
`9cccfa2a100caba53b4b62edc0f6328fa2287ace128f23f864a5eb6e35b112eb`, reproducible with
`scripts/build-tailscaled.sh --no-goroot-patch --no-tailscaled-overlay --suffix -tiny.mipsle-chacha.2a-pgo
--variant chacha2a-pgo` (from the same checkout path, see README, and with the repository as it was on that date:
later builds add `overlay/tailscaled/`, `overlay/goroot/` and `overlay/patches/` by default, use another PGO profile
and a different ChaCha20 file).
