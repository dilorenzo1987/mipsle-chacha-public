# Results: code that fits the instruction cache, GL-MG1300 (Mango 2), 2026-11-19

Device: MediaTek MT7621 (MIPS 1004Kc, 2 cores x 2 hardware threads, 880 MHz). Each core has a 32 KB instruction
cache with 32-byte lines; both share 256 KB of second-level cache. GL firmware 4.10.1, tailscaled 1.104.7 "tiny",
Go 1.27.4.

Short version: on this router a packet's encryption code is not in the instruction cache when the operation
starts, and fetching one 32-byte line of code from memory takes about 155 ns - as long as executing about 135
instructions. So the number of cache lines an operation touches matters more than the number of instructions
it executes. Rewriting the crypto path to be compact (about 85 lines per seal/open instead of 340-400) cut
tailscaled's CPU time per megabyte over a DERP relay by 14.5 % and raised the throughput from 12.1 to
14.0 Mbit/s. Warm micro-benchmarks do not show this; some of them show the opposite sign.

Builds compared. They have the same Tailscale source, tags, flags, PGO profile, runtime patch and source
patches and differ only in the crypto code:

| name | crypto code | built with |
|---|---|---|
| `.4` | ChaCha20 with fully unrolled rounds and Poly1305 in assembly, joined by x/crypto's generic Go code | the overlay as it was before this change |
| `.5` | as `.4`, but ChaCha20 with the ten double rounds as a loop ("compact") | `scripts/build-tailscaled.sh --no-aead` |
| `.6` | `.5` plus the whole seal/open in one assembly routine (`overlay/chacha20poly1305/`) | `scripts/build-tailscaled.sh` (default) |

## 1. Where the time went: waiting for code

A CPU profile records the address of the interrupted instruction. In code that runs from a warm cache these
addresses are spread evenly over the eight instructions of a 32-byte line (12.5 % each). When a line has to be
fetched from memory, the processor waits at the first instruction it executes in that line, so samples pile up
at addresses that are a multiple of 32. `scripts/icache-stall.py <profile>` estimates the waiting share from that
(a lower bound; kernel time and data-cache misses are not covered).

The ChaCha20 assembly of `.4`, split by its two call sites in x/crypto's `chacha_generic.go` (75 s profile of
tailscaled under relay load, 146.8 CPU-s in total):

| x/crypto copy | call site | CPU-s | samples at a line start | estimated wait |
|---|---|---|---|---|
| WireGuard | loop over full blocks | 2.78 | 17.3 % | 0.15 s |
| WireGuard | single block (the Poly1305 key block that starts every message) | 2.79 | 88.2 % | 2.41 s |
| TLS (Go's vendored copy) | loop over full blocks | 3.32 | 21.1 % | 0.33 s |
| TLS (Go's vendored copy) | single block | 2.40 | 84.2 % | 1.97 s |

Same machine code at the same addresses; only the call site differs. The single block - the first ChaCha20 code
a message runs - took as long as the 20 blocks that follow it (about 22 us against about 1.6 us per block): it
pays for fetching the routine's 140 cache lines. That is main-memory speed, so the code is in neither cache when
the next packet arrives. The same pattern showed in four profiles of four different builds.

For the whole process the estimate is that tailscaled waited at least 22.6 % of its CPU time for instruction-cache
misses in user code (`.4`, same profile).

## 2. What one line costs: benchmark with cold caches

`bench/cold` evicts the instruction cache and the second-level cache before every single operation, touches the
operation's own buffers again and then times exactly one operation. ns per operation, median of 300, three
interleaved runs per comparison (`scripts/bench-ab.sh --bench cold`); every value contains about 6,500 ns of
measurement overhead (the "empty" case). The `.4` and `.6` columns are from one interleaved run; the `.5` column
is from two other runs of the same day, in which the `.4` values agreed with these to within 0.2 % and the `.6`
values to within about 2 %.

| operation, caches cold | `.4` code | `.5` code | `.6` code | `.6` against `.4` |
|---|---|---|---|---|
| ChaCha20: new cipher + 32 bytes (key block) | 51,754 | 34,633 | 34,208 | -33.9 % |
| ChaCha20: new cipher + 1280 bytes | 60,816 | 45,273 | 45,198 | -25.7 % |
| Poly1305, 1280 bytes (unchanged code) | 26,001 | 26,107 | 25,552 | -1.7 % |
| open 1280 bytes, WireGuard layout | 93,979 | 78,600 | 55,023 | -41.5 % |
| open 1350 bytes, TLS layout | 104,081 | 88,988 | 60,160 | -42.2 % |
| seal 64 bytes, WireGuard layout (a TCP ACK) | 64,231 | 47,063 | 24,096 | -62.5 % |
| seal 134 bytes, TLS layout (the ACK inside a relay frame) | 73,610 | 56,714 | 28,612 | -61.1 % |

The same operations called back to back (warm), `.4` -> `.6`: open 1280 bytes 35,372 -> 34,248; open 1350 bytes
41,407 -> 38,602; seal 64 bytes 6,692 -> 3,781; seal 134 bytes 11,409 -> 7,308. ChaCha20 alone is about 7 %
slower warm in the compact form (1344 bytes at offset 5: 27,045 -> 28,872): the loop executes 6.8 % more
instructions per block. In the cold case, which is the one that happens in real traffic, it is 24-34 % faster.

Cost of a line: the key block got 17.5 us cheaper with 111 fewer lines, about 155 ns per line.

## 3. Lines and instructions per operation

Counted by running the Seal/Open functions of the complete tailscaled binaries in an interpreter
(`sim/aead_ops.py <binary>`; every result is checked against a reference implementation). Instructions executed /
distinct instruction-cache lines touched:

| operation | `.4` | `.5` | `.6` |
|---|---|---|---|
| WireGuard open, 1280 bytes | 29,594 / 338 | 30,930 / 227 | 29,227 / 83 |
| TLS open, 1350 bytes | 34,302 / 380 | 35,711 / 269 | 32,806 / 92 |
| WireGuard seal, 64 bytes | 4,883 / 338 | 4,889 / 227 | 2,983 / 82 |
| TLS seal, 134 bytes | 8,663 / 395 | 8,742 / 284 | 5,916 / 88 |
| model: crypto per data packet, cold | 243 us | 196 us | 114 us |
| model: crypto per data packet, warm | 80 us | 83 us | 75 us |

Model: every line fetched once at 155 ns, plus one cycle per instruction at 880 MHz; a data packet = one WireGuard
open, one TLS open and 0.46 small seals of each kind (the measured share of ACKs). In `.4`, 182-216 of the lines
per operation were not the ciphers but the Go code around them (cipher setup, buffering of the key block, padding,
MAC finalisation in emulated 64-bit arithmetic, `memmove`). For the benchmark binaries of section 2 the model
reproduces the measured cold cost to within about 1 % (`.4`, `.5`) and 2-5 % (`.6`).

In real traffic the Go code is less cold than in the benchmark (the profile of `.4` shows about 1.3-1.5 times
less time in it than the model predicts), so the model overstates what removing it saves.

## 4. End to end over a DERP relay

Router at home on Wi-Fi; download server = a host in the same tailnet that the router reached only through a
custom DERP relay (TLS 1.3 with ChaCha20-Poly1305), checked with `tailscale ping` before the session. Nine blocks
in the order `.6 .4 .5 | .4 .5 .6 | .5 .6 .4` (each build once in each position). Per block: install the build,
then two plain restarts with three 30 MB downloads each, and one 60 s CPU profile under the same load. CPU time
of the tailscaled process from `/proc`. All 54 downloads were limited by the router's CPU (11.5-14.9 Mbit/s); the
server's load was logged and stayed low.

Rule, written down before the first run: X beats Y if its mean CPU-s/MB over its six restarts is at least 2 %
lower, it is lower in at least two of the three rounds, and the profiles agree.

| build | CPU-s/MB per block (round 1, 2, 3) | mean of 6 restarts | range | Mbit/s, mean (range of the restarts) |
|---|---|---|---|---|
| `.4` | 1.521, 1.519, 1.422 | 1.487 | 1.417-1.557 | 12.1 (11.6-12.8) |
| `.5` | 1.482, 1.329, 1.281 | 1.364 (-8.3 %) | 1.240-1.494 | 13.0 (12.0-14.0) |
| `.6` | 1.397, 1.200, 1.221 | 1.272 (-14.5 %) | 1.173-1.431 | 14.0 (12.7-14.8) |

`.6` is cheaper than `.5` (-6.7 %) and `.5` cheaper than `.4` in every round, so by the rule `.6` beats both.

The nine profiles, CPU-seconds per MB received while the profile ran (as recorded by the profiler, which captures
80-83 % of the CPU time `/proc` reports, for all three builds alike):

| build | crypto (assembly, x/crypto Go code, byte-order helpers), per block | mean | everything else, mean | user samples at a line start |
|---|---|---|---|---|
| `.4` | 0.134, 0.167, 0.146 | 0.149 | 1.042 | 27.0-28.7 % |
| `.5` | 0.145, 0.127, 0.128 | 0.133 | 1.007 | 24.3-26.1 % |
| `.6` | 0.098, 0.101, 0.099 | 0.099 | 0.944 | 22.3-23.9 % |

- Crypto per MB: -11 % (`.5`) and -33 % (`.6`) against `.4`. Estimated wait for instruction-cache misses in user
  code (round 3 profiles): 21.5 %, 17.2 % and 16.0 % of the profiled CPU time.
- Only about a third of the gain is crypto getting cheaper (0.050 of the 0.148 CPU-s/MB between `.4` and `.6` in
  the profiles). The larger part is that everything else got cheaper too. A possible explanation is that the
  caches are shared: about 800 fewer lines of crypto code per data packet (by the counts of section 3) leave more
  of the rest of the packet path in the caches. This is a hypothesis; it has not been tested.
- Limits: one session on one day, three installs per build. The level of one build differs between installs
  (`.5`: 1.48 against 1.28; round 1 was the most expensive round for every build). The order of the builds is the
  same in all rounds, but the size of the gain is uncertain by roughly +-5 percentage points.

Direct path (exit node over direct UDP, download from and upload to a public speed test), two runs each on `.6`
after the session: 22.7 / 23.5 Mbit/s down, 21.0 / 20.2 up. Not an A/B; two days earlier `.4` reached
21.3 / 21.0 down and 15.8 / 17.9 up.

## 5. Warm micro-benchmark, for completeness

`bench/main.go`, 1420-byte packets, pure Go and the current overlay run alternately twice on 2026-11-19:

| | pure Go | assembly (`.6` code) |
|---|---|---|
| ChaCha20-Poly1305 seal, 1 thread | 49.5 Mbit/s | 286 Mbit/s |
| ChaCha20-Poly1305 open, 1 thread | 49.1 Mbit/s | 286 Mbit/s |
| ChaCha20 only | 76.5 Mbit/s | 362 Mbit/s |
| Poly1305 only | 156 Mbit/s | 1348 Mbit/s |
| ChaCha20-Poly1305 seal, 4 threads | 107 Mbit/s | 562 Mbit/s |

The first version (2026-11-16) measured 265 Mbit/s for seal and 384 Mbit/s for ChaCha20 alone: the compact
ChaCha20 is slower in this benchmark, the whole seal faster.

## 6. The two steps before this one (2026-11-17)

Both measured over the same kind of relay path, with builds alternating in blocks of plain restarts:

| step | Mbit/s | CPU-s/MB |
|---|---|---|
| 3 Go threads instead of 4 (`overlay/tailscaled/`) | +5.1 % | -3.9 % |
| + lock striping for 64-bit atomics (`overlay/goroot/`) | +8.8 % in total | -7.4 % in total |
| + fewer barriers in those locks, Poly1305 `Sum` without the state copy, two source patches (`overlay/patches/`), merged PGO profile (this is `.4`) | +3.7 % | -3.1 % |

For the last row the rule "at least 2 % and cheaper in most restarts" was only half met (cheaper in 3 of 4
neighbouring block pairs, but only 4 of 8 restarts below the other build's median); a profile showed each change
in place (per-frame `SetReadDeadline` 1.45 % of the CPU -> gone, map iteration in wireguard-go's batch loops
3.32 % -> 0.22 %).

From the community tiny build (unpacked) to `.6`, relay download: 7.2 Mbit/s (2026-11-16) -> 14.0 Mbit/s
(2026-11-19). The two values come from different days and different download servers; the steps in between were
each measured within one session (+56 %, +8.8 %, +3.7 %, +15 %) and multiply to a factor of 2.0. For orientation:
GL.iNet's stock Tailscale binary (1.92.5, firmware 4.10.1) reached about 3-4 Mbit/s through a relay in the
author's use; that was not measured in these sessions.

## 7. Reproduce

```sh
bash scripts/build-tailscaled.sh                      # .6 -> build/tailscaled-mipsle-chacha
bash scripts/build-tailscaled.sh --no-aead --variant chacha-noaead    # .5
python3 scripts/icache-stall.py <cpu-profile.pprof>   # profile from `tailscale debug --cpu-profile`
python3 sim/aead_ops.py build/tailscaled-mipsle-chacha --detail
python3 sim/chacha_check.py overlay/chacha20/chacha_mipsle.s
python3 sim/aead_check.py overlay/chacha20poly1305/chacha20poly1305_mipsle.s
bash scripts/bench-ab.sh --bench cold --pairs 3 <older revision> worktree     # needs a device, see the script
```

The measured `.6` binary has sha256 `9ea41b49f6fff874dc27770c7e13392123a585786e1886af9c2dd5de7e344db7` and
`.5` `df90faac77558eaa2d244d0ffc74d0ff885a996472e81a05a4ccce9a7585617e` (suffixes `-tiny.mipsle-chacha.6` and
`.5`). Overlay builds embed the absolute path of the checkout, so other checkout paths give other hashes
(see README).
