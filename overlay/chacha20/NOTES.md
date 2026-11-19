# ChaCha20 for GOARCH=mipsle (MIPS32r2, MT7621 / 1004Kc)

Files: `chacha_mipsle.go`, `chacha_mipsle.s`, `chacha_mipsle_test.go` for
`golang.org/x/crypto/chacha20` v0.58.0 (also drop-in for the Go stdlib copy in
`src/vendor/golang.org/x/crypto/chacha20`; its `chacha_generic.go` is identical
to v0.58.0). Build tags: `gc && !purego`, plus the `_mipsle` file suffix.
`chacha_noasm.go` needs the constraint transform
`//go:build (<original>) && (!mipsle || !gc || purego)`.

## Design
- One 64-byte block at a time, all 16 state words in registers, `ROTR`
  (MIPS32r2) for each rotation, so a quarter round is 12 instructions.
  Requires a MIPS32r2 CPU: Go's mipsle baseline is MIPS32r1 and the build
  constraint (`gc && !purego`, `_mipsle`) cannot tell r1 from r2, so on an r1
  core this code would raise SIGILL. (The Poly1305 assembly is MIPS32r1-only.)
- **Compact on purpose (since 2026-11-19).** The 10 double rounds are a loop
  (96 instructions plus 3 for the loop), there is no per-call precompute and
  no stack frame: 1368 bytes of code instead of 4920. A call touches 29
  instruction-cache lines (aligned) or 34 (unaligned) instead of 140 / 145.
  It executes 1104 / 1138 instructions per block instead of 1034 / 1068
  (+6.8 %) and 11 per call instead of 78. See "Why compact" below.
- One round body serves both the aligned and the unaligned path. The path is
  picked per call (`(src|dst)&3`) and only the feed-forward differs: `LW/SW`
  vs `LWR/LWL` + `SWR/SWL`.
- The asm does not use `Cipher.p1..p15`/`precompDone`, so it only depends on
  the key/counter/nonce layout.
- Feed-forward ordering (2026-11-16): the two constant words are handled in
  pairs with both loads first, and on the unaligned path no LWL directly
  follows the LWR into the same register (measured to stall on the 1004Kc);
  every loaded word is used at least one instruction later.
- The quarter rounds are 960 of the 1104 instructions per block (12 per QR
  with ROTR, the minimum on MIPS32r2); the CPU runs them at close to one
  instruction per cycle.

### Why compact
The MT7621 has a 32 KB instruction cache (and 256 KB of L2 shared by both
cores), and the path of one packet through the kernel and tailscaled is far
larger. When a message's first ChaCha20 block starts, the cipher's code is in
neither cache. Three independent measurements:
- A CPU profile of tailscaled under load, split by the call site in
  `chacha_generic.go`: for the call that produces the first block of every
  message (the Poly1305 key block), 84-88 % of the samples sit on the first
  instruction of a 32-byte cache line; in the loop over the following blocks
  17-21 % (an even spread would be 12.5 %). With the unrolled code that first
  block took ~22 us, as long as 14 of the following blocks.
- A benchmark on the device that evicts the caches before every single
  operation (`bench/cold`): the key block costs
  51.7 us with the unrolled code and 34.6 us with the loop; 111 fewer lines
  save 17.0 us, i.e. ~153 ns per line - the time of about 135 instructions.
- Counting lines and instructions of whole seal/open operations in an
  interpreter (`sim/`) and applying "155 ns per line + one cycle per instruction"
  reproduces the device's cold timings within ~1 % for eight cases.
So per message the unrolled form saved 70 instructions per block and paid
about 110 extra line fetches: for a 1280-byte packet (21 blocks) -1,500
instructions against +17 us, which is worth about 15,000 instructions.
Warm micro-benchmarks show the opposite sign (see Benchmarks); they measure a
state the router is never in between two packets.

### Register map
| Reg | Use |
|---|---|
| R1..R16 | x0..x15 |
| R17 | dst |
| R18 | src |
| R19 | src end |
| R20 | `&Cipher.key` (key 0..28, counter 32, nonce 36..44) |
| R25 | non-zero = unaligned path |
| R21, R24 | temps; R24 also counts the double rounds |
R22 (REGCTXT), R26..R28, R30 and R31 are not touched; R29 (SP) is not moved (no frame).
R23 (REGTMP) is clobbered by the assembler, which loads the 32-bit constants of
`ADDU $const` into it (LUI/ORI).

### bufSize
`bufSize = blockSize` (64). There is no multi-block SIMD path, so a bigger
buffer would only waste key stream: 1420-byte packets need 23 blocks with 64,
24 with 256.

### Counter
- The asm increments `Cipher.counter` by one per block, wrapping mod 2^32 like
  `s.counter += 1` in the generic code. `XORKeyStream` already panics before a
  real overflow and sets `overflow` for the last block.
- With `bufSize == 64`, the "multi-block would overflow" fallback in
  `XORKeyStream` never triggers.
- The Go glue checks that the lengths match and are multiples of 64, and skips
  the call when the length is 0.
- Compile-time asserts in `chacha_mipsle.go` pin `counter` at offset 32 and
  `nonce` at offset 36 from `key`.

## Tests (run on the GL-MG1300, Go 1.27.4)
```
cd work/xcrypto   # env: GOOS=linux GOARCH=mipsle GOMIPS=softfloat CGO_ENABLED=0
go test -c -o chacha.test ./chacha20
go test -c -o aead.test ./chacha20poly1305
# on device: ./chacha.test -test.v ; ./aead.test -test.v
# benchmarks: ./chacha.test -test.run XXX -test.bench ChaCha20
go test -c -tags purego ...    # generic path still builds and passes
```
`chacha_mipsle_test.go` adds three tests:
- Direct asm vs generic over 3000 cases: 0–69 blocks, src/dst offsets 0–7,
  in-place, counters wrapping mod 2^32, guard bytes around dst, src left unchanged.
- Public `XORKeyStream` vs generic over 3000 cases: 0–4200 bytes, random chunking,
  offsets, in-place, 12- and 24-byte nonces, counters 0, random, or just below 2^32.
- The last block before counter overflow; then one more byte, which must panic when the counter is
  exhausted (length a multiple of 64) and otherwise must come from the leftover key stream and match the
  generic stream (extended 2026-11-17, run on the device).

Results (2026-11-16):
- chacha20: 10/10 tests pass. chacha20poly1305: 3/3 pass.
- With `-tags purego`: chacha20 7/7 and chacha20poly1305 3/3 pass on the device.
- Host (windows/amd64) `go test ./chacha20`: ok.
- `go vet` cross builds pass for mips, mips64le, arm, arm64, 386, ppc64le,
  s390x, loong64, riscv64.
- The stdlib vendored copy builds via `-overlay`, together with `crypto/tls`.

## Benchmarks (1 thread, 1420-byte packets, new cipher per packet)
| | pure Go | asm |
|---|---|---|
| chacha20 only | 76.0 Mbit/s | 382–388 Mbit/s (~5.0x) |
| chacha20 only, unaligned buffer | 76.8 | ~369 |
| chacha20poly1305 seal (pure-Go poly1305) | 48.7 | ~106 |

A first version with a rolled round loop and no precompute reached ~362–367 Mbit/s
(warm); that is the form used again since 2026-11-19.

Cold and warm, 2026-11-19 (ns per operation, median of 300, 3 interleaved runs;
cold = caches evicted before each operation; unrolled = the code used until then):
| case | cold unrolled | cold loop | warm unrolled | warm loop |
|---|---|---|---|---|
| new cipher + 32 bytes (key block) | 51,658 | 34,633 (-33 %) | 5,349 | 5,114 |
| new cipher + 1280 bytes, aligned | 60,750 | 45,273 (-25 %) | 24,695 | 26,547 (+7.5 %) |
| new cipher + 1344 bytes at offset 5 | 63,624 | 48,266 (-24 %) | 26,858 | 28,694 (+6.8 %) |
| open 1280 bytes, WireGuard layout | 94,146 | 78,587 (-16.5 %) | 35,856 | 38,791 |
| open 1350 bytes, TLS layout | 104,231 | 89,111 (-14.5 %) | 41,609 | 42,826 |
| seal 64 bytes | 64,344 | 47,059 (-27 %) | 6,628 | 6,696 |
The loop was faster in 3 of 3 runs in every cold case (ranges +-0.3 %).
`BenchmarkChaCha20/4096`: 52.5 MB/s (~1220 ns per block).
The seal figure uses the unmodified pure-Go poly1305, which now dominates;
OpenSSL's ChaCha20-Poly1305 does 213 Mbit/s.
Benchmark numbers vary by roughly ±3% between runs, and one run dropped to
~250 Mbit/s, probably because of other load on the device.

## Considered, not kept
All of these were judged with warm micro-benchmarks on 2026-11-16. They were
rejected for small or unmeasurable gains; with the cost of cold code known
(see "Why compact"), each of them would also lose because it adds code.
- **Fully unrolled rounds with the first column round of columns 1..3
  precomputed per call** (the form used until 2026-11-19): 6.4 % fewer
  instructions per block, 3.6 times the code. Faster only when the code is
  already in the cache.
- **Two separate loops, counter in R25, constants and C0+key[0] on the stack** (the sweep's "B"):
  1023/1055 instructions per block instead of 1034/1068, and in micro-benchmarks 1.4 % / 2.4 % faster
  (streaming) and 0.5–1 % on seal/open; against the kept version (single loop with the feed-forward
  reorder) only ~1 %. Installed in tailscaled and measured end to end (`results/2026-11-17_sweep-e2e-pgo.md`): 10.7–10.9 Mbit/s on
  DERP vs 10.35–11.3 for the kept version, i.e. not separable. Not kept: no measurable end-to-end benefit
  for twice the code (4.9 → 8.7 KB; on the DERP path both loops are hot for every packet).
- **Cache the first round in `Cipher.p1..p15` + 4 more precomputed diagonal-round steps**:
  built and verified (all tests plus a cache test and two mutants on the device), 1019/1051 instructions per
  block. A/B vs the two-loop version above (then committed), interleaved: ChaCha20 streaming with one reused cipher −1.7 % aligned
  (8/8 pairs), but seal/open of 1420-byte packets ±0.5 % (4–7 of 12 pairs faster), 64-byte open −1.0 %
  (12/12), 64-byte seal unchanged; an unchanged Poly1305 control drifted by 2 % in the same runs. The AEAD
  creates a new Cipher per packet, so the cache only helps within one packet's three calls. Not consistently
  faster on the paths Tailscale uses, and it would tie the asm to 13 more field offsets: rejected.
- **Hand-encoded branches to fill delay slots:** ~0.1 %, offsets must be recomputed by hand after every edit.
- **The two-loop version using R22/R28 as extra registers:** same gain as the two-loop version, more risk.
