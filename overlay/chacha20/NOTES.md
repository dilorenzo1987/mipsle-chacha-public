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
- The 10 double rounds are fully unrolled; one round body serves both the
  aligned and the unaligned path. The path is picked per call
  (`(src|dst)&3`) and only the feed-forward differs: `LW/SW` vs
  `LWR/LWL` + `SWR/SWL`.
- The 3 counter-independent quarter rounds of the first column round are
  computed once per call and kept in a 48-byte stack frame (the asm does not
  use `Cipher.p1..p15`/`precompDone`, so it only depends on the
  key/counter/nonce layout).
- About 1030 instructions per block; measured ~1070 cycles per block on
  4 KB inputs, i.e. close to 1 instruction per cycle. The rest is mostly
  adds/xors/rotates, so there is little left to gain by rescheduling.

### Register map
| Reg | Use |
|---|---|
| R1..R16 | x0..x15 |
| R17 | dst |
| R18 | src |
| R19 | src end |
| R20 | `&Cipher.key` (key 0..28, counter 32, nonce 36..44) |
| R25 | non-zero = unaligned path |
| R21, R24 | temps |
R22, R23 (REGTMP, used by the assembler for 32-bit constants in `ADDU $const`),
and R26..R31 are not touched.

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
- The last block before counter overflow, then the panic.

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

A first version with a rolled round loop and no precompute reached ~362–367 Mbit/s.
`BenchmarkChaCha20/4096`: 52.5 MB/s (~1220 ns per block).
The seal figure uses the unmodified pure-Go poly1305, which now dominates;
OpenSSL's ChaCha20-Poly1305 does 213 Mbit/s.
Benchmark numbers vary by roughly ±3% between runs, and one run dropped to
~250 Mbit/s, probably because of other load on the device.
