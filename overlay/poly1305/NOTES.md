# Poly1305 for GOARCH=mipsle (MIPS32r2, MT7621 / 1004Kc)

Files (for `golang.org/x/crypto/internal/poly1305` v0.58.0 and the Go stdlib
vendored copy `src/vendor/golang.org/x/crypto/internal/poly1305`):

- `sum_mipsle.go`: glue, `//go:build gc && !purego` (+ the `_mipsle` file suffix).
  It declares `updateBlocks` (asm), a Go `update(state, msg)` with the same
  semantics as `updateGeneric`, and `mac` with Write/Sum mirroring `sum_asm.go`.
  It uses no imports, so it also builds in the stdlib vendor tree.
- `sum_mipsle.s`: `func updateBlocks(state *macState, msg []byte, padbit uint32)`.
- `sum_mipsle_test.go`: differential tests (`//go:build gc && !purego`).
  **x/crypto only.** It uses `stressFlag` and `unalignBytes` from x/crypto's
  `poly1305_test.go`. Don't copy it into the stdlib vendor tree, which has no
  test files.
- Required change to `mac_noasm.go` (both trees), and nothing else:
  `//go:build (<original>) && (!mipsle || !gc || purego)`.
  `sum_asm.go` is not modified.

## Design

**Radix 2^32, in place.** On mipsle, `macState.h [3]uint64` is already five
little-endian 32-bit words h0..h4 (byte offsets 0..16; the word at offset 20,
the high half of h[2], is always 0) and `r [2]uint64` is r0..r3 at offsets
24..36. No conversion needed, and `finalize` (generic Go) is shared.
`s` is not touched.

Clamping gives r0 < 2^28 and r1..r3 < 2^28 with the low 2 bits clear, so
s_i = r_i + (r_i >> 2) = 5*r_i/4 exactly (i = 1..3). Since 2^130 = 5 (mod p),
2^128 = 5/4 (mod p), so a product h_i*r_j*2^(32(i+j)) with i+j >= 4 equals
h_i*s_j*2^(32(i+j-4)) mod p:

    d0 = h0*r0 + h1*s3 + h2*s2 + h3*s1
    d1 = h0*r1 + h1*r0 + h2*s3 + h3*s2 + h4*s1
    d2 = h0*r2 + h1*r1 + h2*r0 + h3*s3 + h4*s2
    d3 = h0*r3 + h1*r2 + h2*r1 + h3*r0 + h4*s3
    d4 = h4*r0

That is 19 32x32->64 products (MULTU + MADDU into HI:LO) plus one 32-bit MUL
(h4*r0) per 16-byte block. Carries are propagated d0 -> d1 -> d2 -> d3 -> d4
(d_{i+1} += d_i >> 32) **inside the accumulator**: the HI word of column i is
added to column i+1 as one more product, `MADDU hi, 1` (R21 = 1), so the LO
of each column is already the final limb and no ALU carry chain is needed.
d4 = HI(column 3) + h4*r0. The part of d4 above 2^130 is folded back:
c5 = 5*(d4>>2) = (d4 & ~3) + (d4 >> 2), h4 = d4 & 3.

**Lazy fold.** Neither the fold nor c5 is applied at the end of a block. d4 is
left as R24 (HI of column 3) + R25 (h4*r0); the next block starts with the
fold (`FOLD`) and adds c5 together with the message block (h + c5 + m, with
per-limb carries of up to 2). The value entering each multiplication is
exactly what a full propagation would give, so the bounds below are
unchanged. After the loop the pending d4 is folded and c5 propagated once.
On entry R24 = 0 and R25 = the stored h4, so the first in-loop fold turns the
bits of the stored h above 2^130 into the initial c5 (c5 = 5*(h4>>2),
h4 &= 3), exactly what the separate entry pre-fold of the previous version did.

The same approach (radix 2^32 with MULTU/MADDU, s_i = 5*r_i/4, carries added
with `maddu hi, 1`) is used by OpenSSL's `poly1305-mips.pl` (32-bit path). It
inspired this code, which was written from scratch for the Go assembler.

**Scheduling** (timings measured with probe loops on the MT7621, 2026-11-16):
MADDU issues every cycle; MFLO/MFHI/MUL results stall the next ~4
instructions; MFLO right after a MADDU costs ~1 cycle; an LWL right after the
LWR into the same register stalls; no difference was observed between a
zero and a random key (no sign of an operand-dependent early-out). The
block keeps every MFHI/MFLO result at least 5 instructions away from its use,
puts the MUL where HI/LO are dead (MUL leaves HI/LO unpredictable before
MIPS32r6), and loads unaligned words as 4 x LWR then 4 x LWL.

**MADDU.** The Go mips assembler only knows the signed `MADD`, so `MADDU rs, rt`
is emitted as `WORD $(0x70000001 | rs<<21 | rt<<16)`. The Go mips backend never
reorders instructions (`nosched` is always true; each branch delay slot gets a
NOP), and `WORD` is a scheduling barrier anyway. MIPS32 cores interlock
HI/LO, so no hazard NOPs are needed.

**Unaligned input.** Two loops: aligned (`LW`) and unaligned (4 x `LWR` then
4 x `LWL`, `MOVWR`/`MOVWL` in Go syntax), selected once per call by `msg & 3`.

**Partial final block.** This is handled in Go (`update`): copy into a zeroed
16-byte buffer, append 0x01, and call `updateBlocks(..., padbit=0)`.
Full blocks use padbit=1 (adds 2^128).

**Constant time (what was checked).** No branches or memory addresses depend
on secrets. Carries use SGTU. Branches depend only on length and alignment.
Multiplier timing: a zero key and a random key benchmark identically on the
MT7621 (2026-11-16), so there is no sign of an early-out for narrow
operands; that one comparison is not a proof of constant-time multiplies.
Go's generic code on this core also ends up in 32x32 MULTU, so it has the
same exposure.

### Register map

| Reg | Use |
|---|---|
| R1 | padbit |
| R2 / R3 | msg pointer / end |
| R4..R8 | h0..h4 |
| R9..R12 | r0..r3 |
| R13..R15 | s1..s3 |
| R16..R19 | message words, then h + c5 + m (the multiplication inputs) |
| R20 | carry temporary (and the state pointer in the prologue) |
| R21 | constant 1 (for `MADDU hi, 1`) |
| R24 | HI of the previous column (carry-in); temporary in the fold |
| R25 | h4*r0 -> d4 -> c5; with R24 the pending d4 carried across iterations |

Not used: R22 (REGCTXT), R23 (REGTMP; no instruction expands to a sequence
that uses it), R26/R27, R28 (SB), R29 (SP), R30 (g), R31 (LR). Leaf function,
NOSPLIT, frame $0-20.

## Bound argument (carry/reduction correctness)

Notation: all h_i < 2^32 as registers; p = 2^130 - 5.

1. **Entry.** The macState invariant (shared with the generic code) is h < 2p
   < 2^131, so h4 <= 7 and the word at offset 20 is 0. The prologue sets
   R24 = 0 and R25 = h4, so the first in-loop fold computes d4 = h4,
   c5 = 5*(h4>>2) <= 5 and h4 = h4 & 3 <= 3. The value is unchanged mod p.

2. **Loop invariant at block start.** low = h0 + ... + h4*2^128 < 2^130
   (h4 <= 3), and c5 < 2^32 (shown in step 5). This holds on entry by step 1.

3. **Add.** h' = low + c5 + m + padbit*2^128 < 2^130 + 2^32 + 2^128 + 2^128
   < 7*2^128, so **h4' <= 6**. Carries: limb 0 sums two adds (carry <= 2);
   limb i >= 1 computes h_i + m_i + c with c <= 2, giving at most one wrap in
   each of the two adds, so the outgoing carry is <= 2. The carry is detected
   as `x > result`, which is exact because the addend is < 2^32.

4. **Multiply.** Each product h_i*r_j < 2^32 * 2^28 = 2^60, and
   h_i*s_j < 2^32 * 1.25*2^28. Per column (at most 4 full-width products plus
   h4*s_j <= 6*1.25*2^28): d0 < 4.75*2^60, d1 < 4.5*2^60 + 2^32, and so on.
   All are < 2^63, so the 64-bit HI:LO accumulator never overflows. Carry-ins
   d_i>>32 < 2^31 keep each column < 2^63. The carry-in is added inside the
   accumulator as the product hi*1 (`MADDU R24, R21`), so the same bound
   covers it and the high word cannot overflow.

5. **d4 and fold.** d3 < 4*(2^32-1)*(2^28-1) + 6*1.25*2^28 + 2^31 < 2^62, so
   d3>>32 < 2^30. With h4' <= 6 and r0 < 2^28, d4 = h4'*r0 + (d3>>32)
   < 6*2^28 + 4*2^28 = 10*2^28 < 2^32 (no 32-bit overflow).
   c5 = (d4 & ~3) + (d4>>2) <= 1.25*d4 < 12.5*2^28 < 2^32 (no overflow).
   The new low part is h4 = d4 & 3 <= 3, so low < 2^130. The invariant from
   step 2 holds again. (The fold runs at the start of the next block or on
   exit rather than at the end of this one; d4 = R24 + R25 is the same number
   either way, and nothing reads h4 or c5 in between.)
   Without the entry pre-fold, h4' could reach 9 (h = 2p-1 plus an all-0xff
   block). Then d4 < 13*2^28 and c5 could reach about 16.25*2^28 > 2^32. The
   entry pre-fold (now the first in-loop fold, from R24 = 0 and R25 = stored
   h4) exists to rule that out. The first version handled it
   with an explicit carry, and `TestMipsleWorstCase` covers exactly this case.

6. **Exit.** The pending d4 is folded (step 5), then h = low + c5 is
   propagated with a carry chain, giving
   h4 <= 3 + 1 = 4. So h < 5*2^128 < 2p, which satisfies finalize's
   precondition. The word at offset 20 is written as 0.

Because terms are folded early (the s_i trick), the asm may leave a
different, congruent representative of h in macState than `updateGeneric`.
Both are < 2p, so the tags are identical. The tests therefore compare
intermediate states mod p, plus exact tags.

## Tests

`sum_mipsle_test.go`. Each check verifies: asm h < 2p; the high word of h[2]
is 0; asm h == generic h (mod p) == an independent math/big model
(h = (h + m + 2^(8*len)) * r mod p per chunk); r/s unchanged; finalize gives
identical tags.

- `TestMipsleUpdateEdge`: keys {0, all-0xff (max clamped r), r=1, 4 random}
  x initial h {0, p-1, p, p+1, 2p-1, 2^130, 2^130-1, 2^128-1, 7*2^128,
  6*2^128-1} x messages of lengths {0,1,15,16,17,31,32,33,64,255,256,1420},
  each all-0xff, all-zero and random. Aligned and unaligned.
- `TestMipsleWorstCase`: h = 2p-1, max r, all-0xff block, 1000 rounds.
- `TestMipsleExitCarry` (added 2026-11-16): r = 1 makes the multiplication
  the identity, so h = 7*2^128 plus a crafted block drives the final c5
  propagation through exactly k = 0..3 all-ones limbs. Random inputs almost
  never reach this; without it, deleting the h2 -> h3 carry survived.
- `TestMipsleUpdateRandom`: 4000 random keys, states (uniform in [0,2p) or
  built from carry-prone words 0/1/0xffffffff/0xfffffffe/0xfffffffb) and
  lengths 0..4096, with misaligned slices.
- `TestMipsleChain`: 7 keys x 2000 successive updates on one state (0xff,
  zero and random blocks), checked after every step.
- `TestMipsleSumWrite`: 2000 Sum and Write tags (odd chunk sizes 1..100)
  vs `sumGeneric`.
- `-stress`: time-seeded RNG and 50x iterations. Run it with
  `-test.run Mipsle` so that the pre-existing TestBurnin (1e10 iterations)
  is excluded.
  Run on 2026-11-16 (final asm), both PASS:
  - TestMipsleUpdateRandom: 200,000 iterations, seed 1794857083039035868, 471 s.
  - TestMipsleSumWrite: 100,000 iterations, seed 1794857554529222953, 26 s.

**Mutation check.** Single-instruction mutants of the asm were run on the
device; the suite failed for every one:
- Deleting a carry, fold or propagation instruction: 7 mutants on v1 and 9
  on the final asm. These ran with `-test.short` and the earlier version of
  the test file (before the extreme-word random cases were added).
- Replacing each of the three limb>=1 carry combines `ADDU R21, R20` with
  `OR` (wrong now that carries can be 2): 3 mutants, final asm and final test
  file, full mode. Edge catches all three; Random also catches one.
- The rarest to catch was dropping the final carry into h4: only Edge and
  Chain detect it.
- **2026-11-16, block rewrite (carry-in via MADDU, fold at block start):**
  41 single-instruction deletion mutants (every instruction of FOLD, the
  message add and its carries, the three `MADDU hi, 1`, the MUL, the exit
  propagation, and the prologue's `R24 = 0`), full mode, on the device.
  40 failed at once; the survivor was the exit propagation's h2 -> h3 carry
  (`SGTU R20, R6, R20`, code unchanged from the previous version, so an old
  test gap). `TestMipsleExitCarry` was added; with it all 9 exit-propagation
  mutants fail, the h2 -> h3 one only through the new test.

Commands (Git Bash; from `work/xcrypto`):

    export GOPATH=/c/GitHub/mipsle-chacha/work/gopath GOCACHE=/c/GitHub/mipsle-chacha/work/gocache \
      GOTOOLCHAIN=local GOFLAGS=-mod=mod GOOS=linux GOARCH=mipsle GOMIPS=softfloat CGO_ENABLED=0
    go vet ./internal/poly1305 && go vet -tags purego ./internal/poly1305
    go test -c -o p.test ./internal/poly1305
    go test -c -o cp.test ./chacha20poly1305
    # the router has no sftp-server, so copy with cat over ssh:
    ssh root@<router> 'cat > /tmp/p.test && chmod +x /tmp/p.test && /tmp/p.test -test.v; rm -f /tmp/p.test' < p.test

The vendored stdlib copy was checked by copying
`.tools/go/src/vendor/golang.org/x/crypto/internal/poly1305` plus
`sum_mipsle.{go,s}` and the transformed `mac_noasm.go` into a scratch module.
`go vet` and `go build` passed for mipsle, mips, arm and amd64, and for mipsle
with `-tags purego`.

## Results (device, 1 thread, 1420-byte messages, `bench/main.go`, 3 s)

| | pure Go (`-tags purego`) | v1 (full propagation) | final (lazy fold) |
|---|---|---|---|
| poly1305 only | 156.9 Mbit/s | 1121.1 | **1199.8 / 1203.9** (2 runs) |
| chacha20poly1305 seal | 48.7 | 264.3 | 266.7 / 265.3 |
| chacha20poly1305 open | 48.7 | 258.7 | 266.1 / 265.9 |

The seal/open numbers include the (then in-progress) mipsle chacha20
asm (chacha20-only was ~377-387 Mbit/s in the same runs), so they are not a
poly1305-only measurement. 4 threads, v1: poly1305 2239 Mbit/s, seal 527.

That version: about 78 cycles per block in the loop (73 instructions plus a
delay-slot NOP, the rest HI/LO read stalls). TestBurnin (1e10 iterations)
was not run.

**Block rewrite (2026-11-16, performance sweep):** carry-in
via `MADDU hi, 1`, fold at the start of the next block, interleaved unaligned
loads: 65 instructions per block (incl. the NOP), about 67 cycles.
Sweep benchmark (median of interleaved runs, 1420 bytes):

| | previous | rewrite |
|---|---|---|
| poly1305 only, aligned | 1210 Mbit/s | 1358 Mbit/s (−11 % time) |
| poly1305 only, unaligned (offset 1) | 1117 Mbit/s | 1294 Mbit/s (−14 % time) |

**Tried and rejected:**
- Interleaving the message add with the d0 product group and moving the MUL
  after the d0 read (first version): 1188 Mbit/s, within noise.
- Only moving the d3 MFLO/MFHI up (the "V2" reorder): ~1–2 %, superseded.
- Filling the MADDU -> MFHI gaps of columns 0 and 1 with the h4 carry adds and
  the pointer increment: ±0.4 %, no gain.
- Hand-encoding the loop branch to put an MFLO in its delay slot: no gain
  over the rewrite, and fragile (branch offset must be recomputed by hand).
