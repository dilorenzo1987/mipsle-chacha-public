# ChaCha20-Poly1305 seal/open in one assembly routine (GOARCH=mipsle)

Status 2026-11-19: new. Verified in an interpreter and on the device (GL-MG1300) and checked in a separate
automated review pass (a second AI agent that read the code, the wrapper and the tests and ran its own experiments);
no human or third-party audit.
Installed on the author's router since that day. `scripts/build-tailscaled.sh --no-aead` builds without it (the
ChaCha20 and Poly1305 assembly then run under x/crypto's generic Go code, as before).

Like the ChaCha20 assembly it uses `ROTR` and therefore needs a MIPS32r2 CPU; on an r1 core it would raise SIGILL.

## Why

On the MT7621 the code of a packet's crypto is not in the instruction cache when the operation starts; fetching a
32-byte line costs about 155 ns, as much as ~135 instructions (see "Why compact" in `../chacha20/NOTES.md`). With
the two assembly cores alone, the Go
glue of `sealGeneric`/`openGeneric` (cipher setup with byte-wise loads, buffered key block, padding writes, MAC
finalisation in emulated 64-bit arithmetic, `memmove`) is 180-220 of the 230-280 lines an operation touches. This
routine does the whole operation in about 70 lines; with the thin Go wrapper an operation touches 82-92 lines.

| operation | lines: unrolled ChaCha20 + Go glue | compact ChaCha20 + Go glue | this routine (+ wrapper) | cold cost, first → last |
|---|---|---|---|---|
| WireGuard open 1280 B | 338 | 227 | 83 | 86.0 → 46.1 µs |
| TLS open 1350 B at offset 5 | 380 | 269 | 92 | 97.9 → 51.5 µs |
| WireGuard seal 64 B | 338 | 227 | 82 | 57.9 → 16.1 µs |
| TLS seal 134 B | 395 | 284 | 88 | 71.1 → 20.4 µs |

(counted on full tailscaled builds in an interpreter; cold = every line fetched once at 155 ns + instructions at
880 MHz). It also executes fewer instructions than the generic path (29,227 vs 29,594 for the WireGuard open).

Measured on the device with the caches evicted before every operation (ns per operation, median of 300, 3
interleaved runs; "before" = compact ChaCha20 with the Go glue):

| case | cold before | cold this routine | warm before → this |
|---|---|---|---|
| open 1280 B, WireGuard layout | 78,600 | 55,528 (-29 %) | 37,087 → 34,365 |
| open 1350 B, TLS layout | 88,988 | 60,757 (-32 %) | 44,274 → 38,586 |
| seal 64 B | 47,063 | 24,634 (-48 %) | 6,662 → 3,791 |
| seal 134 B, TLS layout | 56,714 | 29,103 (-49 %) | 11,529 → 7,402 |

## Files

- `chacha20poly1305_mipsle.s`: `aeadMIPS(key, nonce, dst, src, n, ad, adLen, open) int`.
- `chacha20poly1305_mipsle.go`: `(*chacha20poly1305).seal` / `.open` (same checks and panics as the generic code,
  then one call). `scripts/apply-overlay.sh` wraps the build line of upstream's `chacha20poly1305_noasm.go`, as for
  the other two packages; no upstream file is edited. Imports: `unsafe` and x/crypto's `internal/alias`.
- `chacha20poly1305_mipsle_test.go`: differential test against `sealGeneric`/`openGeneric` (device).

## Design

One `TEXT` with a 192-byte frame: `st` (ChaCha20 state as in `Cipher`), `kb` (key stream block 0, holds the
Poly1305 key), `tb` (key stream of a trailing partial block), `pb` (zero padded partial Poly1305 block / lengths).
Two local subroutines, called with `BGEZAL R0, label` and returning with `JMP (R31)`; the assembler then treats
the function as non-leaf, saves R31 in the prologue and reloads it in `RET`:

- `cc_blocks`: the compact ChaCha20 block loop of `chacha20/chacha_mipsle.s`, unchanged. Used for the key block
  (in place on `kb`), the full data blocks and the partial block (in place on the zeroed `tb`, then a byte loop
  XORs the tail). One feed-forward variant per operation, chosen by the data pointers (the unaligned one also
  works on the aligned stack buffers), so an operation never touches both.
- `poly_seg`: the block of `internal/poly1305/sum_mipsle.s` (same `FOLD`/`BLOCK`, pad bit fixed to 1) in a loop
  with unaligned loads only; a partial block is copied into the zeroed `pb` and the loop is entered once more.
  h, r, s1..s3 and the pending d4 stay in registers for the whole MAC, exactly as inside one `updateBlocks`
  call, so the bound proof of `../poly1305/NOTES.md` applies unchanged (entry R24 = R25 = 0, h = 0).

Order: seal = key block, encrypt, MAC over the ciphertext, write the tag. Open = key block, MAC over the
ciphertext, constant-time comparison (XOR/OR of the four words), and only if it matches decrypt; otherwise the
routine returns 0 having written nothing, and the Go wrapper zeroes the output region as the generic code does.

New arithmetic (not in the two cores): the final reduction and the tag. After the last block the pending d4 is
folded and c5 propagated once (as on exit of `updateBlocks`), giving h < 2^130 + 2^32 with top limb <= 4. Then
g = h + 5 is computed with a carry chain; bit 2 of its top limb says h >= p = 2^130 - 5, a mask selects the low
128 bits of g or h without a branch, and s is added with carries.

Branches depend only on lengths, alignment, the mode and, after the comparison, on its (then public) result.

## Verification

Interpreter (`sim/`: a strict user-mode interpreter for the MIPS32r2 subset, run on the development host;
`python3 sim/aead_check.py <this .s file>`, `sim/aead_mutants.py`, `sim/aead_ops.py <binary> --verify 1500`):

- 5163 random operations (seal, open, tampered open; every n in 0..130 with 11
  additional-data lengths; larger sizes with all alignment pairs; unaligned key, nonce and additional data; in
  place and disjoint) against a reference written from RFC 8439; 428 crafted operations with an injected Poly1305
  key (r = 1 or 2 so that the value before the final steps can be set limb by limb: h just below, at and above p;
  carries that stop at each limb in both chains; maximal limbs). The interpreter faults on any byte read or written
  outside the declared buffers, on unaligned word accesses, on uninitialised reads, and a tampered message must
  leave dst untouched.
- Mutation check: 650 single-instruction deletion mutants, 646 caught. Survivors: the two saves
  of R31 that the assembler's prologue emits (either one suffices) and the two `AND $3, R25` (without them the
  always-correct unaligned feed-forward is used for aligned data too).
- A tailscaled built with the routine: 1500 random Seal/Open/tampered-Open through the exported API in both
  copies (x/crypto and the stdlib's vendored one). `go vet` (asmdecl) passes.

Device (2026-11-19): the upstream package tests, the differential test and the edge vectors pass.

Separate review pass (2026-11-19, automated: a second AI agent, working independently of the session that wrote
the routine, with read access to the code, the wrapper and the tests): no defect found; control flow and access
addresses are independent of the
secrets (traces compared), the unwinder and frame are in order, the two loops are the machine code of the shipped
cores except the pad-bit instruction. Its two findings concerned the device test and are fixed:
- `TestMIPSEdgeVectors`: 33 ordinary vectors whose last ciphertext block was solved so that the accumulator hits
  the rare cases of the final reduction (possible without key injection because the Poly1305 key is known once key
  and nonce are fixed). They make the device execute those arms with checked results. Limit: six single-instruction
  deletions in the two carry chains (the `SGTU`s after limb 0) are not distinguished by these vectors, because in
  their states a stale carry equals the true one; those are caught only in the interpreter with an injected key.
- The differential test keeps guard bytes around every output, compares the existing prefix, and calls `aeadMIPS`
  directly on a 0xA5-filled destination for forged messages (the wrapper's zeroing would hide an early write).

End-to-end measurement: `results/2026-11-19_cache-lines.md` (-6.7 % CPU time per MB over a DERP relay against
the same build without the routine, -14.5 % against the build before the compact ChaCha20; one session).
