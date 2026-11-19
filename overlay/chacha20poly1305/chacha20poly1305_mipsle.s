// Copyright (c) 2026 netbrains.ch
// SPDX-License-Identifier: BSD-3-Clause
// Use of this source code is governed by the BSD-style license in the LICENSE file.

//go:build gc && !purego

// ChaCha20-Poly1305 (RFC 8439) seal and open for MIPS32r2 little endian
// (e.g. MT7621 / 1004Kc) as one compact routine.
//
// Why one routine: on the target the code of a packet's crypto is not in the
// instruction cache when the operation starts, and every 32-byte line costs
// about as much to fetch as 130 instructions take to run. The generic path
// (Go glue around the two assembly cores) touches 230-280 lines per
// operation; this routine needs about 70. The two cores are the ones of
// chacha20/chacha_mipsle.s and internal/poly1305/sum_mipsle.s, used here as
// local subroutines.
//
// Operation (mode = 0 seal, 1 open), n data bytes, the tag is the 16 bytes
// after the data:
//	key block:  kb = ChaCha20 block 0 (Poly1305 key r|s in kb[0:32])
//	seal:       dst = src ^ key stream (blocks 1..); tag = MAC(ad, dst); write tag
//	open:       tag = MAC(ad, src); compare with src[n:n+16] in constant time;
//	            only if equal: dst = src ^ key stream. Otherwise nothing is written.
//	MAC:        Poly1305 over ad | zero pad to 16 | data | zero pad to 16 |
//	            len(ad) as 8 bytes | n as 8 bytes
// dst and src are identical or disjoint (checked by the caller).
//
// Stack frame (192 bytes):
//	st  48: ChaCha20 state as in Cipher: key 0..28, counter 32, nonce 36..44
//	kb  64: key stream block 0
//	tb  64: key stream of a trailing partial block
//	pb  16: zero padded partial Poly1305 block, lengths block
//
// All branches depend only on lengths, alignment, the mode and - after the
// constant-time comparison - on whether the tag matched.
//
// Registers. ChaCha20 phase (cc_blocks): R1..R16 x0..x15, R17 dst, R18 src,
// R19 src end, R20 = &st, R25 non-zero if dst or src is not 4-byte aligned,
// R21/R24 temporaries (R24 also counts the double rounds). Poly1305 phase:
// R2 msg, R3 msg end, R4..R8 h0..h4, R9..R12 r0..r3, R13..R15 s1..s3,
// R16..R19 message words, R20 carry, R21 = 1, R22 tail length, R24/R25 the
// pending d4 (see sum_mipsle.s). R23 (REGTMP) is clobbered by the assembler in
// the ChaCha20 feed-forward only. R31 is the return address of the local
// subroutines; the function has a frame and uses BGEZAL, so the assembler
// saves the caller's R31 in the prologue and RET reloads it.

#include "textflag.h"

// ---------------------------------------------------------------- ChaCha20

#define QR(a, b, c, d) \
	ADDU	b, a; XOR a, d; ROTR $16, d; \
	ADDU	d, c; XOR c, b; ROTR $20, b; \
	ADDU	b, a; XOR a, d; ROTR $24, d; \
	ADDU	d, c; XOR c, b; ROTR $25, b

#define COLROUND \
	QR(R1, R5, R9, R13); QR(R2, R6, R10, R14); QR(R3, R7, R11, R15); QR(R4, R8, R12, R16)
#define DIAGROUND \
	QR(R1, R6, R11, R16); QR(R2, R7, R12, R13); QR(R3, R8, R9, R14); QR(R4, R5, R10, R15)

#define C0 $0x61707865
#define C1 $0x3320646e
#define C2 $0x79622d32
#define C3 $0x6b206574

// Unaligned word store (little endian).
#define STU(r, off) MOVWR r, off(R17); MOVWL r, off+3(R17)

// Feed-forward, see chacha20/chacha_mipsle.s.
#define FFC2A(x, k, off, y, j, yoff) \
	MOVW off(R18), R24; MOVW yoff(R18), R21; ADDU k, x; ADDU j, y; \
	XOR R24, x; MOVW x, off(R17); XOR R21, y; MOVW y, yoff(R17)
#define FFC2U(x, k, off, y, j, yoff) \
	MOVWR off(R18), R24; MOVWR yoff(R18), R21; ADDU k, x; MOVWL off+3(R18), R24; \
	ADDU j, y; MOVWL yoff+3(R18), R21; XOR R24, x; STU(x, off); XOR R21, y; STU(y, yoff)
#define FFSA(x, soff, off) \
	MOVW soff(R20), R21; MOVW off(R18), R24; ADDU R21, x; XOR R24, x; MOVW x, off(R17)
#define FFSU(x, soff, off) \
	MOVWR off(R18), R24; MOVW soff(R20), R21; MOVWL off+3(R18), R24; ADDU R21, x; \
	XOR R24, x; STU(x, off)

#define FINISH(FC2, FS) \
	FC2(R1, C0, 0, R2, C1, 4); FC2(R3, C2, 8, R4, C3, 12); \
	FS(R5, 0, 16); FS(R6, 4, 20); FS(R7, 8, 24); FS(R8, 12, 28); \
	FS(R9, 16, 32); FS(R10, 20, 36); FS(R11, 24, 40); FS(R12, 28, 44); \
	FS(R13, 32, 48); \
	FS(R14, 36, 52); FS(R15, 40, 56); FS(R16, 44, 60)

// ---------------------------------------------------------------- Poly1305

// MADDU rs, rt: HI:LO += rs*rt (unsigned); not known to the Go assembler.
#define MADDU(rs, rt) WORD $(0x70000001 | ((rs)<<21) | ((rt)<<16))

// The 4 LWR before the 4 LWL: an LWL right after the LWR into the same
// register stalls on the 1004Kc. Works for aligned addresses as well.
#define LOAD_UNALIGNED \
	MOVWR	0(R2), R16 \
	MOVWR	4(R2), R17 \
	MOVWR	8(R2), R18 \
	MOVWR	12(R2), R19 \
	MOVWL	3(R2), R16 \
	MOVWL	7(R2), R17 \
	MOVWL	11(R2), R18 \
	MOVWL	15(R2), R19

// FOLD: d4 = R24 + R25; h4 = d4&3 (R8), c5 = (d4&~3) + (d4>>2) (R25).
#define FOLD \
	ADDU	R24, R25 \
	SRL	$2, R25, R24 \
	AND	$3, R25, R8 \
	SUBU	R8, R25 \
	ADDU	R24, R25

// BLOCK: as in internal/poly1305/sum_mipsle.s with the pad bit fixed to 1
// (every block of the AEAD input is a full 16-byte block): fold the pending
// d4, then h = (h + c5 + m + 2^128) * r, partially reduced, leaving the new
// pending d4 in R24 + R25. Message words in R16..R19, R21 = 1.
#define BLOCK \
	FOLD \
	ADDU	R4, R16 \
	SGTU	R4, R16, R20 \
	ADDU	R25, R16 \
	SGTU	R25, R16, R24 \
	ADDU	R5, R17 \
	ADDU	R24, R20 \
	SGTU	R5, R17, R24 \
	ADDU	R20, R17 \
	SGTU	R20, R17, R20 \
	ADDU	R6, R18 \
	ADDU	R24, R20 \
	SGTU	R6, R18, R24 \
	ADDU	R20, R18 \
	SGTU	R20, R18, R20 \
	ADDU	R7, R19 \
	ADDU	R24, R20 \
	SGTU	R7, R19, R24 \
	ADDU	R20, R19 \
	SGTU	R20, R19, R20 \
	ADDU	R24, R20 \
	ADDU	R20, R8 \
	ADDU	R21, R8 \
	MULU	R16, R9 \
	MADDU(17, 15) \
	MADDU(18, 14) \
	MADDU(19, 13) \
	MOVW	HI, R24 \
	MOVW	LO, R4 \
	MULU	R16, R10 \
	MADDU(17, 9) \
	MADDU(18, 15) \
	MADDU(19, 14) \
	MADDU(8, 13) \
	MADDU(24, 21) \
	MOVW	HI, R24 \
	MOVW	LO, R5 \
	MULU	R16, R11 \
	MADDU(17, 10) \
	MADDU(18, 9) \
	MADDU(19, 15) \
	MADDU(8, 14) \
	MADDU(24, 21) \
	MOVW	HI, R24 \
	MOVW	LO, R6 \
	MUL	R8, R9, R25 \
	MULU	R16, R12 \
	MADDU(17, 11) \
	MADDU(18, 10) \
	MADDU(19, 9) \
	MADDU(8, 15) \
	MADDU(24, 21) \
	MOVW	HI, R24 \
	MOVW	LO, R7

// func aeadMIPS(key *[32]byte, nonce *byte, dst, src *byte, n int, ad *byte, adLen int, open int) int
TEXT ·aeadMIPS(SB), NOSPLIT, $192-36
	// ChaCha20 state: key, counter 0, nonce (any alignment).
	MOVW	key+0(FP), R1
	MOVW	nonce+4(FP), R2
	MOVW	$st-192(SP), R20
	MOVWR	0(R1), R3; MOVWR 4(R1), R4; MOVWR 8(R1), R5; MOVWR 12(R1), R6
	MOVWR	16(R1), R7; MOVWR 20(R1), R8; MOVWR 24(R1), R9; MOVWR 28(R1), R10
	MOVWL	3(R1), R3; MOVWL 7(R1), R4; MOVWL 11(R1), R5; MOVWL 15(R1), R6
	MOVWL	19(R1), R7; MOVWL 23(R1), R8; MOVWL 27(R1), R9; MOVWL 31(R1), R10
	MOVWR	0(R2), R11; MOVWR 4(R2), R12; MOVWR 8(R2), R13
	MOVWL	3(R2), R11; MOVWL 7(R2), R12; MOVWL 11(R2), R13
	MOVW	R3, 0(R20); MOVW R4, 4(R20); MOVW R5, 8(R20); MOVW R6, 12(R20)
	MOVW	R7, 16(R20); MOVW R8, 20(R20); MOVW R9, 24(R20); MOVW R10, 28(R20)
	MOVW	R0, 32(R20); MOVW R11, 36(R20); MOVW R12, 40(R20); MOVW R13, 44(R20)

	// kb and tb start as zeros: XORing key stream into them gives the key stream.
	MOVW	$kb-144(SP), R1
	ADDU	$128, R1, R2
zero:
	MOVW	R0, (R1)
	ADDU	$4, R1
	BNE	R1, R2, zero

	// One feed-forward variant for the whole operation, chosen by the data pointers
	// (the unaligned one also works on the aligned stack buffers).
	MOVW	dst+8(FP), R17
	MOVW	src+12(FP), R18
	OR	R17, R18, R25
	AND	$3, R25

	// Key block: kb = key stream block 0, the counter becomes 1.
	MOVW	$kb-144(SP), R17
	MOVW	R17, R18
	ADDU	$64, R18, R19
	BGEZAL	R0, cc_blocks

	MOVW	open+28(FP), R1
	BNE	R1, mac			// open: authenticate first

crypt:
	// dst = src ^ key stream.
	MOVW	$st-192(SP), R20
	MOVW	dst+8(FP), R17
	MOVW	src+12(FP), R18
	MOVW	n+16(FP), R19
	OR	R17, R18, R25
	AND	$3, R25
	AND	$63, R19, R1
	SUBU	R1, R19			// bytes in full blocks
	BEQ	R19, crypt_tail
	ADDU	R18, R19
	BGEZAL	R0, cc_blocks
crypt_tail:
	MOVW	n+16(FP), R1
	AND	$63, R1
	BEQ	R1, crypt_done
	MOVW	$tb-80(SP), R17		// tb = key stream of the partial block
	MOVW	R17, R18
	ADDU	$64, R18, R19
	BGEZAL	R0, cc_blocks
	MOVW	dst+8(FP), R17
	MOVW	src+12(FP), R18
	MOVW	n+16(FP), R19
	MOVW	$tb-80(SP), R2
	AND	$63, R19, R1		// R1 = bytes in the partial block
	SUBU	R1, R19
	ADDU	R19, R17
	ADDU	R19, R18
	ADDU	R18, R1			// end of src
crypt_bytes:
	MOVBU	(R18), R3
	MOVBU	(R2), R4
	ADDU	$1, R18
	XOR	R4, R3
	MOVB	R3, (R17)
	ADDU	$1, R2
	ADDU	$1, R17
	BNE	R18, R1, crypt_bytes
crypt_done:
	MOVW	open+28(FP), R1
	BEQ	R1, mac			// seal: now authenticate what was written
	RET				// open: done, the result was stored before decrypting

mac:
	// r (clamped) and s1..s3 from kb[0:16], h = 0.
	MOVW	kb-144(SP), R9
	MOVW	kb-140(SP), R10
	MOVW	kb-136(SP), R11
	MOVW	kb-132(SP), R12
	MOVW	$0x0fffffff, R1
	AND	R1, R9
	ADDU	$-3, R1			// 0x0ffffffc
	AND	R1, R10
	AND	R1, R11
	AND	R1, R12
	SRL	$2, R10, R13
	ADDU	R10, R13
	SRL	$2, R11, R14
	ADDU	R11, R14
	SRL	$2, R12, R15
	ADDU	R12, R15
	MOVW	R0, R4
	MOVW	R0, R5
	MOVW	R0, R6
	MOVW	R0, R7
	MOVW	R0, R24
	MOVW	R0, R25
	MOVW	$1, R21

	// Additional data, zero padded to a multiple of 16.
	MOVW	ad+20(FP), R2
	MOVW	adLen+24(FP), R3
	BGEZAL	R0, poly_seg

	// The ciphertext (seal: in dst, open: in src), zero padded.
	MOVW	open+28(FP), R1
	MOVW	dst+8(FP), R2
	BEQ	R1, mac_data
	MOVW	src+12(FP), R2
mac_data:
	MOVW	n+16(FP), R3
	BGEZAL	R0, poly_seg

	// The two lengths as 64-bit little-endian numbers.
	MOVW	adLen+24(FP), R1
	MOVW	n+16(FP), R2
	MOVW	R1, pb-16(SP)
	MOVW	R0, pb-12(SP)
	MOVW	R2, pb-8(SP)
	MOVW	R0, pb-4(SP)
	MOVW	$pb-16(SP), R2
	MOVW	$16, R3
	BGEZAL	R0, poly_seg

	// Fold the pending d4 and propagate c5 once (as sum_mipsle.s does on exit):
	// h < 2^130 + 2^32 afterwards, h4 = R8 <= 4.
	FOLD
	ADDU	R25, R4
	SGTU	R25, R4, R20
	ADDU	R20, R5
	SGTU	R20, R5, R20
	ADDU	R20, R6
	SGTU	R20, R6, R20
	ADDU	R20, R7
	SGTU	R20, R7, R20
	ADDU	R20, R8

	// h mod p in constant time: g = h + 5; if g >= 2^130 (bit 2 of its top
	// limb) then h >= p and the low 128 bits of h - p are those of g.
	ADDU	$5, R4, R16
	SGTU	R4, R16, R20
	ADDU	R20, R5, R17
	SGTU	R5, R17, R20
	ADDU	R20, R6, R18
	SGTU	R6, R18, R20
	ADDU	R20, R7, R19
	SGTU	R7, R19, R20
	ADDU	R20, R8
	SRL	$2, R8
	SUBU	R8, R0, R8		// all ones if h >= p, else 0
	XOR	R4, R16
	XOR	R5, R17
	XOR	R6, R18
	XOR	R7, R19
	AND	R8, R16
	AND	R8, R17
	AND	R8, R18
	AND	R8, R19
	XOR	R16, R4
	XOR	R17, R5
	XOR	R18, R6
	XOR	R19, R7

	// tag = (h + s) mod 2^128, s = kb[16:32].
	MOVW	kb-128(SP), R16
	MOVW	kb-124(SP), R17
	MOVW	kb-120(SP), R18
	MOVW	kb-116(SP), R19
	ADDU	R16, R4
	SGTU	R16, R4, R20
	ADDU	R17, R5
	SGTU	R17, R5, R24
	ADDU	R20, R5
	SGTU	R20, R5, R20
	ADDU	R24, R20
	ADDU	R18, R6
	SGTU	R18, R6, R24
	ADDU	R20, R6
	SGTU	R20, R6, R20
	ADDU	R24, R20
	ADDU	R19, R7
	ADDU	R20, R7

	MOVW	open+28(FP), R1
	MOVW	n+16(FP), R3
	BNE	R1, verify

	// seal: the tag goes after the ciphertext.
	MOVW	dst+8(FP), R2
	MOVW	$1, R1
	ADDU	R3, R2
	MOVWR	R4, 0(R2); MOVWL R4, 3(R2)
	MOVWR	R5, 4(R2); MOVWL R5, 7(R2)
	MOVWR	R6, 8(R2); MOVWL R6, 11(R2)
	MOVWR	R7, 12(R2); MOVWL R7, 15(R2)
	MOVW	R1, ret+32(FP)
	RET

verify:
	// open: compare with the received tag without data-dependent branches.
	MOVW	src+12(FP), R2
	ADDU	R3, R2
	MOVWR	0(R2), R16
	MOVWR	4(R2), R17
	MOVWR	8(R2), R18
	MOVWR	12(R2), R19
	MOVWL	3(R2), R16
	MOVWL	7(R2), R17
	MOVWL	11(R2), R18
	MOVWL	15(R2), R19
	XOR	R16, R4
	XOR	R17, R5
	XOR	R18, R6
	XOR	R19, R7
	OR	R5, R4
	OR	R7, R6
	OR	R6, R4
	SGTU	R4, R0, R1		// 1 if any bit differs
	XOR	$1, R1			// 1 if authentic
	MOVW	R1, ret+32(FP)
	BNE	R1, crypt		// authentic: decrypt
	RET				// forged: nothing was written

// cc_blocks: dst (R17) = src (R18) ^ key stream for the full blocks up to R19
// (at least one), counter in st advanced. Clobbers R1..R16, R21, R23, R24;
// R17/R18 end up after the last block. Body = chacha20/chacha_mipsle.s.
cc_blocks:
	MOVW	C0, R1; MOVW C1, R2; MOVW C2, R3; MOVW C3, R4
	MOVW	0(R20), R5; MOVW 4(R20), R6; MOVW 8(R20), R7; MOVW 12(R20), R8
	MOVW	16(R20), R9; MOVW 20(R20), R10; MOVW 24(R20), R11; MOVW 28(R20), R12
	MOVW	32(R20), R13; MOVW 36(R20), R14; MOVW 40(R20), R15; MOVW 44(R20), R16
	MOVW	$10, R24
cc_round:
	COLROUND
	DIAGROUND
	ADDU	$-1, R24
	BNE	R24, cc_round

	BNE	R25, cc_unaligned
	FINISH(FFC2A, FFSA)
cc_next:
	MOVW	32(R20), R21
	ADDU	$64, R17
	ADDU	$1, R21
	ADDU	$64, R18
	MOVW	R21, 32(R20)
	BNE	R18, R19, cc_blocks
	JMP	(R31)
cc_unaligned:
	FINISH(FFC2U, FFSU)
	JMP	cc_next

// poly_seg: absorb R3 bytes at R2 into h, the last block zero padded to 16
// bytes (R3 may be 0). Clobbers R2, R3, R16..R20, R22 and pb.
poly_seg:
	AND	$15, R3, R22
	SUBU	R22, R3
	ADDU	R2, R3
	BEQ	R2, R3, poly_tail
poly_loop:
	LOAD_UNALIGNED
	ADDU	$16, R2
	BLOCK
	BNE	R2, R3, poly_loop
poly_tail:
	BEQ	R22, poly_ret
	MOVW	R0, pb-16(SP)
	MOVW	R0, pb-12(SP)
	MOVW	R0, pb-8(SP)
	MOVW	R0, pb-4(SP)
	MOVW	$pb-16(SP), R3
poly_copy:
	MOVBU	(R2), R16
	ADDU	$1, R2
	ADDU	$-1, R22
	MOVB	R16, (R3)
	ADDU	$1, R3
	BNE	R22, poly_copy
	MOVW	$pb-16(SP), R2
	ADDU	$16, R2, R3
	JMP	poly_loop		// R22 = 0 now: one more block, then return
poly_ret:
	JMP	(R31)
