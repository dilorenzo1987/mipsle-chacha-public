// Copyright (c) 2026 netbrains.ch
// SPDX-License-Identifier: BSD-3-Clause
// Use of this source code is governed by the BSD-style license in the LICENSE file.

//go:build gc && !purego

#include "textflag.h"

// Poly1305 block function for MIPS32r2 little-endian (e.g. MT7621 / 1004Kc).
//
// Radix 2^32 approach, inspired by OpenSSL's poly1305-mips.pl (32-bit path),
// written from scratch.
//
// On mipsle, macState (h [3]uint64, r [2]uint64, s [2]uint64) is laid out in
// memory as 32-bit little-endian words:
//
//	 0: h0  4: h1  8: h2  12: h3  16: h4  20: (high half of h[2], always 0)
//	24: r0 28: r1 32: r2  36: r3  40..55: s (not used here)
//
// so h = h0 + h1*2^32 + h2*2^64 + h3*2^96 + h4*2^128 is used in place and
// r = r0 + r1*2^32 + r2*2^64 + r3*2^96. Clamping gives r0 < 2^28 and
// r1, r2, r3 < 2^28 with their low 2 bits cleared, so s_i = r_i + r_i>>2 =
// 5*r_i/4 is exact. Since 2^128 = 5/4 mod 2^130-5, a product term
// h_i*r_j*2^(32(i+j)) with i+j >= 4 equals h_i*s_j*2^(32(i+j-4)) mod p.
//
//	d0 = h0*r0 + h1*s3 + h2*s2 + h3*s1
//	d1 = h0*r1 + h1*r0 + h2*s3 + h3*s2 + h4*s1
//	d2 = h0*r2 + h1*r1 + h2*r0 + h3*s3 + h4*s2
//	d3 = h0*r3 + h1*r2 + h2*r1 + h3*r0 + h4*s3
//	d4 = h4*r0
//
// Each column is accumulated in HI:LO with MULTU/MADDU. The carry of column
// i (its HI word, < 2^31) is added into column i+1 inside the accumulator as
// the last product (MADDU hi, 1 with R21 = 1), so LO of each column is the
// final limb and no ALU carry chain is needed; every column including the
// carry-in stays < 2^63. d4 = HI of column 3 + h4*r0. The bits of d4 above
// 2^130 are folded back multiplied by 5: c5 = 5*(d4>>2) = (d4&~3) + (d4>>2),
// h4 = d4&3.
//
// Lazy reduction: d4 is left in R24 (HI of column 3) + R25 (h4*r0) at the
// end of a block. The fold is done at the start of the next block, and c5 is
// added together with the next message block (h + c5 + m, carries up to 2
// per limb). The value of h entering each multiplication is therefore
// exactly the same as with a full propagation; only the timing differs. On
// entry R24 = 0 and R25 = stored h4, so the first fold moves the bits of h
// above 2^130 (h4>>2, at most 1 because h < 2p) into c5 the same way. After
// the loop the pending d4 is folded and c5 propagated once. See NOTES.md for
// the bound argument (h4 <= 6 before each multiplication, d4 < 10*2^28,
// c5 < 2^32).
//
// Register map:
//	R1       padbit (1 for message blocks, 0 for a pre-padded final block)
//	R2       msg pointer, R3 msg end
//	R4..R8   h0..h4
//	R9..R12  r0..r3
//	R13..R15 s1..s3
//	R16..R19 message words, then h + c5 + m (the multiplication inputs)
//	R20      carry temporary
//	R21      constant 1
//	R24      HI of the previous column (carry-in); temporary in the fold
//	R25      h4*r0 -> d4 -> c5 (loop-carried with R24)
// R23 (REGTMP) is not used; no instruction here expands to a sequence using it.
//
// Note on SGTU: "SGTU Ra, Rb, Rc" sets Rc = (Ra > Rb) unsigned. After
// "ADDU Ra, Rb" (Rb += Ra), the carry out is (Ra > Rb).
//
// Scheduling (measured on the MT7621): MFHI/MFLO results are consumed >= 5
// instructions later, MUL (which leaves HI/LO unpredictable before MIPS32r6)
// sits where HI/LO are dead, and the unaligned loads put the 4 LWR before the
// 4 LWL (an LWL right after the LWR into the same register stalls).
//
// All branches depend only on the message length and alignment (public).

// MADDU rs, rt: HI:LO += rs*rt (unsigned). Not supported by the Go assembler
// (it only knows the signed MADD), so it is encoded by hand. WORD is a
// scheduling barrier for the assembler, so it never reorders around it
// (the Go mips assembler does no reordering anyway; it fills every branch
// delay slot with a NOP).
#define MADDU(rs, rt) WORD $(0x70000001 | ((rs)<<21) | ((rt)<<16))

#define LOAD_ALIGNED \
	MOVW	0(R2), R16 \
	MOVW	4(R2), R17 \
	MOVW	8(R2), R18 \
	MOVW	12(R2), R19

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

// BLOCK: fold the pending d4, then h = (h + c5 + m + padbit*2^128) * r,
// partially reduced, leaving the new pending d4 in R24 + R25. Message words
// in R16..R19.
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
	ADDU	R1, R8 \
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

// func updateBlocks(state *macState, msg []byte, padbit uint32)
TEXT ·updateBlocks(SB), NOSPLIT, $0-20
	MOVW	msg_base+4(FP), R2
	MOVW	msg_len+8(FP), R3
	MOVW	padbit+16(FP), R1
	SRL	$4, R3
	SLL	$4, R3
	BEQ	R3, done
	ADDU	R2, R3

	MOVW	state+0(FP), R20
	MOVW	0(R20), R4
	MOVW	4(R20), R5
	MOVW	8(R20), R6
	MOVW	12(R20), R7
	MOVW	16(R20), R25
	MOVW	24(R20), R9
	MOVW	28(R20), R10
	MOVW	32(R20), R11
	MOVW	36(R20), R12
	MOVW	$0, R24
	MOVW	$1, R21
	SRL	$2, R10, R13
	ADDU	R10, R13
	SRL	$2, R11, R14
	ADDU	R11, R14
	SRL	$2, R12, R15
	ADDU	R12, R15

	AND	$3, R2, R16
	BNE	R16, unaligned

aligned:
	LOAD_ALIGNED
	ADDU	$16, R2
	BLOCK
	BNE	R2, R3, aligned
	JMP	store

unaligned:
	LOAD_UNALIGNED
	ADDU	$16, R2
	BLOCK
	BNE	R2, R3, unaligned

store:
	// Fold the pending d4 and propagate c5 once: h += c5.
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

	MOVW	state+0(FP), R24
	MOVW	R4, 0(R24)
	MOVW	R5, 4(R24)
	MOVW	R6, 8(R24)
	MOVW	R7, 12(R24)
	MOVW	R8, 16(R24)
	MOVW	R0, 20(R24)

done:
	RET
