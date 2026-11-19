// Copyright (c) 2026 netbrains.ch
// SPDX-License-Identifier: BSD-3-Clause
// Use of this source code is governed by the BSD-style license in the LICENSE file.

//go:build gc && !purego

// ChaCha20 for MIPS32r2 little endian (e.g. MT7621 / 1004Kc): one block at a
// time, all 16 state words in registers, ROTR for the rotations.
//
// Compact on purpose: the ten double rounds are a loop, so the whole routine
// is about 30 instruction-cache lines instead of about 140 when unrolled. On
// the target the code is not in the cache when a packet's first block starts
// (the cache is 32 KB and the per-packet path through kernel and Go is far
// larger), and fetching a line costs about as much as 130 instructions. The
// loop costs 3 instructions per double round and there is no per-call
// precompute, about 7 % more instructions per block than the unrolled form.
//
// Register map:
//	R1..R16	x0..x15 (working state)
//	R17	dst pointer
//	R18	src pointer
//	R19	src end pointer
//	R20	state = &Cipher.key (key at 0..28, counter at 32, nonce at 36..44)
//	R25	non-zero if src or dst is not 4-byte aligned
//	R21, R24	temporaries; R24 also counts the double rounds
// R22 (REGCTXT), R26-R28, R30, R31 are not touched, R29 (SP) is not moved (no
// frame). R23 (REGTMP) is clobbered by the assembler (LUI/ORI of the 32-bit
// constants in the feed-forward).

#include "textflag.h"

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

// Feed-forward: out[off] = in[off] ^ (x + k), for two constant words at a
// time (k, j are the constants C0..C3) and for one word from the state
// (soff). The instruction order keeps every loaded value at least one
// instruction away from its first use and, on the unaligned path, never puts
// an LWL right after the LWR into the same register (both stall on the
// 1004Kc). src and dst are identical or disjoint (XORKeyStream panics on
// inexact overlap), so loading a word before storing it is enough.
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

// func xorKeyStreamMIPS(dst, src *byte, n int, state *[8]uint32)
TEXT ·xorKeyStreamMIPS(SB), NOSPLIT|NOFRAME, $0-16
	MOVW	dst+0(FP), R17
	MOVW	src+4(FP), R18
	MOVW	n+8(FP), R19
	MOVW	state+12(FP), R20
	BEQ	R19, done
	ADDU	R18, R19
	OR	R17, R18, R25
	AND	$3, R25

block:
	MOVW	C0, R1; MOVW C1, R2; MOVW C2, R3; MOVW C3, R4
	MOVW	0(R20), R5; MOVW 4(R20), R6; MOVW 8(R20), R7; MOVW 12(R20), R8
	MOVW	16(R20), R9; MOVW 20(R20), R10; MOVW 24(R20), R11; MOVW 28(R20), R12
	MOVW	32(R20), R13; MOVW 36(R20), R14; MOVW 40(R20), R15; MOVW 44(R20), R16
	MOVW	$10, R24
round:
	COLROUND
	DIAGROUND
	ADDU	$-1, R24
	BNE	R24, round

	BNE	R25, unaligned
	FINISH(FFC2A, FFSA)
next:
	MOVW	32(R20), R21
	ADDU	$64, R17
	ADDU	$1, R21
	ADDU	$64, R18
	MOVW	R21, 32(R20)
	BNE	R18, R19, block

done:
	RET

unaligned:
	FINISH(FFC2U, FFSU)
	JMP	next
