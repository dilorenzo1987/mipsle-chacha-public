// Copyright (c) 2026 netbrains.ch
// SPDX-License-Identifier: BSD-3-Clause
// Use of this source code is governed by the BSD-style license in the LICENSE file.

//go:build gc && !purego

// ChaCha20 for MIPS32r2 little endian (e.g. MT7621 / 1004Kc): one block at a
// time, all 16 state words in registers, ROTR for the rotations.
//
// Register map:
//	R1..R16	x0..x15 (working state)
//	R17	dst pointer
//	R18	src pointer
//	R19	src end pointer
//	R20	state = &Cipher.key (key at 0..28, counter at 32, nonce at 36..44)
//	R25	non-zero if src or dst is not 4-byte aligned
//	R21, R24	temporaries
// R22 (REGCTXT), R23 (REGTMP), R26-R31 are not touched (R23 is used by the
// assembler itself for the 32-bit constants in the feed-forward).
//
// Stack frame: the 12 words of the first column round that do not depend on
// the counter (columns 1..3), computed once per call.

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
#define DROUND COLROUND; DIAGROUND

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
TEXT ·xorKeyStreamMIPS(SB), NOSPLIT, $48-16
	MOVW	dst+0(FP), R17
	MOVW	src+4(FP), R18
	MOVW	n+8(FP), R19
	MOVW	state+12(FP), R20
	BEQ	R19, done
	ADDU	R18, R19
	OR	R17, R18, R25
	AND	$3, R25

	// First column round for columns 1..3 (counter independent).
	MOVW	C1, R2; MOVW C2, R3; MOVW C3, R4
	MOVW	4(R20), R6; MOVW 8(R20), R7; MOVW 12(R20), R8
	MOVW	20(R20), R10; MOVW 24(R20), R11; MOVW 28(R20), R12
	MOVW	36(R20), R14; MOVW 40(R20), R15; MOVW 44(R20), R16
	QR(R2, R6, R10, R14); QR(R3, R7, R11, R15); QR(R4, R8, R12, R16)
	MOVW	R2, p1-48(SP); MOVW R6, p5-44(SP); MOVW R10, p9-40(SP); MOVW R14, p13-36(SP)
	MOVW	R3, p2-32(SP); MOVW R7, p6-28(SP); MOVW R11, p10-24(SP); MOVW R15, p14-20(SP)
	MOVW	R4, p3-16(SP); MOVW R8, p7-12(SP); MOVW R12, p11-8(SP); MOVW R16, p15-4(SP)

loop:
	// Column 0 of the first column round.
	MOVW	C0, R1
	MOVW	0(R20), R5
	MOVW	16(R20), R9
	MOVW	32(R20), R13
	MOVW	p1-48(SP), R2
	MOVW	p5-44(SP), R6
	QR(R1, R5, R9, R13)
	MOVW	p9-40(SP), R10; MOVW p13-36(SP), R14
	MOVW	p2-32(SP), R3; MOVW p6-28(SP), R7; MOVW p10-24(SP), R11; MOVW p14-20(SP), R15
	MOVW	p3-16(SP), R4; MOVW p7-12(SP), R8; MOVW p11-8(SP), R12; MOVW p15-4(SP), R16
	DIAGROUND
	DROUND; DROUND; DROUND
	DROUND; DROUND; DROUND
	DROUND; DROUND; DROUND

	BNE	R25, unaligned
	FINISH(FFC2A, FFSA)
next:
	MOVW	32(R20), R21
	ADDU	$64, R17
	ADDU	$1, R21
	ADDU	$64, R18
	MOVW	R21, 32(R20)
	BNE	R18, R19, loop

done:
	RET

unaligned:
	FINISH(FFC2U, FFSU)
	JMP	next
