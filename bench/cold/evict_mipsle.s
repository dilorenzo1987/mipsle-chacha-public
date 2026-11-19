// Copyright (c) 2026 netbrains.ch
// SPDX-License-Identifier: BSD-3-Clause

// 32768 no-ops (128 KiB) and a return: running through them replaces the whole instruction cache.

#include "textflag.h"

#define N4 WORD $0; WORD $0; WORD $0; WORD $0
#define N16 N4; N4; N4; N4
#define N64 N16; N16; N16; N16
#define N256 N64; N64; N64; N64
#define N1K N256; N256; N256; N256
#define N4K N1K; N1K; N1K; N1K

// func evictCode()
TEXT ·evictCode(SB), NOSPLIT|NOFRAME, $0-0
	N4K; N4K; N4K; N4K
	N4K; N4K; N4K; N4K
	RET
