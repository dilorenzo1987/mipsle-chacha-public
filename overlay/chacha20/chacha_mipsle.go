// Copyright (c) 2026 netbrains.ch
// SPDX-License-Identifier: BSD-3-Clause
// Use of this source code is governed by the BSD-style license in the LICENSE file.

//go:build gc && !purego

package chacha20

import "unsafe"

// The MIPS32r2 implementation computes one 64-byte block at a time (no SIMD),
// so a larger buffer would only waste key stream on partial blocks.
const bufSize = blockSize

// The assembly addresses counter and nonce relative to &Cipher.key; these
// declarations fail to compile if the field layout ever changes.
var (
	_ [unsafe.Offsetof(Cipher{}.counter) - 32]struct{}
	_ [32 - unsafe.Offsetof(Cipher{}.counter)]struct{}
	_ [unsafe.Offsetof(Cipher{}.nonce) - 36]struct{}
	_ [36 - unsafe.Offsetof(Cipher{}.nonce)]struct{}
)

// xorKeyStreamMIPS XORs n bytes (a non-zero multiple of 64) of src with key
// stream into dst, reading key, counter and nonce at state[0:8], state[8] and
// state[9:12], and advancing the counter (mod 2^32) by one per block.
//
//go:noescape
func xorKeyStreamMIPS(dst, src *byte, n int, state *[8]uint32)

func (c *Cipher) xorKeyStreamBlocks(dst, src []byte) {
	if len(dst) != len(src) || len(src)%blockSize != 0 {
		panic("chacha20: internal error: wrong dst and/or src length")
	}
	if len(src) == 0 {
		return
	}
	xorKeyStreamMIPS(&dst[0], &src[0], len(src), &c.key)
}
