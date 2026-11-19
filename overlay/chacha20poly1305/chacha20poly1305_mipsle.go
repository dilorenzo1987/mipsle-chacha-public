// Copyright (c) 2026 netbrains.ch
// SPDX-License-Identifier: BSD-3-Clause
// Use of this source code is governed by the BSD-style license in the LICENSE file.

//go:build gc && !purego

package chacha20poly1305

import (
	"unsafe"

	"golang.org/x/crypto/internal/alias"
)

// aeadMIPS seals (open == 0) or opens (open == 1) n bytes from src into dst
// with the given key, 12-byte nonce and additional data; dst and src must be
// identical or disjoint. Sealing writes the 16-byte tag to dst[n:n+16].
// Opening reads the tag from src[n:n+16], compares it in constant time and
// only then decrypts; it returns 1 if the message is authentic and 0 (having
// written nothing) otherwise. Implemented in chacha20poly1305_mipsle.s.
//
//go:noescape
func aeadMIPS(key *[KeySize]byte, nonce *byte, dst, src *byte, n int, ad *byte, adLen int, open int) int

func (c *chacha20poly1305) seal(dst, nonce, plaintext, additionalData []byte) []byte {
	ret, out := sliceForAppend(dst, len(plaintext)+Overhead)
	if alias.InexactOverlap(out, plaintext) {
		panic("chacha20poly1305: invalid buffer overlap of output and input")
	}
	if alias.AnyOverlap(out, additionalData) {
		panic("chacha20poly1305: invalid buffer overlap of output and additional data")
	}
	aeadMIPS(&c.key, unsafe.SliceData(nonce), unsafe.SliceData(out), unsafe.SliceData(plaintext),
		len(plaintext), unsafe.SliceData(additionalData), len(additionalData), 0)
	return ret
}

func (c *chacha20poly1305) open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	n := len(ciphertext) - Overhead
	ret, out := sliceForAppend(dst, n)
	if alias.InexactOverlap(out, ciphertext[:n]) {
		panic("chacha20poly1305: invalid buffer overlap of output and input")
	}
	if alias.AnyOverlap(out, additionalData) {
		panic("chacha20poly1305: invalid buffer overlap of output and additional data")
	}
	if aeadMIPS(&c.key, unsafe.SliceData(nonce), unsafe.SliceData(out), unsafe.SliceData(ciphertext),
		n, unsafe.SliceData(additionalData), len(additionalData), 1) == 0 {
		for i := range out {
			out[i] = 0
		}
		return nil, errOpen
	}
	return ret, nil
}
