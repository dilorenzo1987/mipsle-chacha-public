// Copyright (c) 2026 netbrains.ch
// SPDX-License-Identifier: BSD-3-Clause
// Use of this source code is governed by the BSD-style license in the LICENSE file.

//go:build gc && !purego

package chacha20

import (
	"bytes"
	"math/rand"
	"testing"
)

func randCipher(t *testing.T, r *rand.Rand) (*Cipher, *Cipher) {
	key := make([]byte, KeySize)
	r.Read(key)
	nonceLen := NonceSize
	if r.Intn(4) == 0 {
		nonceLen = NonceSizeX
	}
	nonce := make([]byte, nonceLen)
	r.Read(nonce)
	a, err := NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := NewUnauthenticatedCipher(key, nonce)
	return a, b
}

// genericStream XORs src with the key stream using only the generic
// one-block-at-a-time code, starting at counter ctr.
func genericStream(c *Cipher, ctr uint32, src []byte) []byte {
	n := (len(src) + blockSize - 1) / blockSize * blockSize
	buf := make([]byte, n)
	copy(buf, src)
	g := *c
	g.counter = ctr
	g.len = 0
	g.precompDone = false
	g.xorKeyStreamBlocksGeneric(buf, buf)
	return buf[:len(src)]
}

func randCounter(r *rand.Rand, maxBlocks int) uint32 {
	switch r.Intn(4) {
	case 0:
		return 0
	case 1:
		return uint32(r.Int63())
	default:
		// Close to the 2^32 overflow, but still leaving room for maxBlocks.
		return uint32(1<<32 - int64(maxBlocks) - int64(r.Intn(8)))
	}
}

// TestMIPSBlocksDifferential calls the assembly directly on unaligned and
// in-place buffers and checks output, guard bytes and counter.
func TestMIPSBlocksDifferential(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	for i := 0; i < 3000; i++ {
		a, _ := randCipher(t, r)
		nblocks := r.Intn(70)
		n := nblocks * blockSize
		ctr := uint32(r.Int63())
		if r.Intn(3) == 0 {
			ctr = uint32(1<<32 - int64(r.Intn(nblocks+2))) // may wrap mod 2^32
		}
		src := make([]byte, n+16)
		r.Read(src)
		so, do := r.Intn(8), r.Intn(8)
		inPlace := r.Intn(3) == 0
		want := genericStream(a, ctr, src[so:so+n])
		var dstBuf []byte
		var dst []byte
		srcCopy := append([]byte(nil), src...)
		if inPlace {
			dstBuf = src
			dst = src[so : so+n]
		} else {
			dstBuf = make([]byte, n+16)
			r.Read(dstBuf)
			dst = dstBuf[do : do+n]
		}
		guard := append([]byte(nil), dstBuf...)
		a.counter = ctr
		a.xorKeyStreamBlocks(dst, src[so:so+n])
		if !bytes.Equal(dst, want) {
			t.Fatalf("iter %d: n=%d so=%d do=%d inPlace=%v ctr=%#x: output mismatch", i, n, so, do, inPlace, ctr)
		}
		if a.counter != ctr+uint32(nblocks) {
			t.Fatalf("iter %d: counter %#x, want %#x", i, a.counter, ctr+uint32(nblocks))
		}
		start := do
		if inPlace {
			start = so
		}
		if !bytes.Equal(dstBuf[:start], guard[:start]) || !bytes.Equal(dstBuf[start+n:], guard[start+n:]) {
			t.Fatalf("iter %d: wrote outside dst", i)
		}
		if !inPlace && !bytes.Equal(src, srcCopy) {
			t.Fatalf("iter %d: modified src", i)
		}
	}
}

// TestMIPSXORKeyStreamDifferential exercises the public API with random
// lengths, offsets, chunking and counters near overflow.
func TestMIPSXORKeyStreamDifferential(t *testing.T) {
	r := rand.New(rand.NewSource(2))
	for i := 0; i < 3000; i++ {
		a, ref := randCipher(t, r)
		n := r.Intn(4200)
		maxBlocks := (n + blockSize - 1) / blockSize
		ctr := randCounter(r, maxBlocks)
		if ctr != 0 {
			a.SetCounter(ctr)
		}
		src := make([]byte, n+8)
		r.Read(src)
		so, do := r.Intn(8), r.Intn(8)
		want := genericStream(ref, ctr, src[so:so+n])
		inPlace := r.Intn(3) == 0
		var dst []byte
		if inPlace {
			dst = src[so : so+n]
		} else {
			dst = make([]byte, n+8)[do : do+n]
		}
		in := src[so : so+n]
		// Feed in random chunks.
		for off := 0; off < n; {
			c := n - off
			if r.Intn(2) == 0 {
				c = r.Intn(c + 1)
			}
			a.XORKeyStream(dst[off:off+c], in[off:off+c])
			off += c
		}
		if !bytes.Equal(dst, want) {
			t.Fatalf("iter %d: n=%d so=%d do=%d inPlace=%v ctr=%#x: mismatch", i, n, so, do, inPlace, ctr)
		}
	}
}

// TestMIPSCounterOverflow checks the last block before the counter wraps and
// the panic afterwards.
func TestMIPSCounterOverflow(t *testing.T) {
	r := rand.New(rand.NewSource(3))
	for _, n := range []int{1, 63, 64, 65, 128, 200} {
		a, ref := randCipher(t, r)
		blocks := uint32((n + 63) / 64)
		ctr := uint32(1<<32 - uint64(blocks))
		a.SetCounter(ctr)
		src := make([]byte, n)
		r.Read(src)
		dst := make([]byte, n)
		a.XORKeyStream(dst, src)
		if want := genericStream(ref, ctr, src); !bytes.Equal(dst, want) {
			t.Fatalf("n=%d: mismatch at counter end", n)
		}
		func() {
			defer func() {
				if recover() == nil && n%64 == 0 {
					t.Errorf("n=%d: expected panic after overflow", n)
				}
			}()
			a.XORKeyStream(dst[:1], src[:1])
		}()
	}
}
