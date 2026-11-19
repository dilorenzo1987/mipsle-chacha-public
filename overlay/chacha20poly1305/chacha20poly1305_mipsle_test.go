// Copyright (c) 2026 netbrains.ch
// SPDX-License-Identifier: BSD-3-Clause
// Use of this source code is governed by the BSD-style license in the LICENSE file.

//go:build gc && !purego

package chacha20poly1305

import (
	"bytes"
	"encoding/hex"
	"math/rand"
	"testing"
	"unsafe"
)

const guard = 16 // bytes of 0xA5 kept before and after every output buffer

// guarded returns a buffer of guard + n + guard bytes filled with 0xA5 and a check that the guards are intact.
func guarded(t *testing.T, n int) (buf []byte, check func(what string)) {
	buf = bytes.Repeat([]byte{0xA5}, guard+n+guard)
	return buf, func(what string) {
		t.Helper()
		for i, b := range buf {
			if (i < guard || i >= guard+n) && b != 0xA5 {
				t.Fatalf("%s: byte %d outside the output was overwritten (%#x)", what, i-guard, b)
			}
		}
	}
}

// TestMIPSDifferential compares seal/open (assembly) with sealGeneric/openGeneric: every length 0..300 and
// sizes around the packet and block boundaries, random buffer alignments, in place and disjoint, with and
// without additional data, and a key that is not 4-byte aligned. A tampered message must fail exactly like
// the generic code does: error, nil result, output region zeroed.
func TestMIPSDifferential(t *testing.T) {
	rng := rand.New(rand.NewSource(8439))
	var holder struct {
		pad byte
		c   chacha20poly1305 // the key starts at offset 1
	}
	lengths := []int{1023, 1024, 1025, 1279, 1280, 1281, 1344, 1350, 1408, 1420, 1500, 4096, 16384}
	for n := 0; n <= 300; n++ {
		lengths = append(lengths, n)
	}
	for _, n := range lengths {
		for rep := 0; rep < 4; rep++ {
			c := new(chacha20poly1305)
			if rep == 3 {
				c = &holder.c
			}
			rng.Read(c.key[:])
			nonce := make([]byte, 3+NonceSize)[rng.Intn(4):][:NonceSize]
			rng.Read(nonce)
			adLen := []int{0, 5, 13, 16, 31}[rng.Intn(5)]
			ad := make([]byte, 3+adLen)[rng.Intn(4):][:adLen]
			rng.Read(ad)
			offP, offD := rng.Intn(4), rng.Intn(4)
			pt := make([]byte, offP+n)[offP:]
			rng.Read(pt)
			want := c.sealGeneric(nil, nonce, pt, ad)

			// seal: disjoint (guard bytes around the output, the existing prefix must survive) and in place
			gb, check := guarded(t, offD+n+Overhead)
			prefix := gb[guard : guard+offD : guard+offD+n+Overhead]
			rng.Read(prefix)
			keep := append([]byte(nil), prefix...)
			got := c.seal(prefix, nonce, pt, ad)
			if &got[0] != &gb[guard] || !bytes.Equal(got[:offD], keep) || !bytes.Equal(got[offD:], want) {
				t.Fatalf("seal n=%d ad=%d offsets %d/%d: differs from the generic result or the prefix changed", n, adLen, offP, offD)
			}
			check("seal")
			buf := make([]byte, offP+n+Overhead)
			copy(buf[offP:], pt)
			if got := c.seal(buf[offP:offP], nonce, buf[offP:offP+n], ad); !bytes.Equal(got, want) {
				t.Fatalf("seal in place n=%d ad=%d offset %d: differs from the generic result", n, adLen, offP)
			}

			// open: disjoint and in place
			ct := make([]byte, offP+len(want))[offP:]
			copy(ct, want)
			gb, check = guarded(t, offD+n)
			prefix = gb[guard : guard+offD : guard+offD+n]
			rng.Read(prefix)
			keep = append(keep[:0], prefix...)
			out, err := c.open(prefix, nonce, ct, ad)
			if err != nil || !bytes.Equal(out[:offD], keep) || !bytes.Equal(out[offD:], pt) {
				t.Fatalf("open n=%d ad=%d offsets %d/%d: err=%v, wrong plaintext or the prefix changed", n, adLen, offP, offD, err)
			}
			check("open")
			if out, err = c.open(ct[:0], nonce, ct, ad); err != nil || !bytes.Equal(out, pt) {
				t.Fatalf("open in place n=%d ad=%d offset %d: err=%v or wrong plaintext", n, adLen, offP, err)
			}

			// tampered: one bit in ciphertext, tag or additional data
			copy(ct, want)
			if i := rng.Intn(len(want) + adLen); i < len(want) {
				ct[i] ^= 1 << uint(rng.Intn(8))
			} else {
				ad[i-len(want)] ^= 1 << uint(rng.Intn(8))
			}
			dst := bytes.Repeat([]byte{0xA5}, offD+n)
			out, err = c.open(dst[:offD], nonce, ct, ad)
			if err == nil || out != nil {
				t.Fatalf("open n=%d ad=%d: tampered message accepted", n, adLen)
			}
			for i, b := range dst {
				if (i < offD && b != 0xA5) || (i >= offD && b != 0) {
					t.Fatalf("open n=%d ad=%d: output after a failed open is not as with the generic code (byte %d = %#x)", n, adLen, i, b)
				}
			}
			if _, gerr := c.openGeneric(nil, nonce, ct, ad); gerr == nil {
				t.Fatalf("n=%d: the generic code accepts the tampered message (test bug)", n)
			}
			// The assembly itself must not write a single byte for a forged message (the wrapper's zeroing
			// above would hide plaintext written before the comparison).
			gb, check = guarded(t, n)
			for i := range gb {
				gb[i] = 0xA5
			}
			if aeadMIPS(&c.key, unsafe.SliceData(nonce), &gb[guard], unsafe.SliceData(ct), n, unsafe.SliceData(ad), adLen, 1) != 0 {
				t.Fatalf("aeadMIPS n=%d ad=%d: tampered message accepted", n, adLen)
			}
			if !bytes.Equal(gb, bytes.Repeat([]byte{0xA5}, len(gb))) {
				t.Fatalf("aeadMIPS n=%d ad=%d: wrote to dst although the tag did not match", n, adLen)
			}
		}
	}
}

// TestMIPSEdgeVectors runs the vectors that reach the rare cases of the Poly1305 final reduction through the
// assembly (seal, open, tampered open) and through the generic code.
func TestMIPSEdgeVectors(t *testing.T) {
	h := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for _, v := range mipsEdgeVectors {
		c := new(chacha20poly1305)
		copy(c.key[:], h(v.key))
		nonce, ad, pt := h(v.nonce), h(v.ad), h(v.plaintext)
		want := append(h(v.ciphertext), h(v.tag)...)
		if got := c.sealGeneric(nil, nonce, pt, ad); !bytes.Equal(got, want) {
			t.Fatalf("%s: the vector does not match the generic code (test data bug)", v.name)
		}
		if got := c.seal(nil, nonce, pt, ad); !bytes.Equal(got, want) {
			t.Errorf("%s (n=%d): seal differs", v.name, len(pt))
		}
		if got, err := c.open(nil, nonce, want, ad); err != nil || !bytes.Equal(got, pt) {
			t.Errorf("%s (n=%d): open failed: %v", v.name, len(pt), err)
		}
		for bit := 0; bit < 128; bit += 9 { // a wrong tag must be rejected whatever bit differs
			bad := append([]byte(nil), want...)
			bad[len(pt)+bit/8] ^= 1 << uint(bit%8)
			if _, err := c.open(nil, nonce, bad, ad); err == nil {
				t.Errorf("%s (n=%d): tag with bit %d flipped accepted", v.name, len(pt), bit)
			}
		}
	}
}

// TestMIPSAllocs: no heap allocation in seal/open when dst has capacity.
func TestMIPSAllocs(t *testing.T) {
	c := new(chacha20poly1305)
	nonce := make([]byte, NonceSize)
	buf := make([]byte, 16+1280+Overhead)
	if a := testing.AllocsPerRun(20, func() { c.seal(buf[:16], nonce, buf[16:16+1280], nil) }); a != 0 {
		t.Fatalf("seal allocates %v times", a)
	}
	if a := testing.AllocsPerRun(20, func() {
		c.seal(buf[:16], nonce, buf[16:16+1280], nil)
		if _, err := c.open(buf[:16], nonce, buf[16:], nil); err != nil {
			t.Fatal(err)
		}
	}); a != 0 {
		t.Fatalf("seal+open allocate %v times", a)
	}
}
