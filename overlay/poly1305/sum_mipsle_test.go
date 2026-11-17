// Copyright (c) 2026 netbrains.ch
// SPDX-License-Identifier: BSD-3-Clause
// Use of this source code is governed by the BSD-style license in the LICENSE file.

//go:build gc && !purego

package poly1305

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"
	"math/rand"
	"testing"
	"time"
)

// Differential tests for the mipsle assembly update against updateGeneric
// and against an independent math/big model.
//
// The asm and the generic code may leave different (but congruent)
// representatives of h in macState, because the asm folds the product terms
// above 2^128 early. Intermediate states are therefore compared modulo
// p = 2^130 - 5, and the asm state is checked to satisfy the invariant
// finalize relies on: h < 2p (which also implies h[2] < 8).

var (
	bigP    = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 130), big.NewInt(5))
	big2P   = new(big.Int).Lsh(bigP, 1)
	big2128 = new(big.Int).Lsh(big.NewInt(1), 128)
)

func hToBig(h [3]uint64) *big.Int {
	x := new(big.Int).SetUint64(h[2])
	x.Lsh(x, 64)
	x.Or(x, new(big.Int).SetUint64(h[1]))
	x.Lsh(x, 64)
	x.Or(x, new(big.Int).SetUint64(h[0]))
	return x
}

func bigToH(x *big.Int) [3]uint64 {
	var b [24]byte
	x.FillBytes(b[:])
	return [3]uint64{
		binary.BigEndian.Uint64(b[16:24]),
		binary.BigEndian.Uint64(b[8:16]),
		binary.BigEndian.Uint64(b[0:8]),
	}
}

func rToBig(r [2]uint64) *big.Int {
	x := new(big.Int).SetUint64(r[1])
	x.Lsh(x, 64)
	return x.Or(x, new(big.Int).SetUint64(r[0]))
}

// bigUpdate is an independent model of updateGeneric's semantics, mod p.
func bigUpdate(h *big.Int, r *big.Int, msg []byte) *big.Int {
	h = new(big.Int).Set(h)
	for len(msg) > 0 {
		n := min(len(msg), TagSize)
		var buf [TagSize + 1]byte
		copy(buf[:], msg[:n])
		buf[n] = 1
		// little-endian to big.Int
		be := make([]byte, n+1)
		for i := 0; i <= n; i++ {
			be[n-i] = buf[i]
		}
		h.Add(h, new(big.Int).SetBytes(be))
		h.Mul(h, r)
		h.Mod(h, bigP)
		msg = msg[n:]
	}
	return h
}

func checkState(t *testing.T, what string, got, want *macState, model *big.Int) {
	t.Helper()
	g := hToBig(got.h)
	if g.Cmp(big2P) >= 0 {
		t.Fatalf("%s: asm h = %x is not < 2p", what, g)
	}
	if got.h[2]>>32 != 0 {
		t.Fatalf("%s: asm h[2] high word non-zero: %#x", what, got.h[2])
	}
	gm := new(big.Int).Mod(g, bigP)
	wm := new(big.Int).Mod(hToBig(want.h), bigP)
	if gm.Cmp(wm) != 0 {
		t.Fatalf("%s: asm h mod p = %x, generic h mod p = %x", what, gm, wm)
	}
	if model != nil && gm.Cmp(model) != 0 {
		t.Fatalf("%s: asm h mod p = %x, big model = %x", what, gm, model)
	}
	if got.r != want.r || got.s != want.s {
		t.Fatalf("%s: r/s modified", what)
	}
	// The final tags must agree exactly.
	var tg, tw [16]byte
	finalize(&tg, &got.h, &got.s)
	finalize(&tw, &want.h, &want.s)
	if tg != tw {
		t.Fatalf("%s: tag mismatch: asm %x generic %x", what, tg, tw)
	}
}

func randState(rng *rand.Rand, key *[32]byte) macState {
	var st macState
	initialize(key, &st)
	// Random h in [0, 2p).
	b := make([]byte, 17)
	rng.Read(b)
	x := new(big.Int).SetBytes(b)
	x.Mod(x, big2P)
	st.h = bigToH(x)
	return st
}

// interesting h values, all < 2p.
func edgeStates() []*big.Int {
	one := big.NewInt(1)
	vals := []*big.Int{
		big.NewInt(0),
		new(big.Int).Sub(bigP, one),                       // p-1
		new(big.Int).Set(bigP),                            // p
		new(big.Int).Add(bigP, one),                       // p+1
		new(big.Int).Sub(big2P, one),                      // 2p-1
		new(big.Int).Lsh(one, 130),                        // 2^130
		new(big.Int).Sub(new(big.Int).Lsh(one, 130), one), // 2^130-1
		new(big.Int).Sub(new(big.Int).Lsh(one, 128), one), // 2^128-1
		new(big.Int).Mul(big.NewInt(7), big2128),          // 7*2^128
		new(big.Int).Sub(new(big.Int).Mul(big.NewInt(6), big2128), one),
	}
	return vals
}

func edgeKeys(rng *rand.Rand) [][32]byte {
	var keys [][32]byte
	var k [32]byte
	keys = append(keys, k) // zero
	for i := range k {
		k[i] = 0xff
	}
	keys = append(keys, k) // max clamped r
	for i := 0; i < 16; i++ {
		k[i] = 0
	}
	k[0] = 1
	keys = append(keys, k) // r = 1
	for i := 0; i < 4; i++ {
		rng.Read(k[:])
		keys = append(keys, k)
	}
	return keys
}

func edgeMsgs(rng *rand.Rand) [][]byte {
	var msgs [][]byte
	for _, n := range []int{0, 1, 15, 16, 17, 31, 32, 33, 64, 255, 256, 1420} {
		ff := bytes.Repeat([]byte{0xff}, n)
		msgs = append(msgs, ff, make([]byte, n))
		r := make([]byte, n)
		rng.Read(r)
		msgs = append(msgs, r)
	}
	return msgs
}

func TestMipsleUpdateEdge(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for ki, key := range edgeKeys(rng) {
		for hi, hv := range edgeStates() {
			for mi, msg := range edgeMsgs(rng) {
				what := fmt.Sprintf("edge key#%d h#%d msg#%d len %d", ki, hi, mi, len(msg))
				var a, g macState
				initialize(&key, &a)
				a.h = bigToH(hv)
				g = a
				for _, unaligned := range []bool{false, true} {
					m := msg
					if unaligned {
						m = unalignBytes(msg)
					}
					a2, g2 := a, g
					update(&a2, m)
					updateGeneric(&g2, m)
					model := bigUpdate(new(big.Int).Mod(hv, bigP), rToBig(a.r), m)
					checkState(t, what, &a2, &g2, model)
				}
			}
		}
	}
}

// TestMipsleWorstCase drives the largest possible intermediate values:
// h = 2p-1 (allowed by the macState invariant), max clamped r, all-0xff
// message. Without the entry pre-fold in the asm, h4 would reach 9 after
// adding the block and the fold of the bits above 2^130 would carry out of
// 32 bits; with it, this exercises the largest values the asm can see.
func TestMipsleWorstCase(t *testing.T) {
	var key [32]byte
	for i := range key {
		key[i] = 0xff
	}
	var a macState
	initialize(&key, &a)
	a.h = bigToH(new(big.Int).Sub(big2P, big.NewInt(1)))
	g := a
	model := new(big.Int).Mod(hToBig(a.h), bigP)
	msg := bytes.Repeat([]byte{0xff}, 16)
	for i := 0; i < 1000; i++ {
		update(&a, msg)
		updateGeneric(&g, msg)
		model = bigUpdate(model, rToBig(a.r), msg)
		checkState(t, "worst", &a, &g, model)
		// Also restart from the extreme state every other round.
		if i%2 == 1 {
			a.h = bigToH(new(big.Int).Sub(big2P, big.NewInt(1)))
			g.h = a.h
			model = new(big.Int).Mod(hToBig(a.h), bigP)
		}
	}
}

// TestMipsleExitCarry drives the carry chain that propagates the last c5
// after the loop through each limb in turn. With r = 1 the multiplication is
// the identity (s1..s3 = 0), so the state after the block is chosen exactly:
// h = 7*2^128 gives c5 = 5 on entry, the block (0xfffffff9, k words
// 0xffffffff, then 0) plus padbit gives h0 = 0xfffffffe and h4 = 4, so the
// final fold yields c5 = 5 again and h0 + c5 carries through exactly k
// all-ones limbs. Random inputs essentially never hit this (a deletion
// mutant of the h2 -> h3 carry survived all other tests).
func TestMipsleExitCarry(t *testing.T) {
	var key [32]byte
	key[0] = 1 // r = 1
	for k := 0; k <= 3; k++ {
		msg := make([]byte, 16)
		binary.LittleEndian.PutUint32(msg[0:], 0xfffffff9)
		for i := 1; i <= k; i++ {
			binary.LittleEndian.PutUint32(msg[4*i:], 0xffffffff)
		}
		for _, unaligned := range []bool{false, true} {
			m := msg
			if unaligned {
				m = unalignBytes(msg)
			}
			var a macState
			initialize(&key, &a)
			a.h = bigToH(new(big.Int).Mul(big.NewInt(7), big2128))
			g := a
			model := bigUpdate(new(big.Int).Mod(hToBig(a.h), bigP), rToBig(a.r), m)
			update(&a, m)
			updateGeneric(&g, m)
			checkState(t, fmt.Sprintf("exit carry k=%d unaligned=%v", k, unaligned), &a, &g, model)
		}
	}
}

// testRNG returns a deterministic RNG, or a time-seeded one with -stress.
// iters is scaled up with -stress and down with -short.
func testRNG(t *testing.T, seed int64, iters int) (*rand.Rand, int) {
	if *stressFlag {
		seed = time.Now().UnixNano()
		iters *= 50
		t.Logf("seed %d, %d iterations", seed, iters)
	} else if testing.Short() {
		iters /= 10
	}
	return rand.New(rand.NewSource(seed)), iters
}

// extremeWord returns 32-bit values that tend to trigger carry edge cases.
func extremeWord(rng *rand.Rand) uint32 {
	switch rng.Intn(6) {
	case 0:
		return 0
	case 1:
		return 1
	case 2:
		return 0xffffffff
	case 3:
		return 0xfffffffe
	case 4:
		return 0xfffffffb
	}
	return rng.Uint32()
}

func fillExtreme(rng *rand.Rand, b []byte) {
	for i := range b {
		if i%4 == 0 {
			var w [4]byte
			binary.LittleEndian.PutUint32(w[:], extremeWord(rng))
			copy(b[i:], w[:])
		}
	}
}

func TestMipsleUpdateRandom(t *testing.T) {
	rng, n := testRNG(t, 2, 4000)
	buf := make([]byte, 4200)
	for i := 0; i < n; i++ {
		extreme := i%4 == 1
		var key [32]byte
		if extreme {
			fillExtreme(rng, key[:])
		} else {
			rng.Read(key[:])
		}
		var a macState
		switch {
		case extreme:
			initialize(&key, &a)
			var hb [24]byte
			fillExtreme(rng, hb[:20])
			h := [3]uint64{
				binary.LittleEndian.Uint64(hb[0:8]),
				binary.LittleEndian.Uint64(hb[8:16]),
				uint64(rng.Intn(8)),
			}
			a.h = bigToH(new(big.Int).Mod(hToBig(h), big2P))
		case i%2 == 0:
			a = randState(rng, &key)
		default:
			initialize(&key, &a)
		}
		g := a
		l := rng.Intn(4097)
		msg := buf[:l]
		if i%3 == 0 {
			off := 1 + rng.Intn(3)
			msg = buf[off : off+l]
		}
		if extreme {
			fillExtreme(rng, msg)
		} else {
			rng.Read(msg)
		}
		model := bigUpdate(new(big.Int).Mod(hToBig(a.h), bigP), rToBig(a.r), msg)
		update(&a, msg)
		updateGeneric(&g, msg)
		checkState(t, fmt.Sprintf("random #%d len %d", i, l), &a, &g, model)
	}
}

// TestMipsleChain runs many successive updates on the same state and
// compares against generic after every step.
func TestMipsleChain(t *testing.T) {
	rng := rand.New(rand.NewSource(3))
	for _, key := range edgeKeys(rng) {
		var a macState
		initialize(&key, &a)
		g := a
		model := new(big.Int)
		for i := 0; i < 2000; i++ {
			l := 16 * rng.Intn(8)
			var msg []byte
			switch rng.Intn(3) {
			case 0:
				msg = bytes.Repeat([]byte{0xff}, l)
			case 1:
				msg = make([]byte, l)
			default:
				msg = make([]byte, l)
				rng.Read(msg)
			}
			update(&a, msg)
			updateGeneric(&g, msg)
			model = bigUpdate(model, rToBig(a.r), msg)
			checkState(t, "chain", &a, &g, model)
		}
	}
}

// TestMipsleSumWrite compares full tags from the public API (asm path) with
// sumGeneric, writing in odd chunk sizes.
func TestMipsleSumWrite(t *testing.T) {
	rng, n := testRNG(t, 4, 2000)
	chunks := []int{1, 3, 7, 13, 15, 16, 17, 31, 33, 64, 100}
	for i := 0; i < n; i++ {
		var key [32]byte
		if i%10 == 0 {
			for j := range key {
				key[j] = 0xff
			}
		} else {
			rng.Read(key[:])
		}
		l := rng.Intn(4097)
		msg := make([]byte, l)
		if i%7 == 0 {
			for j := range msg {
				msg[j] = 0xff
			}
		} else {
			rng.Read(msg)
		}
		var want, got [16]byte
		sumGeneric(&want, msg, &key)
		Sum(&got, msg, &key)
		if got != want {
			t.Fatalf("Sum len %d: got %x want %x", l, got, want)
		}
		h := New(&key)
		rest := msg
		for len(rest) > 0 {
			c := min(chunks[rng.Intn(len(chunks))], len(rest))
			h.Write(rest[:c])
			rest = rest[c:]
		}
		if s := h.Sum(nil); !bytes.Equal(s, want[:]) {
			t.Fatalf("Write len %d: got %x want %x", l, s, want)
		}
	}
}
