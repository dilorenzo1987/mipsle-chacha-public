// Copyright (c) 2026 netbrains.ch
// SPDX-License-Identifier: BSD-3-Clause

// Sweep benchmark for the mipsle ChaCha20/Poly1305 assembly: ns/op per case
// (median of R rounds), aligned and unaligned buffers, small and packet sizes,
// seal/open at the WireGuard (dst offset 16) and TLS (offset 5, 5-byte AD)
// buffer layouts, plus heap allocations per op.
//
// Usage: sweep [rounds [ms-per-round [name-filter]]]   (defaults: 5 300 "")
//
// Built and run on the device by scripts/bench-ab.sh (interleaved A/B of two
// overlay revisions).
package main

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/poly1305"
)

type tc struct {
	name  string
	bytes int
	f     func()
}

var key = make([]byte, 32)
var nonce = make([]byte, 12)

// cc: new cipher per op (like the AEAD does), n bytes, includes the tail path.
func cc(n, srcOff, dstOff int) func() {
	s := make([]byte, n+8)[srcOff : srcOff+n]
	d := make([]byte, n+8)[dstOff : dstOff+n]
	return func() {
		c, _ := chacha20.NewUnauthenticatedCipher(key, nonce)
		c.XORKeyStream(d, s)
	}
}

// ccStream: one cipher reused, n a multiple of 64, so each op is a single asm
// call with no allocation and no partial-block path (lowest noise).
func ccStream(n, srcOff, dstOff int) func() {
	s := make([]byte, n+8)[srcOff : srcOff+n]
	d := make([]byte, n+8)[dstOff : dstOff+n]
	c, _ := chacha20.NewUnauthenticatedCipher(key, nonce)
	return func() { c.XORKeyStream(d, s) }
}

func poly(n, off int) func() { return polyK(n, off, false) }

// polyK: rnd uses a non-zero key and message (a zero key makes r = 0, which
// would hide an operand-dependent multiplier).
func polyK(n, off int, rnd bool) func() {
	m := make([]byte, n+8)[off : off+n]
	var k [32]byte
	if rnd {
		for i := range k {
			k[i] = byte(i*37 + 11)
		}
		for i := range m {
			m[i] = byte(i*13 + 7)
		}
	}
	var tag [16]byte
	return func() { poly1305.Sum(&tag, m, &k) }
}

func seal(n, off, adLen int) func() {
	a, _ := chacha20poly1305.New(key)
	p := make([]byte, n)
	ad := make([]byte, adLen)
	buf := make([]byte, off+n+16+8)
	return func() { a.Seal(buf[:off], nonce, p, ad) }
}

func open(n, off, adLen int) func() {
	a, _ := chacha20poly1305.New(key)
	ad := make([]byte, adLen)
	ct0 := a.Seal(nil, nonce, make([]byte, n), ad)
	src := make([]byte, off+len(ct0)+8)
	copy(src[off:], ct0)
	ct := src[off : off+len(ct0)]
	buf := make([]byte, off+n+8)
	return func() {
		if _, err := a.Open(buf[:off], nonce, ct, ad); err != nil {
			panic(err)
		}
	}
}

func main() {
	rounds, ms := 5, 300
	posInt := func(i int, def int) int {
		if len(os.Args) <= i {
			return def
		}
		v, err := strconv.Atoi(os.Args[i])
		if err != nil || v < 1 {
			fmt.Fprintf(os.Stderr, "sweep: argument %d must be a positive integer, got %q\n", i, os.Args[i])
			os.Exit(2)
		}
		return v
	}
	rounds, ms = posInt(1, rounds), posInt(2, ms)
	cases := []tc{
		{"chacha20 1420 aligned", 1420, cc(1420, 0, 0)},
		{"chacha20 1420 unaligned", 1420, cc(1420, 1, 3)},
		{"chacha20 64", 64, cc(64, 0, 0)},
		{"ccstream 1408 aligned", 1408, ccStream(1408, 0, 0)},
		{"ccstream 1408 unaligned", 1408, ccStream(1408, 1, 1)},
		{"poly1305 1420 aligned", 1420, poly(1420, 0)},
		{"poly1305 1420 unaligned", 1420, poly(1420, 1)},
		{"poly1305 64", 64, poly(64, 0)},
		{"poly1305 1420 RANDOM key", 1420, polyK(1420, 0, true)},
		{"seal 1420 off16 (WG)", 1420, seal(1420, 16, 0)},
		{"seal 1420 off5 ad5 (TLS)", 1420, seal(1420, 5, 5)},
		{"open 1420 off16 (WG)", 1420, open(1420, 16, 0)},
		{"open 1420 off5 ad5 (TLS)", 1420, open(1420, 5, 5)},
		{"seal 64 off16 (WG small)", 64, seal(64, 16, 0)},
		{"open 64 off16 (WG small)", 64, open(64, 16, 0)},
	}
	if len(os.Args) > 3 {
		var f []tc
		for _, c := range cases {
			if strings.Contains(c.name, os.Args[3]) {
				f = append(f, c)
			}
		}
		cases = f
	}
	res := make([][]float64, len(cases))
	for r := 0; r < rounds; r++ {
		for i, c := range cases {
			n := 0
			start := time.Now()
			lim := time.Duration(ms) * time.Millisecond
			for {
				for j := 0; j < 32; j++ {
					c.f()
				}
				n += 32
				if time.Since(start) > lim {
					break
				}
			}
			res[i] = append(res[i], float64(time.Since(start).Nanoseconds())/float64(n))
		}
	}
	for i, c := range cases {
		v := append([]float64(nil), res[i]...)
		sort.Float64s(v)
		med := v[len(v)/2]
		spread := (v[len(v)-1] - v[0]) / med * 100
		allocs := testing.AllocsPerRun(50, c.f)
		fmt.Printf("%-26s %9.0f ns/op  %7.1f Mbit/s  spread %4.1f%%  allocs %.0f\n",
			c.name, med, float64(c.bytes)*8/med*1e3, spread, allocs)
	}
}
