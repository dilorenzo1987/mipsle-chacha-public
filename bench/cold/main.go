// Copyright (c) 2026 netbrains.ch
// SPDX-License-Identifier: BSD-3-Clause

// coldbench: what one crypto operation costs when its code is not in the caches, next to the usual warm
// figure. On the MT7621 a packet's crypto starts with its code evicted from L1 and L2, so the warm numbers of
// bench/sweep miss most of the per-operation cost.
//
// Per cold iteration: evict (128 KiB of straight-line filler code through the 32 KiB instruction cache, then a
// 1 MiB data walk through the 256 KiB L2), touch the operation's own buffers again (in the real path the packet
// was just copied, so its data is warm), then time exactly one operation. "empty" is the timer overhead under
// the same conditions.
//
// Usage: coldbench [iterations [name-filter]]   (default 300 iterations per case)
// Output lines are in the bench/sweep format, so scripts/ab-compare.py can compare two builds
// (scripts/bench-ab.sh --bench cold runs two overlay revisions interleaved on the device).
package main

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/poly1305"
)

// evictCode runs 128 KiB of no-ops (evict_mipsle.s): every set of the 4-way 32 KiB instruction cache is
// replaced 16 times over.
func evictCode()

var wall [1 << 20]byte // 4x the L2 size; written at start so every page is a distinct physical page
var sink uint32

func evictData() {
	s := uint32(0)
	for i := 0; i < len(wall); i += 32 {
		s += uint32(wall[i])
	}
	sink += s
}

func touch(bs ...[]byte) func() {
	return func() {
		s := uint32(0)
		for _, b := range bs {
			for i := 0; i < len(b); i += 32 {
				s += uint32(b[i])
			}
			if len(b) > 0 {
				s += uint32(b[len(b)-1])
			}
		}
		sink += s
	}
}

type tc struct {
	name  string
	f     func()
	touch func()
}

var key = make([]byte, 32)
var nonce = make([]byte, 12)

func fill(b []byte, seed byte) []byte {
	for i := range b {
		b[i] = byte(i)*13 + seed
	}
	return b
}

// keyBlock: what starts every AEAD operation - a new cipher and 32 bytes of key stream (through Cipher.buf).
func keyBlock() tc {
	var pk [32]byte
	return tc{"chacha20 key block", func() {
		c, _ := chacha20.NewUnauthenticatedCipher(key, nonce)
		c.XORKeyStream(pk[:], pk[:])
	}, touch(key, nonce, pk[:])}
}

func stream(n, off int) tc {
	b := fill(make([]byte, n+8), 3)[off : off+n]
	return tc{fmt.Sprintf("chacha20 %d off%d", n, off), func() {
		c, _ := chacha20.NewUnauthenticatedCipher(key, nonce)
		c.XORKeyStream(b, b)
	}, touch(key, nonce, b)}
}

func poly(n int) tc {
	m := fill(make([]byte, n), 5)
	var k [32]byte
	fill(k[:], 11)
	var tag [16]byte
	return tc{fmt.Sprintf("poly1305 %d", n), func() { poly1305.Sum(&tag, m, &k) }, touch(m, k[:])}
}

func seal(name string, n, off, adLen int) tc {
	a, _ := chacha20poly1305.New(key)
	p := fill(make([]byte, n), 7)
	ad := make([]byte, adLen)
	buf := make([]byte, off+n+16+8)
	return tc{name, func() { a.Seal(buf[:off], nonce, p, ad) }, touch(key, nonce, p, ad, buf)}
}

func open(name string, n, off, adLen int) tc {
	a, _ := chacha20poly1305.New(key)
	ad := make([]byte, adLen)
	ct0 := a.Seal(nil, nonce, fill(make([]byte, n), 9), ad)
	src := make([]byte, off+len(ct0)+8)
	copy(src[off:], ct0)
	ct := src[off : off+len(ct0)]
	buf := make([]byte, off+n+8)
	return tc{name, func() {
		if _, err := a.Open(buf[:off], nonce, ct, ad); err != nil {
			panic(err)
		}
	}, touch(key, nonce, ct, ad, buf)}
}

func median(v []float64) float64 {
	s := append([]float64(nil), v...)
	sort.Float64s(s)
	return s[len(s)/2]
}

func main() {
	iters, filter := 300, ""
	if len(os.Args) > 1 {
		v, err := strconv.Atoi(os.Args[1])
		if err != nil || v < 10 {
			fmt.Fprintln(os.Stderr, "coldbench: iterations must be an integer >= 10")
			os.Exit(2)
		}
		iters = v
	}
	if len(os.Args) > 2 {
		filter = os.Args[2]
	}
	for i := range wall {
		wall[i] = byte(i >> 5)
	}
	// Sizes as on the measured DERP path: WireGuard data 1280 B at offset 16 without AD; TLS record
	// around one DERP frame at offset 5 with the 5-byte header as AD; the small ACK messages the other way.
	cases := []tc{
		{"empty", func() {}, func() {}},
		keyBlock(),
		stream(1280, 0),
		stream(1344, 5),
		poly(1280),
		open("open 1280 off16 (WG)", 1280, 16, 0),
		open("open 1350 off5 ad5 (TLS)", 1350, 5, 5),
		seal("seal 64 off16 (WG ACK)", 64, 16, 0),
		seal("seal 134 off5 ad5 (TLS ACK)", 134, 5, 5),
	}
	for _, c := range cases {
		if filter != "" && c.name != "empty" && !strings.Contains(c.name, filter) {
			continue
		}
		// warm: back-to-back calls, as bench/sweep measures
		n, start := 0, time.Now()
		for time.Since(start) < 100*time.Millisecond {
			for j := 0; j < 16; j++ {
				c.f()
			}
			n += 16
		}
		warm := float64(time.Since(start).Nanoseconds()) / float64(n)
		cold := make([]float64, 0, iters)
		for i := 0; i < iters+5; i++ {
			evictCode()
			evictData()
			c.touch()
			t0 := time.Now()
			c.f()
			d := time.Since(t0)
			if i >= 5 {
				cold = append(cold, float64(d.Nanoseconds()))
			}
		}
		fmt.Printf("%-34s %9.0f ns/op\n", c.name+" cold", median(cold))
		fmt.Printf("%-34s %9.0f ns/op\n", c.name+" warm", warm)
	}
}
