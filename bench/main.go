// Copyright (c) 2026 netbrains.ch
// SPDX-License-Identifier: BSD-3-Clause

// Measures Go crypto throughput with 1420-byte packets (WireGuard-sized), same libs as tailscaled 1.104.7.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/poly1305"
)

const pkt = 1420

var dur = 3 * time.Second

func run(name string, threads int, mk func() func([]byte)) {
	var wg sync.WaitGroup
	counts := make([]int, threads)
	start := time.Now()
	for t := 0; t < threads; t++ {
		wg.Add(1)
		go func(t int) {
			defer wg.Done()
			f := mk()
			buf := make([]byte, pkt)
			for n := 0; ; n++ {
				if n%64 == 0 && time.Since(start) > dur {
					counts[t] = n
					return
				}
				f(buf)
			}
		}(t)
	}
	wg.Wait()
	el := time.Since(start).Seconds()
	tot := 0
	for _, c := range counts {
		tot += c
	}
	fmt.Printf("%-28s threads=%d  %7.1f Mbit/s\n", name, threads, float64(tot)*pkt*8/el/1e6)
}

func main() {
	if len(os.Args) > 1 {
		if s, err := strconv.Atoi(os.Args[1]); err == nil {
			dur = time.Duration(s) * time.Second
		}
	}
	key := make([]byte, 32)
	nonce := make([]byte, 12)
	for _, th := range []int{1, 4} {
		run("chacha20poly1305 seal", th, func() func([]byte) {
			a, _ := chacha20poly1305.New(key)
			out := make([]byte, 0, pkt+16)
			return func(b []byte) { out = a.Seal(out[:0], nonce, b, nil) }
		})
		run("chacha20poly1305 open", th, func() func([]byte) {
			a, _ := chacha20poly1305.New(key)
			ct := a.Seal(nil, nonce, make([]byte, pkt), nil)
			out := make([]byte, 0, pkt)
			return func(b []byte) {
				var err error
				out, err = a.Open(out[:0], nonce, ct, nil)
				if err != nil {
					panic(err)
				}
			}
		})
		run("  chacha20 only", th, func() func([]byte) {
			return func(b []byte) { c, _ := chacha20.NewUnauthenticatedCipher(key, nonce); c.XORKeyStream(b, b) }
		})
		run("  poly1305 only", th, func() func([]byte) {
			var k [32]byte
			var tag [16]byte
			return func(b []byte) { poly1305.Sum(&tag, b, &k) }
		})
		run("aes-128-gcm seal (TLS)", th, func() func([]byte) {
			bc, _ := aes.NewCipher(key[:16])
			a, _ := cipher.NewGCM(bc)
			out := make([]byte, 0, pkt+16)
			return func(b []byte) { out = a.Seal(out[:0], nonce, b, nil) }
		})
	}
}
