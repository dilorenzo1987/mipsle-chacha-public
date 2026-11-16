// Copyright (c) 2026 netbrains.ch
// SPDX-License-Identifier: BSD-3-Clause
// Use of this source code is governed by the BSD-style license in the LICENSE file.

//go:build gc && !purego

package poly1305

// updateBlocks absorbs len(msg)/16 full 16-byte blocks of msg into state.h,
// adding padbit<<128 to each block (padbit is 1 for full message blocks and 0
// for an already padded final block). len(msg) must be a multiple of 16;
// any excess bytes are ignored. Implemented in sum_mipsle.s.
//
//go:noescape
func updateBlocks(state *macState, msg []byte, padbit uint32)

// update has the same semantics as updateGeneric: if len(msg) is not a
// multiple of TagSize, the last incomplete chunk is treated as the final one.
func update(state *macState, msg []byte) {
	if n := len(msg) &^ (TagSize - 1); n > 0 {
		updateBlocks(state, msg[:n], 1)
		msg = msg[n:]
	}
	if len(msg) > 0 {
		var buf [TagSize]byte
		copy(buf[:], msg)
		buf[len(msg)] = 1
		updateBlocks(state, buf[:], 0)
	}
}

// mac is a wrapper for macGeneric that redirects calls that would have gone to
// updateGeneric to update. It mirrors sum_asm.go.
type mac struct{ macGeneric }

func (h *mac) Write(p []byte) (int, error) {
	nn := len(p)
	if h.offset > 0 {
		n := copy(h.buffer[h.offset:], p)
		if h.offset+n < TagSize {
			h.offset += n
			return nn, nil
		}
		p = p[n:]
		h.offset = 0
		updateBlocks(&h.macState, h.buffer[:], 1)
	}
	if n := len(p) - (len(p) % TagSize); n > 0 {
		updateBlocks(&h.macState, p[:n], 1)
		p = p[n:]
	}
	if len(p) > 0 {
		h.offset += copy(h.buffer[h.offset:], p)
	}
	return nn, nil
}

func (h *mac) Sum(out *[16]byte) {
	state := h.macState
	if h.offset > 0 {
		update(&state, h.buffer[:h.offset])
	}
	finalize(out, &state.h, &state.s)
}
