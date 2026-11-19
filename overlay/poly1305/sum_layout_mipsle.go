// Copyright (c) 2026 netbrains.ch
// SPDX-License-Identifier: BSD-3-Clause
// Use of this source code is governed by the BSD-style license in the LICENSE file.

//go:build gc && !purego

package poly1305

import "unsafe"

// sum_mipsle.s addresses macState.h at offsets 0..20 and macState.r at 24..36; these declarations fail to
// compile if the layout of macState ever changes (they generate no code).
var (
	_ [unsafe.Offsetof(macState{}.h) - 0]struct{}
	_ [0 - unsafe.Offsetof(macState{}.h)]struct{}
	_ [unsafe.Offsetof(macState{}.r) - 24]struct{}
	_ [24 - unsafe.Offsetof(macState{}.r)]struct{}
	_ [unsafe.Sizeof(macState{}.h) - 24]struct{}
	_ [24 - unsafe.Sizeof(macState{}.h)]struct{}
)
