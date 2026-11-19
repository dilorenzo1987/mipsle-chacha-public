// Copyright (c) 2026 netbrains.ch
// SPDX-License-Identifier: BSD-3-Clause
// Use of this source code is governed by the BSD-style license in the LICENSE file.

//go:build linux && mipsle

package main

import (
	"os"
	"runtime"
)

// On the MT7621 (2 cores x 2 hardware threads, NumCPU 4) tailscaled moves more traffic with 3 Go threads
// than with the default 4: one hardware thread stays free for the kernel's network work, and fewer
// threads contend for the locks behind Go's 64-bit atomics on 32-bit MIPS. Measured on a GL-MG1300 over a
// DERP relay: +4.8 % throughput, -4.5 % CPU per MB (see NOTES.md). An explicit GOMAXPROCS env var wins.
func init() {
	if os.Getenv("GOMAXPROCS") == "" && runtime.NumCPU() == 4 {
		runtime.GOMAXPROCS(3)
	}
}
