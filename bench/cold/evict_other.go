// Copyright (c) 2026 netbrains.ch
// SPDX-License-Identifier: BSD-3-Clause

//go:build !mipsle

package main

// evictCode has an assembly body only on mipsle (the benchmark is meaningful only on the device).
func evictCode() {}
