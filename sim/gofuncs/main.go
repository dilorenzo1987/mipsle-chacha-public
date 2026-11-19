// Copyright (c) 2026 netbrains.ch
// SPDX-License-Identifier: BSD-3-Clause

// gofuncs <elf> [regexp] : list functions of a Go binary (name, start, end) from its pclntab; works on
// binaries stripped with -s -w. Used by sim/aead_ops.py to find code in a built tailscaled.
package main

import (
	"debug/elf"
	"debug/gosym"
	"fmt"
	"os"
	"regexp"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: gofuncs <elf> [regexp]")
		os.Exit(2)
	}
	f, err := elf.Open(os.Args[1])
	if err != nil {
		panic(err)
	}
	pcln := f.Section(".gopclntab")
	text := f.Section(".text")
	if pcln == nil || text == nil {
		panic("no .gopclntab or .text section")
	}
	data, err := pcln.Data()
	if err != nil {
		panic(err)
	}
	tab, err := gosym.NewTable(nil, gosym.NewLineTable(data, text.Addr))
	if err != nil {
		panic(err)
	}
	re := regexp.MustCompile(".")
	if len(os.Args) > 2 {
		re = regexp.MustCompile(os.Args[2])
	}
	for i := range tab.Funcs {
		fn := &tab.Funcs[i]
		if re.MatchString(fn.Name) {
			fmt.Printf("%s\t%#x\t%#x\n", fn.Name, fn.Entry, fn.End)
		}
	}
}
