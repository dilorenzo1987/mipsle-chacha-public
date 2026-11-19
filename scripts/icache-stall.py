#!/usr/bin/env python3
# Copyright (c) 2026 netbrains.ch
# SPDX-License-Identifier: BSD-3-Clause
"""icache-stall.py <cpu-profile.pprof> [--top N] : where does tailscaled wait for instruction-cache misses?

Method: a CPU-profile sample records the interrupted PC. In straight-line code that runs from a warm
instruction cache, PCs are spread evenly over the 8 words of a 32-byte cache line (12.5 % each). When a line has
to be fetched from memory, the pipeline waits at the first instruction executed in that line, so samples pile up
at addresses with addr % 32 == 0. With P0 = share of samples at a line start, the share of time spent waiting is
estimated as f = (P0 - 1/8) / (7/8). (Lines entered by a jump into their middle are missed, so f is a lower bound;
data-cache misses and kernel time are not covered at all.)

Prints the estimate per group and per function, and for the stand-alone ChaCha20 assembly per call site in
x/crypto v0.58.0's chacha_generic.go (229 = full-block loop, 251 = single block through the buffer: Poly1305 key
block or tail). Builds with the assembly seal/open routine (aeadMIPS) do their ChaCha20 inside that routine.

Needs the Go toolchain (.tools/go) for `go tool pprof -raw`.
"""
import collections
import os
import re
import subprocess
import sys

LINE = 32


def load(profile):
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    go = os.path.join(root, ".tools", "go", "bin", "go")
    raw = subprocess.run([go, "tool", "pprof", "-raw", profile], capture_output=True, text=True, check=True).stdout
    lines = raw.split("\n")
    si, li, mi = lines.index("Samples:"), lines.index("Locations"), lines.index("Mappings")
    locs, cur = {}, None
    for l in lines[li + 1:mi]:
        m = re.match(r"\s*(\d+): (0x[0-9a-f]+) M=\d+ (.*)", l)
        if m:
            cur = int(m.group(1))
            locs[cur] = (int(m.group(2), 16), [m.group(3)])
        elif l.strip() and cur is not None:
            locs[cur][1].append(l.strip())  # further (inlined) frames of the same location
    samples = []
    for l in lines[si + 2:li]:
        m = re.match(r"\s*(\d+)\s+\d+: (.*)", l)
        if m:
            samples.append((int(m.group(1)), [int(x) for x in m.group(2).split()]))
    return locs, samples


def group(name):
    if "Syscall6" in name:
        return "(kernel: syscalls)"
    if "LostSIGPROF" in name or "ExternalCode" in name or name in ("runtime._System", "runtime._GC"):
        return "(unattributed)"
    if "chacha20poly1305.aeadMIPS" in name:
        return "AEAD asm (seal/open)"
    if "chacha20.xorKeyStreamMIPS" in name:
        return "ChaCha20 asm"
    if "poly1305.updateBlocks" in name:
        return "Poly1305 asm"
    if "x/crypto/" in name:
        return "x/crypto Go code"
    if name.startswith("runtime.") or name.startswith("internal/runtime"):
        return "Go runtime"
    if name.startswith("crypto/"):
        return "crypto/tls etc."
    if "wireguard-go" in name:
        return "wireguard-go"
    if name.startswith("tailscale.com"):
        return "tailscale"
    return "other Go (incl. inlined std)"


def stall(p0):
    return max(0.0, (p0 - 1 / 8) / (7 / 8))


def main():
    args, top = sys.argv[1:], 25
    if "--top" in args:
        i = args.index("--top")
        top = int(args[i + 1])
        del args[i:i + 2]
    if len(args) != 1:
        sys.exit(__doc__)
    locs, samples = load(args[0])
    fn_n, fn_0 = collections.Counter(), collections.Counter()
    g_n, g_0 = collections.Counter(), collections.Counter()
    site_n, site_0, site_pcs = collections.Counter(), collections.Counter(), collections.defaultdict(set)
    total = 0
    for n, ids in samples:
        addr, frames = locs[ids[0]]
        name = frames[0].split(" ")[0]
        g = group(name)
        total += n
        fn_n[name] += n
        g_n[g] += n
        at0 = addr % LINE == 0
        if at0:
            fn_0[name] += n
            g_0[g] += n
        if g == "ChaCha20 asm":
            site = "?"
            for i in ids[1:6]:
                for f in locs[i][1]:
                    m = re.search(r"chacha_generic\.go:(\d+)", f)
                    if m and "XORKeyStream" in f:
                        site = m.group(1)
                        break
                if site != "?":
                    break
            k = ("TLS (vendored)" if name.startswith("vendor/") else "WireGuard (x/crypto)", site)
            site_n[k] += n
            site_0[k] += n if at0 else 0
            site_pcs[k].add(addr)

    sec = lambda n: n / 100  # 100 Hz profile: one sample = 10 ms
    print(f"{args[0]}: {total} samples = {sec(total):.1f} CPU-s")
    print(f"\n{'group':30} {'CPU-s':>7} {'share':>6} {'at line start':>14} {'est. I-miss wait':>17}")
    user_wait = 0.0
    for g, n in g_n.most_common():
        if g.startswith("("):
            print(f"{g:30} {sec(n):7.2f} {n * 100 / total:5.1f}% {'-':>14} {'-':>17}")
            continue
        w = stall(g_0[g] / n) * sec(n)
        user_wait += w
        print(f"{g:30} {sec(n):7.2f} {n * 100 / total:5.1f}% {g_0[g] * 100 / n:13.1f}% {w:15.2f} s")
    print(f"estimated wait for instruction-cache misses in user code: {user_wait:.1f} s = "
          f"{user_wait * 100 / sec(total):.1f} % of all CPU time (lower bound)")

    if site_n:
        print("\nChaCha20 asm by call site (chacha_generic.go line: 229 = full-block loop, 251 = single block via buffer):")
    for k in sorted(site_n):
        n = site_n[k]
        print(f"  {k[0]:22} line {k[1]:>3}: {sec(n):5.2f} s, {site_0[k] * 100 / n:5.1f}% at line start, "
              f"est. wait {stall(site_0[k] / n) * sec(n):5.2f} s, {len(site_pcs[k])} distinct PCs")

    print(f"\ntop {top} functions by estimated wait (functions with >= 20 samples):")
    rows = sorted(((stall(fn_0[k] / n) * sec(n), sec(n), fn_0[k] / n, k) for k, n in fn_n.items()
                   if n >= 20 and not group(k).startswith("(")), reverse=True)
    for w, t, p0, k in rows[:top]:
        print(f"  {w:5.2f} s of {t:5.2f} s  {p0 * 100:4.0f}% at line start  {k[-80:]}")


if __name__ == "__main__":
    main()
