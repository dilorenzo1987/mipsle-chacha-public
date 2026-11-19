#!/usr/bin/env python3
# Copyright (c) 2026 netbrains.ch
# SPDX-License-Identifier: BSD-3-Clause
"""chacha_check.py <chacha_mipsle.s> [--quick] : run xorKeyStreamMIPS from an assembly file in the strict
interpreter (mipsim.py), compare with a reference ChaCha20 and report instruction and cache-line counts.

The file is assembled by the Go toolchain in .tools/go into a throwaway linux/mipsle binary (work/mipsim/), the
function's machine code is taken from that ELF. Nothing runs on the device.

Checks per case: output == src XOR key stream, counter advanced by the number of blocks (mod 2^32), key and nonce
untouched, no access outside src/dst/state/own frame, plus everything mipsim.py is strict about.
Cases: all 16 alignment pairs of dst and src (mod 4), disjoint and in-place, 1..23 blocks, counter wrap.
"""
import hashlib
import os
import random
import struct
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mipsim import Cpu, Elf, Fault, Region, LINE, M32  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GO = os.path.join(ROOT, ".tools", "go", "bin", "go")

MAIN_GO = """package main

import "unsafe"

//go:noescape
func xorKeyStreamMIPS(dst, src *byte, n int, state *[8]uint32)

var buf [192]byte
var st [12]uint32

func main() {
	xorKeyStreamMIPS(&buf[0], &buf[64], 64, (*[8]uint32)(unsafe.Pointer(&st[0])))
}
"""


def build(asm, tag=None):
    """Assemble asm into work/mipsim/<tag>/prog and return (entry address, code bytes)."""
    src = open(asm, "rb").read()
    tag = tag or hashlib.sha256(src).hexdigest()[:12]
    d = os.path.join(ROOT, "work", "mipsim", tag)
    os.makedirs(d, exist_ok=True)
    open(os.path.join(d, "main.go"), "w").write(MAIN_GO)
    open(os.path.join(d, "x_mipsle.s"), "wb").write(src)
    open(os.path.join(d, "go.mod"), "w").write("module mipsimprog\n\ngo 1.27\n")
    env = dict(os.environ, GOOS="linux", GOARCH="mipsle", GOMIPS="softfloat", CGO_ENABLED="0", GOTOOLCHAIN="local",
               GOFLAGS="-mod=mod", GOCACHE=os.path.join(ROOT, "work", "gocache"), GOPATH=os.path.join(ROOT, "work", "gopath"))
    subprocess.run([GO, "build", "-o", "prog", "."], cwd=d, env=env, check=True)
    return Elf(os.path.join(d, "prog")).function("main.xorKeyStreamMIPS")


def rotl(v, n):
    return ((v << n) | (v >> (32 - n))) & M32


def chacha_block(key, counter, nonce):
    s = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574] + list(key) + [counter] + list(nonce)
    x = s[:]

    def qr(a, b, c, d):
        x[a] = (x[a] + x[b]) & M32; x[d] = rotl(x[d] ^ x[a], 16)
        x[c] = (x[c] + x[d]) & M32; x[b] = rotl(x[b] ^ x[c], 12)
        x[a] = (x[a] + x[b]) & M32; x[d] = rotl(x[d] ^ x[a], 8)
        x[c] = (x[c] + x[d]) & M32; x[b] = rotl(x[b] ^ x[c], 7)

    for _ in range(10):
        qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15)
        qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14)
    return b"".join(struct.pack("<I", (x[i] + s[i]) & M32) for i in range(16))


assert chacha_block([0x03020100, 0x07060504, 0x0B0A0908, 0x0F0E0D0C, 0x13121110, 0x17161514, 0x1B1A1918, 0x1F1E1D1C],
                    1, [0x09000000, 0x4A000000, 0])[:8].hex() == "10f1e7e4d13b5915", "reference self-test (RFC 8439 2.3.2)"

STATE, SRC, DST, SP = 0x10000000, 0x20000000, 0x30000000, 0x7FFF0000


def run(entry, code, key, counter, nonce, src, da, sa, inplace):
    """One call. Returns (Stats, output bytes, new counter)."""
    n = len(src)
    state = Region("state", STATE, 48, struct.pack("<12I", *key, counter, *nonce))
    state.allow_write(32, 4)
    if inplace:
        rs = Region("buf", SRC + sa, n, src, writable=True)
        rd, regions = rs, [rs]
        dst_addr = SRC + sa
    else:
        rs = Region("src", SRC + sa, n, src)
        rd = Region("dst", DST + da, n, writable=True, init=False)
        regions = [rs, rd]
        dst_addr = DST + da
    stack = Region("stack", SP - 4096, 4096 + 64, writable=True, init=False)
    stack.wr[4096:] = bytes(64)                                 # the caller's frame is not ours to write
    stack.data[4096 + 4:4096 + 20] = struct.pack("<4I", dst_addr, SRC + sa, n, STATE)
    stack.init[4096:4096 + 20] = b"\x01" * 20
    cpu = Cpu([state, stack] + regions, entry, code)
    st = cpu.call(entry, SP)
    return st, bytes(rd.data), struct.unpack_from("<I", state.data, 32)[0], bytes(state.data)


def expect(key, counter, nonce, src):
    ks = b"".join(chacha_block(key, (counter + i) & M32, nonce) for i in range(len(src) // 64))
    return bytes(a ^ b for a, b in zip(src, ks))


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    quick = "--quick" in sys.argv
    if len(args) != 1:
        sys.exit(__doc__)
    entry, code = build(args[0])
    print(f"{args[0]}: {len(code)} bytes of code = {len(code) // 4} instructions, "
          f"{(entry + len(code) - 1) // LINE - entry // LINE + 1} cache lines spanned, entry {entry:#x}")
    rng = random.Random(20261119)
    cases = 0
    blocks_list = [1, 2, 3] if quick else [1, 2, 3, 5, 23]
    per = {}
    for inplace in (False, True):
        for da in range(4):
            for sa in range(4):
                if inplace and da != sa:
                    continue
                for blocks in blocks_list:
                    for counter in ([rng.getrandbits(32)] if quick else [rng.getrandbits(32), M32, M32 - 1, 0]):
                        key = [rng.getrandbits(32) for _ in range(8)]
                        nonce = [rng.getrandbits(32) for _ in range(3)]
                        src = rng.randbytes(64 * blocks)
                        try:
                            st, out, newctr, state = run(entry, code, key, counter, nonce, src, da, sa, inplace)
                        except Fault as e:
                            sys.exit(f"FAULT (da={da} sa={sa} blocks={blocks} inplace={inplace} ctr={counter:#x}): {e}")
                        if out != expect(key, counter, nonce, src):
                            sys.exit(f"WRONG OUTPUT (da={da} sa={sa} blocks={blocks} inplace={inplace} ctr={counter:#x})")
                        if newctr != (counter + blocks) & M32:
                            sys.exit(f"WRONG COUNTER (da={da} sa={sa} blocks={blocks}): {newctr:#x}")
                        cases += 1
                        kind = "aligned" if (da | sa) == 0 else "unaligned"
                        per.setdefault((kind, blocks), []).append(st)
    # n == 0: nothing may be read or written (the regions are empty, so any access faults) and the counter stays
    key, nonce = [rng.getrandbits(32) for _ in range(8)], [rng.getrandbits(32) for _ in range(3)]
    try:
        st0, out, newctr, _ = run(entry, code, key, 7, nonce, b"", 0, 0, False)
    except Fault as e:
        sys.exit(f"FAULT (n=0): {e}")
    if out != b"" or newctr != 7:
        sys.exit("WRONG RESULT for n=0")
    cases += 1
    print(f"PASS: {cases} cases (alignments x in-place/disjoint x blocks {blocks_list} x counters incl. wrap, and n=0: "
          f"{st0.instr} instructions)")
    print(f"\n{'path':10} {'blocks':>6} {'instr':>7} {'instr/block':>12} {'I-lines':>8} {'load-use':>9} {'lwl-after-lwr':>14}")
    for (kind, blocks), sts in sorted(per.items()):
        s = sts[0]
        assert all(x.instr == s.instr and len(x.ilines) == len(s.ilines) for x in sts), "counts vary within a class"
        print(f"{kind:10} {blocks:6d} {s.instr:7d} {s.instr / blocks:12.1f} {len(s.ilines):8d} {s.load_use:9d} {s.lwl_after_lwr:14d}")
    for kind in ("aligned", "unaligned"):
        a, b = per[(kind, 1)][0].instr, per[(kind, 2)][0].instr
        print(f"{kind}: {b - a} instructions per additional block, {2 * a - b} per call")
    notes = set().union(*(x.notes for sts in per.values() for x in sts))
    if notes:
        print("notes:", ", ".join(sorted(notes)))
    ops_report(entry, code, rng)


# One AEAD operation = the ChaCha20 calls chacha20poly1305 makes for one message: the Poly1305-key block and a
# tail go through Cipher.buf (always aligned), the full blocks run in place on the message. Sizes as on the
# measured DERP download path (results/2026-11-19_cache-lines.md): WireGuard data 1280 B aligned, TLS record
# around one DERP frame at offset 5, and the small ACK messages in the other direction.
OPS = [
    ("WireGuard data, 1280 B", [(1, 0), (20, 0)]),
    ("TLS record, 1350 B @5", [(1, 0), (21, 1), (1, 0)]),
    ("WireGuard ACK, 64 B", [(1, 0), (1, 0)]),
    ("TLS record, 134 B @5", [(1, 0), (2, 1), (1, 0)]),
]
# measured on the device: wait per cold line; one cycle at 880 MHz (the cores run about one instruction per cycle)
NS_LINE, NS_INSTR = 155.0, 1e9 / 880e6


def ops_report(entry, code, rng):
    print(f"\nper AEAD operation (cold = every line fetched once at {NS_LINE:.0f} ns, + instructions at 880 MHz):")
    print(f"{'operation':24} {'calls':>5} {'blocks':>6} {'instr':>7} {'I-lines':>8} {'cold us':>8} {'warm us':>8}")
    for name, calls in OPS:
        lines, instr, blocks = set(), 0, 0
        for nb, mis in calls:
            key = [rng.getrandbits(32) for _ in range(8)]
            nonce = [rng.getrandbits(32) for _ in range(3)]
            st, _, _, _ = run(entry, code, key, rng.getrandbits(31), nonce, rng.randbytes(64 * nb), mis, mis, True)
            lines |= set(st.ilines)
            instr += st.instr
            blocks += nb
        warm = instr * NS_INSTR / 1000
        print(f"{name:24} {len(calls):5d} {blocks:6d} {instr:7d} {len(lines):8d} {warm + len(lines) * NS_LINE / 1000:8.1f} {warm:8.1f}")


if __name__ == "__main__":
    main()
