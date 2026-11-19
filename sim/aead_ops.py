#!/usr/bin/env python3
# Copyright (c) 2026 netbrains.ch
# SPDX-License-Identifier: BSD-3-Clause
"""aead_ops.py <linux/mipsle Go binary> [--detail] [--verify N] : run the ChaCha20-Poly1305 Seal/Open of a built
binary (for example build/tailscaled-mipsle-chacha, stripped or not) in the strict interpreter and report, per
AEAD operation, the instructions executed and the instruction-cache lines touched - Go glue, runtime helpers and
assembly together. This is the per-packet crypto path exactly as built (PGO inlining included).

Both copies are measured: golang.org/x/crypto (WireGuard) and vendor/golang.org/x/crypto (crypto/tls, DERP).
Every result is checked against a reference ChaCha20-Poly1305 written here (RFC 8439), so the numbers come from
code that produced the right bytes.

--verify N first runs N random Seal / Open / tampered-Open operations (sizes 0..1500, offsets, AD lengths) against
the reference. --detail lists instructions and lines per function.

Cost model (results/2026-11-19_cache-lines.md): cold = every line fetched once at ~155 ns + instructions at
880 MHz; warm = instructions only.
Nothing runs on the device.
"""
import bisect
import os
import random
import struct
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mipsim import Cpu, Elf, Fault, Region, LINE, M32  # noqa: E402
from chacha_check import chacha_block, ROOT, GO  # noqa: E402

NS_LINE, NS_INSTR = 155.0, 1e9 / 880e6
G_ADDR, STACK_LO, STACK_SIZE, HEAP = 0x60000000, 0x70000000, 1 << 18, 0x50000000


def poly1305(msg, key):
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:32], "little")
    acc, p = 0, (1 << 130) - 5
    for i in range(0, len(msg), 16):
        blk = msg[i:i + 16]
        acc = (acc + int.from_bytes(blk, "little") + (1 << (8 * len(blk)))) * r % p
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")


def aead_seal(key, nonce, pt, ad):
    kw, nw = list(struct.unpack("<8I", key)), list(struct.unpack("<3I", nonce))
    polykey = chacha_block(kw, 0, nw)[:32]
    ks = b"".join(chacha_block(kw, 1 + i, nw) for i in range((len(pt) + 63) // 64))
    ct = bytes(a ^ b for a, b in zip(pt, ks))
    pad = lambda b: b + bytes(-len(b) % 16)
    return ct + poly1305(pad(ad) + pad(ct) + struct.pack("<QQ", len(ad), len(ct)), polykey)


assert aead_seal(bytes(range(0x80, 0xA0)), bytes.fromhex("070000004041424344454647"),
                 b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.",
                 bytes.fromhex("50515253c0c1c2c3c4c5c6c7"))[-16:].hex() == "1ae10b594f09e26a7e902ecbd0600691", "RFC 8439 2.8.2"


class GoBinary:
    def __init__(self, path):
        self.path = path
        self.elf = Elf(path)
        helper = os.path.join(ROOT, "work", "mipsim", "gofuncs")
        if not os.path.exists(helper):
            env = dict(os.environ, GOTOOLCHAIN="local", GOCACHE=os.path.join(ROOT, "work", "gocache-host"))
            subprocess.run([GO, "build", "-o", helper, "."], cwd=os.path.join(ROOT, "sim", "gofuncs"), env=env, check=True)
        out = subprocess.run([helper, path], capture_output=True, text=True, check=True).stdout
        self.funcs = sorted((int(a, 16), int(b, 16), n) for n, a, b in (l.split("\t") for l in out.splitlines()))
        self.starts = [f[0] for f in self.funcs]
        self.byname = {n: a for a, b, n in self.funcs}

    def func_at(self, pc):
        i = bisect.bisect_right(self.starts, pc) - 1
        if i >= 0 and self.funcs[i][0] <= pc < self.funcs[i][1]:
            return self.funcs[i][2]
        return "?"

    def machine(self):
        """Fresh memory image: ELF segments, a fake g (stack guard far below), a stack and a small heap."""
        regions, text = [], None
        for vaddr, data, memsz, flags in self.elf.segments:
            r = Region(f"seg@{vaddr:#x}", vaddr, memsz, data + bytes(memsz - len(data)), writable=bool(flags & 2))
            regions.append(r)
            if flags & 1:
                text = r
        g = Region("g", G_ADDR, 512)
        struct.pack_into("<4I", g.data, 0, STACK_LO, STACK_LO + STACK_SIZE, STACK_LO + 2048, STACK_LO + 2048)
        stack = Region("stack", STACK_LO, STACK_SIZE, writable=True, init=False)
        heap = Region("heap", HEAP, 1 << 16, writable=True)
        cpu = Cpu([stack, heap, g] + regions, text.base, bytes(text.data), go_mode=True)
        return cpu, stack, heap


def call(binary, cpu, stack, fn, words, nres):
    """Call a Go function (stack ABI): words = argument words; returns (Stats, result words)."""
    sp = STACK_LO + STACK_SIZE - 512
    o = sp - STACK_LO
    struct.pack_into(f"<{len(words)}I", stack.data, o + 4, *words)
    stack.init[o:o + 4 + 4 * len(words)] = b"\x01" * (4 + 4 * len(words))
    st = cpu.call(binary.byname[fn], sp, max_instr=3_000_000, g=G_ADDR)
    return st, struct.unpack_from(f"<{nres}I", stack.data, o + 4 + 4 * len(words))


def run_op(binary, pkg, op, n, off, adlen, rng, tamper=False):
    """One Seal or Open of n plaintext bytes, in place at buffer offset off, AD of adlen bytes at offset 0.
    Returns Stats (of the measured call). tamper (Open only): flip one bit of ciphertext, tag or AD and expect
    an error and no plaintext."""
    cpu, stack, heap = binary.machine()
    key, nonce = rng.randbytes(32), rng.randbytes(12)
    pt, ad = rng.randbytes(n), rng.randbytes(adlen)
    want = aead_seal(key, nonce, pt, ad)
    C, NONCE, BUF = HEAP, HEAP + 64, HEAP + 4096           # BUF is 32-byte aligned; data at BUF+off
    heap.data[0:32] = key
    heap.data[64:76] = nonce
    b = BUF - HEAP
    heap.data[b:b + adlen] = ad
    cap = off + n + 16 + 64
    recv = f"{pkg}/chacha20poly1305.(*chacha20poly1305)"
    if recv + ".Open" not in binary.byname:                # a test program has only the x/crypto copy
        recv = "golang.org/x/crypto/chacha20poly1305.(*chacha20poly1305)"
    if op == "seal":
        heap.data[b + off:b + off + n] = pt
        # Seal(dst = buf[:off], nonce, plaintext = buf[off:off+n], ad = buf[:adlen])
        st, res = call(binary, cpu, stack, recv + ".Seal",
                       [C, BUF, off, cap, NONCE, 12, 12, BUF + off, n, cap - off, BUF, adlen, adlen], 3)
        got = bytes(heap.data[b + off:b + off + n + 16])
        if res[0] != BUF or res[1] != off + n + 16 or got != want:
            raise SystemExit(f"{pkg} seal n={n} off={off}: wrong result")
    elif tamper:
        bad = bytearray(want)
        where = rng.randrange(n + 16 + adlen)
        if where < n + 16:
            bad[where] ^= 1 << rng.randrange(8)
        else:
            heap.data[b + where - n - 16] ^= 1 << rng.randrange(8)
        heap.data[b + off:b + off + n + 16] = bad
        st, res = call(binary, cpu, stack, recv + ".Open",
                       [C, BUF + off, 0, cap - off, NONCE, 12, 12, BUF + off, n + 16, cap - off, BUF, adlen, adlen], 5)
        got = bytes(heap.data[b + off:b + off + n])
        if res[3] == 0 or res[0] != 0 or res[1] != 0:
            raise SystemExit(f"{pkg} open n={n} off={off}: tampered message accepted")
        if n and got == pt:
            raise SystemExit(f"{pkg} open n={n} off={off}: plaintext released for a tampered message")
    else:
        heap.data[b + off:b + off + n + 16] = want
        # Open(dst = buf[off:off], nonce, ciphertext = buf[off:off+n+16], ad = buf[:adlen])
        st, res = call(binary, cpu, stack, recv + ".Open",
                       [C, BUF + off, 0, cap - off, NONCE, 12, 12, BUF + off, n + 16, cap - off, BUF, adlen, adlen], 5)
        got = bytes(heap.data[b + off:b + off + n])
        if res[3] != 0 or res[4] != 0 or res[0] != BUF + off or res[1] != n or got != pt:
            raise SystemExit(f"{pkg} open n={n} off={off}: wrong result (err={res[3]:#x})")
    return st


def by_function(binary, st):
    instr, lines = {}, {}
    for pc, c in st.pc_count.items():
        f = binary.func_at(pc)
        instr[f] = instr.get(f, 0) + c
    for ln in st.ilines:                                   # a line belongs to the function of its first executed pc
        pcs = [pc for pc in range(ln * LINE, ln * LINE + LINE, 4) if pc in st.pc_count]
        f = binary.func_at(min(pcs))
        lines[f] = lines.get(f, 0) + 1
    return instr, lines


def short(name):
    name = name.replace("vendor/golang.org/x/crypto/", "v/").replace("golang.org/x/crypto/", "x/")
    return name.replace("(*chacha20poly1305)", "(*c)").replace("internal/poly1305", "poly1305")


# Operations of the measured DERP download path; AD: none for WireGuard, the 5-byte record header for TLS.
OPS = [
    ("WireGuard open 1280 B", "golang.org/x/crypto", "open", 1280, 16, 0),
    ("TLS open 1350 B @5", "vendor/golang.org/x/crypto", "open", 1350, 5, 5),
    ("WireGuard seal 64 B (ACK)", "golang.org/x/crypto", "seal", 64, 16, 0),
    ("TLS seal 134 B @5 (ACK)", "vendor/golang.org/x/crypto", "seal", 134, 5, 5),
]


def verify(binary, count, rng):
    """Random Seal/Open/tampered-Open over sizes, offsets and AD lengths, both copies."""
    sizes = list(range(0, 200)) + [255, 256, 257, 1279, 1280, 1281, 1344, 1350, 1408, 1420, 1500]
    done = 0
    while done < count:
        for pkg in ("golang.org/x/crypto", "vendor/golang.org/x/crypto"):
            n, off, adlen = rng.choice(sizes), rng.randrange(0, 33), rng.choice([0, 0, 5, 5, 13, 16, 31])
            off = max(off, adlen)                         # AD sits before the data in the buffer
            for op, tamper in (("seal", False), ("open", False), ("open", True)):
                try:
                    run_op(binary, pkg, op, n, off, adlen, rng, tamper)
                except Fault as e:
                    raise SystemExit(f"FAULT {pkg} {op} n={n} off={off} ad={adlen}: {e}")
                done += 1
    print(f"verify: {done} operations OK (seal, open, tampered open; sizes 0..1500, offsets 0..32, AD 0..31; both copies)")


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    detail = "--detail" in sys.argv
    nverify = 0
    if "--verify" in args or "--verify" in sys.argv:
        i = sys.argv.index("--verify")
        nverify = int(sys.argv[i + 1])
        args = [a for a in args if a != sys.argv[i + 1]]
    if len(args) != 1:
        sys.exit(__doc__)
    binary = GoBinary(args[0])
    rng = random.Random(8439)
    if nverify:
        verify(binary, nverify, rng)
    print(f"{args[0]}")
    print(f"{'operation':28} {'instr':>7} {'asm instr':>10} {'Go instr':>9} {'I-lines':>8} {'asm':>5} {'Go':>5} {'cold us':>8} {'warm us':>8}")
    tot = [0.0, 0.0]
    weights = {0: 1.0, 1: 1.0, 2: 0.46, 3: 0.46}           # per data packet: 0.46 ACKs (measured)
    for i, (name, pkg, op, n, off, adlen) in enumerate(OPS):
        st = run_op(binary, pkg, op, n, off, adlen, rng)
        instr, lines = by_function(binary, st)
        is_asm = lambda f: f.endswith(("xorKeyStreamMIPS", "poly1305.updateBlocks", "chacha20poly1305.aeadMIPS"))
        ai = sum(v for f, v in instr.items() if is_asm(f))
        al = sum(v for f, v in lines.items() if is_asm(f))
        nl = len(st.ilines)
        warm = st.instr * NS_INSTR / 1000
        cold = warm + nl * NS_LINE / 1000
        tot[0] += weights[i] * cold
        tot[1] += weights[i] * warm
        print(f"{name:28} {st.instr:7d} {ai:10d} {st.instr - ai:9d} {nl:8d} {al:5d} {nl - al:5d} {cold:8.1f} {warm:8.1f}")
        if detail:
            for f in sorted(instr, key=lambda f: -lines.get(f, 0)):
                print(f"      {short(f)[:66]:66} {instr[f]:7d} instr {lines.get(f, 0):4d} lines")
            if st.uninit_reads:
                print(f"      (reads of never-written memory: {st.uninit_reads})")
    print(f"per data packet (open WG + open TLS + 0.46 x both ACK seals): cold {tot[0]:.1f} us, warm {tot[1]:.1f} us")


if __name__ == "__main__":
    main()
