#!/usr/bin/env python3
# Copyright (c) 2026 netbrains.ch
# SPDX-License-Identifier: BSD-3-Clause
"""aead_check.py <chacha20poly1305_mipsle.s> [--quick] : run aeadMIPS from an assembly file in the strict
interpreter (mipsim.py), compare with a reference ChaCha20-Poly1305 (RFC 8439) and report instruction and
cache-line counts.

Strict memory rules per call: key, nonce, additional data and src are read-only and exactly as long as declared
(any byte read beyond them faults); dst is writable only in dst[0:n] (plus the 16 tag bytes when sealing) and
starts unwritten unless the operation is in place; on the stack only the function's own frame and its result slot
may be written. Checks: seal output and tag; open output and result 1; a tampered message (one bit flipped in
data, tag or additional data) gives result 0 and not a single byte written to dst.

Cases: every n in 0..130 with several additional-data lengths, larger sizes around the packet sizes, all
alignment pairs of dst and src, unaligned key / nonce / additional data, in place and disjoint.
Nothing runs on the device.
"""
import hashlib
import os
import random
import struct
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mipsim import Cpu, Elf, Fault, Region, LINE  # noqa: E402
from chacha_check import ROOT, GO  # noqa: E402
from aead_ops import aead_seal, NS_LINE, NS_INSTR  # noqa: E402

MAIN_GO = """package main

//go:noescape
func aeadMIPS(key *[32]byte, nonce *byte, dst, src *byte, n int, ad *byte, adLen int, open int) int

var k [32]byte
var b [256]byte

func main() {
	println(aeadMIPS(&k, &b[0], &b[16], &b[16], 64, &b[0], 0, 0))
}
"""

KEY, NONCE, AD, SRC, DST, SP = 0x10000000, 0x11000000, 0x12000000, 0x20000000, 0x30000000, 0x7FFF0000


def build(asm):
    src = open(asm, "rb").read()
    d = os.path.join(ROOT, "work", "mipsim", "aead-" + hashlib.sha256(src).hexdigest()[:12])
    os.makedirs(d, exist_ok=True)
    open(os.path.join(d, "main.go"), "w").write(MAIN_GO)
    open(os.path.join(d, "x_mipsle.s"), "wb").write(src)
    open(os.path.join(d, "go.mod"), "w").write("module mipsimprog\n\ngo 1.27\n")
    env = dict(os.environ, GOOS="linux", GOARCH="mipsle", GOMIPS="softfloat", CGO_ENABLED="0", GOTOOLCHAIN="local",
               GOFLAGS="-mod=mod", GOCACHE=os.path.join(ROOT, "work", "gocache"), GOPATH=os.path.join(ROOT, "work", "gopath"))
    subprocess.run([GO, "build", "-o", "prog", "."], cwd=d, env=env, check=True)
    return Elf(os.path.join(d, "prog")).function("main.aeadMIPS")


def first_call_site(entry, code):
    """Address of the first BGEZAL (the key-block call) in the function."""
    for off in range(0, len(code), 4):
        (w,) = struct.unpack_from("<I", code, off)
        if w >> 26 == 1 and (w >> 16) & 31 == 0x11:
            return entry + off
    raise ValueError("no BGEZAL found")


def poly_key_hooks(entry, code, polykey):
    """Hooks that replace the Poly1305 key (kb[0:32]) right after the key block was computed."""
    site, box = first_call_site(entry, code), {}

    def at_call(cpu, reg):
        box.setdefault("kb", reg[17])                            # dst of the key block = kb

    def after_call(cpu, reg):
        if "done" not in box:
            r = cpu._region(box["kb"], 32, "inject")
            o = box["kb"] - r.base
            r.data[o:o + 32] = polykey
            box["done"] = True

    return {site: at_call, site + 8: after_call}


def run(entry, code, key, nonce, ad, data, tag, mode, da, sa, inplace, ka=0, na=0, aa=0, hooks=None):
    """One call. data = plaintext (seal) or ciphertext (open, tag = received tag).
    Returns (Stats, result, dst region bytes, its per-byte 'written' flags, its bytes before the call)."""
    n = len(data)
    rkey = Region("key", KEY + ka, 32, key)
    rnonce = Region("nonce", NONCE + na, 12, nonce)
    regions = [rkey, rnonce]
    if ad:
        regions.append(Region("ad", AD + aa, len(ad), ad))
    src_bytes = data + (tag if mode == 1 else b"")
    if inplace:
        size = n + 16
        rd = Region("buf", SRC + sa, size, src_bytes + bytes(size - len(src_bytes)), writable=False, init=False)
        rd.init[:len(src_bytes)] = b"\x01" * len(src_bytes)
        rd.allow_write(0, n + (16 if mode == 0 else 0))
        dst_addr = src_addr = SRC + sa
        regions.append(rd)
    else:
        if src_bytes:
            regions.append(Region("src", SRC + sa, len(src_bytes), src_bytes))
        size = n + (16 if mode == 0 else 0)
        rd = Region("dst", DST + da, max(size, 1), writable=False, init=False)
        rd.allow_write(0, size)
        regions.append(rd)
        dst_addr, src_addr = DST + da, SRC + sa
    stack = Region("stack", SP - 4096, 4096 + 64, writable=True, init=False)
    stack.wr[4096:] = bytes(64)
    args = [KEY + ka, NONCE + na, dst_addr, src_addr, n, (AD + aa) if ad else 0, len(ad), mode]
    stack.data[4096 + 4:4096 + 36] = struct.pack("<8I", *args)
    stack.init[4096:4096 + 36] = b"\x01" * 36
    stack.allow_write(4096 + 36, 4)                              # the result slot
    before = bytes(rd.data)
    cpu = Cpu([stack] + regions, entry, code)
    st = cpu.call(entry, SP, max_instr=2_000_000, allow_lr_scratch=True, hooks=hooks)
    (res,) = struct.unpack_from("<I", stack.data, 4096 + 36)
    return st, res, bytes(rd.data), bytes(rd.init), before


def check(entry, code, rng, n, adlen, da, sa, inplace, stats=None):
    key, nonce, ad, pt = rng.randbytes(32), rng.randbytes(12), rng.randbytes(adlen), rng.randbytes(n)
    ka, na, aa = rng.randrange(4), rng.randrange(4), rng.randrange(4)
    want = aead_seal(key, nonce, pt, ad)
    ct, tag = want[:n], want[n:]
    what = f"n={n} ad={adlen} da={da} sa={sa} inplace={inplace} ka={ka} na={na} aa={aa}"
    try:
        st, res, out, init, _ = run(entry, code, key, nonce, ad, pt, b"", 0, da, sa, inplace, ka, na, aa)
        if out[:n + 16] != want or res != 1:
            sys.exit(f"SEAL WRONG ({what})")
        if stats is not None:
            stats[("seal", n, adlen, (da | sa) != 0)] = st
        st, res, out, init, _ = run(entry, code, key, nonce, ad, ct, tag, 1, da, sa, inplace, ka, na, aa)
        if res != 1 or out[:n] != pt:
            sys.exit(f"OPEN WRONG ({what}): result {res}")
        if stats is not None:
            stats[("open", n, adlen, (da | sa) != 0)] = st
        # tampered: one bit in ciphertext, tag or additional data
        bad_ct, bad_tag, bad_ad = bytearray(ct), bytearray(tag), bytearray(ad)
        where = rng.randrange(n + 16 + adlen)
        if where < n:
            bad_ct[where] ^= 1 << rng.randrange(8)
        elif where < n + 16:
            bad_tag[where - n] ^= 1 << rng.randrange(8)
        else:
            bad_ad[where - n - 16] ^= 1 << rng.randrange(8)
        st, res, out, init, before = run(entry, code, key, nonce, bytes(bad_ad), bytes(bad_ct), bytes(bad_tag), 1, da, sa, inplace, ka, na, aa)
        if res != 0:
            sys.exit(f"TAMPERED MESSAGE ACCEPTED ({what}, bit in byte {where})")
        if out != before or (not inplace and any(init[:n])):
            sys.exit(f"WRITE TO DST FOR A TAMPERED MESSAGE ({what})")
    except Fault as e:
        sys.exit(f"FAULT ({what}): {e}")
    return 3


def crafted(entry, code, rng):
    """Edge cases random data never reaches, with an injected Poly1305 key (r, s): the final h just below, at and
    above p = 2^130 - 5 (the constant-time final subtraction), full carry chains in h + s, and maximal limbs."""
    from aead_ops import poly1305
    from chacha_check import chacha_block
    n_ok = 0
    key, nonce = rng.randbytes(32), rng.randbytes(12)
    kw, nw = list(struct.unpack("<8I", key)), list(struct.unpack("<3I", nonce))
    ks = b"".join(chacha_block(kw, 1 + i, nw) for i in range(4))
    pad = lambda b: b + bytes(-len(b) % 16)
    cases = []
    r1 = (1).to_bytes(16, "little")
    for delta in range(-3, 9):                                   # r = 1: h before the final reduction = p + delta
        b1 = 1 << 127
        b2 = (1 << 127) - 5 - (32 << 64) + delta
        ct = b1.to_bytes(16, "little") + b2.to_bytes(16, "little")
        for s in (bytes(16), b"\xff" * 16, (5 - delta if 0 <= 5 - delta else 0).to_bytes(16, "little"), rng.randbytes(16)):
            cases.append((f"h=p{delta:+d}", r1 + s, b"", ct))
    # r = 1 again, the sum before the final steps chosen limb by limb (found by the mutation check):
    M, ONES = (1 << 128), 0xFFFFFFFF
    limbs = lambda h3, h2, h1, h0: (h3 << 96) | (h2 << 64) | (h1 << 32) | h0
    for k in range(1, 6):                                        # sum = 5*2^128 - k: adding c5 = 5 ripples through every limb
        b2 = M - (k - 1) - (32 << 64)
        for s in (bytes(16), rng.randbytes(16)):
            cases.append((f"c5 ripple k={k}", r1 + s, b"", (M - 1).to_bytes(16, "little") + b2.to_bytes(16, "little")))
    for name, t in (("g carry stops at limb 1", limbs(ONES, ONES, 0x12345678, ONES)),
                    ("g carry stops at limb 2", limbs(ONES, 0x12345678, ONES, ONES)),
                    ("g carry stops at limb 3", limbs(0x12345678, ONES, ONES, ONES)),
                    ("g carry stops at limb 1, low", limbs(7, 9, 0x12345678, ONES - 2))):
        for s in (bytes(16), rng.randbytes(16)):
            # top limb 3 (two data blocks + lengths block), h < p: the comparison must not be fooled by a stale carry
            cases.append((name + " h4=3", r1 + s, b"", (t - (32 << 64)).to_bytes(16, "little") + bytes(16)))
            # top limb 2 (one AD block + lengths block, no data): g differs from h in several limbs but is not selected
            cases.append((name + " h4=2", r1 + s, (t - 16).to_bytes(16, "little"), b""))
    # r = 2, one data block m and the lengths block: the value before the final fold is 2*(3*2^128 + 2*m + 16*2^64),
    # so its top limb d4 (6 or 7) and low 128 bits can be set exactly. c5 = 5 is then added to chosen low limbs.
    r2 = (2).to_bytes(16, "little")
    lw = 16 << 64
    for name, m in (("c5 carry into h4 decides h >= p", (1 << 127) - 1 - lw // 2),
                    ("c5 carry stops at limb 2", limbs(0x01234567, 0x89ABCDEF, ONES, ONES - 3) // 4 - lw // 2),
                    ("c5 carry stops at limb 3, h4=3", (1 << 126) + limbs(0x01234567, ONES, ONES, ONES - 3) // 4 - lw // 2)):
        for s in (bytes(16), rng.randbytes(16)):
            cases.append((name, r2 + s, b"", m.to_bytes(16, "little")))
    rmax = bytes.fromhex("ffffff0f" + "fcffff0f" * 3)            # all clamped bits set
    for n in (16, 32, 48, 64, 80, 1280):
        for s in (b"\xff" * 16, rng.randbytes(16)):
            cases.append((f"rmax ff n={n}", rmax + s, b"\xff" * 13, b"\xff" * n))
            cases.append((f"rmax rnd n={n}", rmax + s, rng.randbytes(5), rng.randbytes(n)))
    for _ in range(40):                                          # random keys through the same injection path
        n = rng.choice([0, 1, 15, 16, 17, 63, 64, 65, 200])
        cases.append((f"rnd n={n}", rng.randbytes(32), rng.randbytes(rng.choice([0, 5, 16, 20])), rng.randbytes(n)))
    for name, pk, ad, ct in cases:
        n = len(ct)
        tag = poly1305(pad(ad) + pad(ct) + struct.pack("<QQ", len(ad), n), pk)
        pt = bytes(a ^ b for a, b in zip(ct, (ks * (n // len(ks) + 1))[:n])) if n <= len(ks) else None
        try:
            st, res, out, _, _ = run(entry, code, key, nonce, ad, ct, tag, 1, 0, 0, True, hooks=poly_key_hooks(entry, code, pk))
            if res != 1 or (pt is not None and out[:n] != pt):
                sys.exit(f"CRAFTED OPEN WRONG ({name}): result {res}")
            bad = bytearray(tag); bad[rng.randrange(16)] ^= 1 << rng.randrange(8)
            st, res, out, _, before = run(entry, code, key, nonce, ad, ct, bytes(bad), 1, 0, 0, True, hooks=poly_key_hooks(entry, code, pk))
            if res != 0 or out != before:
                sys.exit(f"CRAFTED TAMPERED ACCEPTED ({name})")
            if pt is not None:
                st, res, out, _, _ = run(entry, code, key, nonce, ad, pt, b"", 0, 0, 0, True, hooks=poly_key_hooks(entry, code, pk))
                if out[:n] != ct or out[n:n + 16] != tag:
                    sys.exit(f"CRAFTED SEAL WRONG ({name})")
                n_ok += 1
            n_ok += 2
        except Fault as e:
            sys.exit(f"FAULT (crafted {name}): {e}")
    print(f"PASS: {n_ok} crafted operations with an injected Poly1305 key (final h around p, carry chains, maximal limbs)")


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    quick = "--quick" in sys.argv
    if len(args) != 1:
        sys.exit(__doc__)
    entry, code = build(args[0])
    print(f"{args[0]}: {len(code)} bytes of code = {len(code) // 4} instructions, "
          f"{(entry + len(code) - 1) // LINE - entry // LINE + 1} cache lines spanned")
    rng = random.Random(8439)
    crafted(entry, code, rng)
    cases = 0
    small = range(0, 131, 7 if quick else 1)
    adlens = [0, 5, 13, 16] if quick else [0, 1, 5, 12, 13, 15, 16, 17, 31, 32, 33]
    for n in small:
        for adlen in adlens:
            da, sa, inplace = rng.randrange(4), rng.randrange(4), rng.random() < 0.5
            cases += check(entry, code, rng, n, adlen, sa if inplace else da, sa, inplace)
    for n in ([255, 1280, 1350] if quick else [191, 192, 193, 255, 256, 257, 1279, 1280, 1281, 1344, 1350, 1408, 1420, 1500]):
        for da in range(4):
            for sa in range(4):
                for inplace in (False, True):
                    if inplace and da != sa:
                        continue
                    if quick and (da, sa) not in ((0, 0), (1, 1), (0, 3)):
                        continue
                    cases += check(entry, code, rng, n, rng.choice(adlens), da, sa, inplace)
    print(f"PASS: {cases} operations (seal, open, tampered open; n 0..130 x AD lengths {adlens}, larger sizes x all alignments)")

    stats = {}
    ops = [("WireGuard open 1280 B", "open", 1280, 0, 0), ("TLS open 1350 B @5", "open", 1350, 5, 1),
           ("WireGuard seal 64 B (ACK)", "seal", 64, 0, 0), ("TLS seal 134 B @5 (ACK)", "seal", 134, 5, 1)]
    print(f"\n{'operation (assembly only)':28} {'instr':>7} {'I-lines':>8} {'cold us':>8} {'warm us':>8} {'load-use':>9}")
    tot, w = [0.0, 0.0], [1, 1, 0.46, 0.46]
    for i, (name, op, n, adlen, mis) in enumerate(ops):
        check(entry, code, rng, n, adlen, mis, mis, True, stats)
        st = stats[(op, n, adlen, mis != 0)]
        warm = st.instr * NS_INSTR / 1000
        cold = warm + len(st.ilines) * NS_LINE / 1000
        tot[0] += w[i] * cold
        tot[1] += w[i] * warm
        print(f"{name:28} {st.instr:7d} {len(st.ilines):8d} {cold:8.1f} {warm:8.1f} {st.load_use:9d}")
    print(f"per data packet (two opens + 0.46 x both seals), assembly only: cold {tot[0]:.1f} us, warm {tot[1]:.1f} us")
    notes = set().union(*(s.notes for s in stats.values()))
    if notes:
        print("notes:", ", ".join(sorted(notes)))


if __name__ == "__main__":
    main()
