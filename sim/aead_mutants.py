#!/usr/bin/env python3
# Copyright (c) 2026 netbrains.ch
# SPDX-License-Identifier: BSD-3-Clause
"""aead_mutants.py <chacha20poly1305_mipsle.s> [--jobs N] : mutation check of aeadMIPS in the interpreter.

Every instruction of the function is replaced by a NOP in turn (deletion mutant) and a fixed kill suite is run:
seal, open and tampered open at several sizes, alignments and additional-data lengths, plus the crafted cases with
an injected Poly1305 key (aead_check.crafted). A mutant is killed by a wrong result or by a Fault of the strict
interpreter (stray read/write, uninitialised use). Survivors are listed with their offset in the function and
their instruction word; each one is either an instruction that only matters for speed, a redundant one, or a gap
in the tests.
"""
import multiprocessing
import os
import random
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import aead_check as ac  # noqa: E402
from mipsim import Fault  # noqa: E402

ENTRY = CODE = None


def suite(entry, code):
    """Raises SystemExit (wrong result) or Fault if the code misbehaves."""
    rng = random.Random(77)
    for n, adlen, da, sa, inplace in [(0, 0, 0, 0, True), (1, 5, 1, 1, True), (16, 0, 0, 0, True), (17, 13, 0, 0, False),
                                      (63, 16, 2, 3, False), (64, 0, 0, 0, True), (65, 17, 3, 3, True), (130, 31, 0, 0, False),
                                      (200, 1, 1, 2, False), (1280, 0, 0, 0, True), (1350, 5, 1, 1, True)]:
        ac.check(entry, code, rng, n, adlen, da, sa, inplace)
    ac.crafted(entry, code, rng)


def one(i):
    code = bytearray(CODE)
    code[4 * i:4 * i + 4] = b"\0\0\0\0"
    devnull = open(os.devnull, "w")
    old = sys.stdout
    sys.stdout = devnull
    try:
        suite(ENTRY, bytes(code))
        return i, None
    except SystemExit as e:
        return i, "wrong: " + str(e)[:60]
    except Fault as e:
        return i, "fault: " + str(e)[:60]
    except Exception as e:  # interpreter-level error on a broken program counts as killed
        return i, "error: " + type(e).__name__
    finally:
        sys.stdout = old
        devnull.close()


def main():
    global ENTRY, CODE
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    jobs = int(sys.argv[sys.argv.index("--jobs") + 1]) if "--jobs" in sys.argv else 6
    if "--jobs" in sys.argv:
        args = [a for a in args if a != str(jobs)]
    ENTRY, CODE = ac.build(args[0])
    suite(ENTRY, CODE)                                           # the unmutated code must pass
    idx = [i for i in range(len(CODE) // 4) if CODE[4 * i:4 * i + 4] != b"\0\0\0\0"]
    with multiprocessing.Pool(jobs) as pool:
        res = pool.map(one, idx, chunksize=8)
    surv = [i for i, r in res if r is None]
    kinds = {}
    for i, r in res:
        if r:
            kinds[r.split(":")[0]] = kinds.get(r.split(":")[0], 0) + 1
    print(f"{len(idx)} deletion mutants: {len(idx) - len(surv)} killed ({kinds}), {len(surv)} survived")
    for i in surv:
        print(f"  survivor +{4 * i:#05x} {struct.unpack_from('<I', CODE, 4 * i)[0]:#010x}")

if __name__ == "__main__":
    main()
