#!/usr/bin/env python3
# Copyright (c) 2026 netbrains.ch
# SPDX-License-Identifier: BSD-3-Clause
#
# Generate single-instruction deletion mutants of overlay/poly1305/sum_mipsle.s.
# Usage: mutants-poly1305.py <sum_mipsle.s> <out-dir>
# Writes <out-dir>/mNN.s and prints "mNN <line> [<section>] <instruction>".
#
# Mutated: every instruction of the FOLD macro, the message add and its
# carries in BLOCK, the carry-ins (MADDU R24, R21), the MUL, the exit carry
# propagation after "store:", and the prologue's "MOVW $0, R24". Products,
# HI/LO reads and loads are left alone (deleting them breaks everything).
# A deleted line becomes NOOP (emits nothing), keeping macro continuations.
import os
import sys

BS = '\\'
src = open(sys.argv[1], encoding='utf-8').read().split('\n')
out = sys.argv[2]
os.makedirs(out, exist_ok=True)

cands, sec = [], None
for i, line in enumerate(src):
    t = line.strip().rstrip(BS).strip()
    if t == 'MOVW\t$0, R24' or t == 'MOVW $0, R24':
        cands.append((i, 'ENTRY', t))
        continue
    if line.startswith('#define FOLD'):
        sec = 'FOLD'
        continue
    if line.startswith('#define BLOCK'):
        sec = 'BLOCK'
        continue
    if line.startswith('store:'):
        sec = 'STORE'
        continue
    if sec is None:
        continue
    if t == '' or t.startswith('//'):
        if t == '':
            sec = None
        continue
    if sec == 'STORE' and t.startswith('MOVW'):
        sec = None
        continue
    if t == 'FOLD':
        continue
    if sec == 'BLOCK' and (t.startswith('MULU') or t.startswith('MOVW') or
                           (t.startswith('MADDU') and '24, 21' not in t)):
        continue
    cands.append((i, sec, t))

for n, (i, sec, t) in enumerate(cands, 1):
    m = src[:]
    m[i] = '\tNOOP ' + BS if src[i].rstrip().endswith(BS) else '\tNOOP'
    with open(os.path.join(out, 'm%02d.s' % n), 'w', encoding='utf-8', newline='') as f:
        f.write('\n'.join(m))
    print('m%02d %d [%s] %s' % (n, i + 1, sec, ' '.join(t.split())))
