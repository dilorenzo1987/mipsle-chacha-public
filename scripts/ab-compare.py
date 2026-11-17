#!/usr/bin/env python3
# Copyright (c) 2026 netbrains.ch
# SPDX-License-Identifier: BSD-3-Clause
#
# Compare interleaved runs of bench/sweep. Input: a file with blocks
#   ## <label> <run>
#   <sweep output lines>
# Usage: ab-compare.py <file> <labelA> <labelB>
# Prints per case: median ns/op of A and B, the change, the min-max range, and
# in how many of the paired runs (A run i vs B run i) B was faster. With the
# ~3 % run-to-run noise on the router, only trust small changes that are
# consistent across pairs.
import re
import statistics
import sys

path, a, b = sys.argv[1], sys.argv[2], sys.argv[3]
data, label = {}, None
for line in open(path, encoding='utf-8', errors='replace'):
    if line.startswith('## '):
        label = line.split()[1]
        continue
    m = re.match(r'(.+?)\s+(\d+) ns/op', line)
    if m and label:
        data.setdefault(m.group(1).strip(), {}).setdefault(label, []).append(int(m.group(2)))

print('%-26s %9s %9s %7s  %-15s %-15s %s' % ('case', a, b, 'change', a + ' range', b + ' range', b + ' faster'))
for case, runs in data.items():
    xa, xb = runs.get(a, []), runs.get(b, [])
    if not xa or not xb:
        continue
    ma, mb = statistics.median(xa), statistics.median(xb)
    wins = sum(1 for p, q in zip(xa, xb) if q < p)
    print('%-26s %9.0f %9.0f %+6.1f%%  %-15s %-15s %d/%d' % (
        case, ma, mb, 100 * (mb - ma) / ma,
        '%d-%d' % (min(xa), max(xa)), '%d-%d' % (min(xb), max(xb)),
        wins, min(len(xa), len(xb))))
