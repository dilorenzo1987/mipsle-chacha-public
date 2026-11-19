# Copyright (c) 2026 netbrains.ch
# SPDX-License-Identifier: BSD-3-Clause
"""mipsim: a strict user-mode interpreter for the MIPS32r2 (little endian) subset the assembly in overlay/ uses.

Purpose: run an assembly function taken from a linux/mipsle ELF on the development host, check it against a
reference, and count what matters on the MT7621 (see results/2026-11-19_cache-lines.md): instructions executed,
distinct 32-byte instruction-cache lines touched, data lines touched, load-use stalls.

Strict on purpose - it raises Fault for anything the real code must never do:
  * LW/SW/LH/SH at an unaligned address (the kernel would emulate that, very slowly)
  * a read of a register, HI/LO or memory byte that was never written
  * a memory access outside the declared regions, a write to a read-only byte
  * a write to R26/R27 (kernel) or R30 (g); R29 (SP) and R31 (LR) must hold their entry values at return
  * an instruction outside the modelled subset, a branch in a delay slot, running past the instruction limit

This is not a timing model: it counts events. Cost estimates in the other scripts use two constants measured on
the device: about 155 ns to fetch a cache line that is in neither cache, and about one cycle per instruction.
"""
import struct

LINE = 32
M32 = 0xFFFFFFFF


class Fault(Exception):
    pass


class Region:
    """A byte range with per-byte 'initialised' and 'writable' flags."""

    def __init__(self, name, base, size, data=None, writable=False, init=True):
        self.name, self.base, self.size = name, base, size
        self.data = bytearray(data) if data is not None else bytearray(size)
        if len(self.data) != size:
            raise ValueError("data size")
        self.init = bytearray([1 if init else 0]) * size
        self.wr = bytearray([1 if writable else 0]) * size
        self.end = base + size

    def allow_write(self, off, n):
        self.wr[off:off + n] = b"\x01" * n


class Elf:
    """Just enough ELF32-LE to pull one function's bytes and address out of a Go binary."""

    def __init__(self, path):
        self.b = b = open(path, "rb").read()
        if b[:4] != b"\x7fELF" or b[4] != 1 or b[5] != 1:
            raise ValueError("not a 32-bit little-endian ELF")
        (shoff,) = struct.unpack_from("<I", b, 0x20)
        shentsize, shnum, shstrndx = struct.unpack_from("<HHH", b, 0x2E)
        self.sections = []
        for i in range(shnum):
            name, typ, flags, addr, off, size, link, info, align, entsize = struct.unpack_from("<10I", b, shoff + i * shentsize)
            self.sections.append(dict(name=name, type=typ, addr=addr, off=off, size=size, link=link, entsize=entsize))
        (phoff,) = struct.unpack_from("<I", b, 0x1C)
        phentsize, phnum = struct.unpack_from("<HH", b, 0x2A)
        self.segments = []   # PT_LOAD: (vaddr, file bytes, memsz, flags)  flags: 1 = X, 2 = W, 4 = R
        for i in range(phnum):
            typ, off, vaddr, paddr, filesz, memsz, flags, align = struct.unpack_from("<8I", b, phoff + i * phentsize)
            if typ == 1:
                self.segments.append((vaddr, b[off:off + filesz], memsz, flags))
        strtab = self.sections[shstrndx]
        for s in self.sections:
            s["name"] = self._str(strtab, s["name"])
        self.symbols = {}
        for s in self.sections:
            if s["type"] == 2:  # SHT_SYMTAB
                st = self.sections[s["link"]]
                for o in range(s["off"], s["off"] + s["size"], 16):
                    nm, value, size, info, other, shndx = struct.unpack_from("<IIIBBH", b, o)
                    self.symbols[self._str(st, nm)] = (value, size)

    def _str(self, sec, off):
        o = sec["off"] + off
        return self.b[o:self.b.index(b"\0", o)].decode("utf-8", "replace")

    def function(self, name):
        if name not in self.symbols:
            cand = [k for k in self.symbols if k.endswith(name)]
            if len(cand) != 1:
                raise KeyError(f"symbol {name!r}: {len(cand)} candidates")
            name = cand[0]
        addr, size = self.symbols[name]
        for s in self.sections:
            if s["type"] == 1 and s["addr"] <= addr < s["addr"] + s["size"]:  # SHT_PROGBITS
                o = s["off"] + addr - s["addr"]
                return addr, self.b[o:o + size]
        raise KeyError(f"no section holds {name}")


class Stats:
    def __init__(self):
        self.instr = 0
        self.ilines = {}        # line number -> index of first touch (order of first use)
        self.dlines_r = set()
        self.dlines_w = set()
        self.load_use = 0       # instruction uses the register the previous instruction loaded (one bubble)
        self.lwl_after_lwr = 0  # LWL right after LWR into the same register (stalls on the 1004Kc)
        self.taken = 0          # taken branches/jumps
        self.notes = set()
        self.uninit_reads = 0   # go_mode only: reads of never-written memory (a Fault otherwise)
        self.pc_count = None    # go_mode: {pc: executions} for per-function attribution

    def summary(self):
        return (f"{self.instr} instr, {len(self.ilines)} I-lines, {len(self.dlines_r | self.dlines_w)} D-lines, "
                f"{self.load_use} load-use, {self.lwl_after_lwr} lwl-after-lwr, {self.taken} taken")


RETURN_PC = 0x0BAD0000   # sentinel link address
G_VALUE = 0x6A6A6A6A     # poison for R30 (g): readable in principle, never writable


class Cpu:
    def __init__(self, regions, code_base, code, go_mode=False):
        self.regions = regions
        self.code_base, self.code, self.code_end = code_base, code, code_base + len(code)
        self._last = regions[0] if regions else None
        # go_mode: compiled Go code - calls (JAL/JALR), R23/R28/R31 as ordinary registers, the g register
        # points at readable memory, reads of never-written stack bytes are counted instead of faulting.
        self.go_mode = go_mode

    # -- memory -------------------------------------------------------------------------------------------
    def _region(self, addr, n, what):
        r = self._last
        if not (r.base <= addr and addr + n <= r.end):
            for r in self.regions:
                if r.base <= addr and addr + n <= r.end:
                    self._last = r
                    break
            else:
                raise Fault(f"{what} of {n} byte(s) at {addr:#010x}: outside every region")
        return r

    def load(self, addr, n, st):
        r = self._region(addr, n, "read")
        o = addr - r.base
        if r.init[o:o + n] != b"\x01" * n:
            if not self.go_mode:
                raise Fault(f"read of uninitialised memory at {addr:#010x} ({r.name}+{o})")
            st.uninit_reads += 1
        st.dlines_r.add(addr // LINE)
        st.dlines_r.add((addr + n - 1) // LINE)
        return int.from_bytes(r.data[o:o + n], "little")

    def store(self, addr, n, value, st):
        r = self._region(addr, n, "write")
        o = addr - r.base
        if r.wr[o:o + n] != b"\x01" * n:
            raise Fault(f"write to read-only memory at {addr:#010x} ({r.name}+{o}, {n} byte(s))")
        r.data[o:o + n] = (value & ((1 << (8 * n)) - 1)).to_bytes(n, "little")
        r.init[o:o + n] = b"\x01" * n
        st.dlines_w.add(addr // LINE)
        st.dlines_w.add((addr + n - 1) // LINE)

    # -- execution ----------------------------------------------------------------------------------------
    def call(self, entry, sp, max_instr=5_000_000, allow_lr_scratch=False, g=None, hooks=None):
        """Run from entry until control returns to the link address. Returns Stats.
        hooks: {pc: fn(cpu, reg)} called before the instruction at pc executes (test instrumentation)."""
        st = Stats()
        go = self.go_mode
        if go:
            st.pc_count = {}
            allow_lr_scratch = True
        gval = G_VALUE if g is None else g
        reg = [None] * 32
        valid = [0] * 32    # bit i set: byte i of the register holds a defined value (LWR/LWL build words in halves)
        reg[0], reg[29], reg[30], reg[31] = 0, sp, gval, RETURN_PC
        valid[0] = valid[29] = valid[30] = valid[31] = 15
        hi = lo = None
        pc, npc = entry, entry + 4
        in_delay = False
        last_load = -1      # register loaded by the previous instruction
        last_lwr = -1       # register the previous instruction loaded with LWR
        code, cb, ce = self.code, self.code_base, self.code_end
        ilines = st.ilines

        def rd(i):
            if valid[i] != 15:
                raise Fault(f"read of uninitialised register R{i} (valid bytes {valid[i]:04b}) at pc {cur:#x}")
            return reg[i]

        while True:
            if pc == RETURN_PC:
                break
            if not (cb <= pc < ce) or pc & 3:
                raise Fault(f"pc {pc:#x} outside the function")
            if hooks and pc in hooks:
                hooks[pc](self, reg)
            st.instr += 1
            if st.instr > max_instr:
                raise Fault("instruction limit")
            ln = pc // LINE
            if ln not in ilines:
                ilines[ln] = len(ilines)
            if go:
                st.pc_count[pc] = st.pc_count.get(pc, 0) + 1
            (w,) = struct.unpack_from("<I", code, pc - cb)
            cur, pc, npc = pc, npc, npc + 4
            was_delay, in_delay = in_delay, False
            op, rs, rt, rdn = w >> 26, (w >> 21) & 31, (w >> 16) & 31, (w >> 11) & 31
            sh, fn, imm = (w >> 6) & 31, w & 63, w & 0xFFFF
            simm = imm - 0x10000 if imm & 0x8000 else imm
            dest, val, dvalid = -1, None, 15
            this_load, this_lwr = -1, -1
            uses = ()

            if op == 0:
                if fn == 0x00:                                   # SLL (NOP when everything is zero)
                    if w != 0:
                        uses = (rt,); dest, val = rdn, (rd(rt) << sh) & M32
                elif fn == 0x02:                                 # SRL / ROTR
                    uses = (rt,); v = rd(rt)
                    if rs == 1:
                        val = ((v >> sh) | (v << (32 - sh))) & M32 if sh else v
                    elif rs == 0:
                        val = v >> sh
                    else:
                        raise Fault(f"bad SRL encoding {w:#010x}")
                    dest = rdn
                elif fn == 0x03:                                 # SRA
                    uses = (rt,); v = rd(rt); v = v - (1 << 32) if v & 0x80000000 else v
                    dest, val = rdn, (v >> sh) & M32
                elif fn == 0x04:                                 # SLLV
                    uses = (rs, rt); dest, val = rdn, (rd(rt) << (rd(rs) & 31)) & M32
                elif fn == 0x06:                                 # SRLV / ROTRV
                    uses = (rs, rt); v, s = rd(rt), rd(rs) & 31
                    if sh == 1:
                        val = ((v >> s) | (v << (32 - s))) & M32 if s else v
                    else:
                        val = v >> s
                    dest = rdn
                elif fn == 0x08:                                 # JR
                    if was_delay:
                        raise Fault("jump in a delay slot")
                    uses = (rs,); npc = rd(rs); in_delay = True; st.taken += 1
                elif fn == 0x09 and go:                          # JALR
                    if was_delay:
                        raise Fault("jump in a delay slot")
                    uses = (rs,); npc = rd(rs); in_delay = True; st.taken += 1
                    dest, val = rdn, cur + 8
                elif fn == 0x34:                                 # TEQ (Go: division-by-zero check)
                    uses = (rs, rt)
                    if rd(rs) == rd(rt):
                        raise Fault(f"TEQ trap at {cur:#x}")
                elif fn == 0x18:                                 # MULT
                    uses = (rs, rt); a, b = rd(rs), rd(rt)
                    a = a - (1 << 32) if a & 0x80000000 else a
                    b = b - (1 << 32) if b & 0x80000000 else b
                    p = (a * b) & 0xFFFFFFFFFFFFFFFF; hi, lo = p >> 32, p & M32
                elif fn == 0x1B:                                 # DIVU
                    uses = (rs, rt); a, b = rd(rs), rd(rt)
                    if b == 0:
                        raise Fault(f"DIVU by zero at {cur:#x}")
                    lo, hi = a // b, a % b
                elif fn == 0x0A:                                 # MOVZ
                    uses = (rs, rt)
                    if rd(rt) == 0:
                        dest, val = rdn, rd(rs)
                elif fn == 0x0B:                                 # MOVN
                    uses = (rs, rt)
                    if rd(rt) != 0:
                        dest, val = rdn, rd(rs)
                elif fn == 0x0F:                                 # SYNC
                    pass
                elif fn == 0x10:                                 # MFHI
                    if hi is None:
                        raise Fault(f"MFHI of uninitialised HI at {cur:#x}")
                    dest, val = rdn, hi
                elif fn == 0x12:                                 # MFLO
                    if lo is None:
                        raise Fault(f"MFLO of uninitialised LO at {cur:#x}")
                    dest, val = rdn, lo
                elif fn == 0x11:                                 # MTHI
                    uses = (rs,); hi = rd(rs)
                elif fn == 0x13:                                 # MTLO
                    uses = (rs,); lo = rd(rs)
                elif fn == 0x19:                                 # MULTU
                    uses = (rs, rt); p = rd(rs) * rd(rt); hi, lo = p >> 32, p & M32
                elif fn in (0x20, 0x21):                         # ADD(U)
                    uses = (rs, rt); dest, val = rdn, (rd(rs) + rd(rt)) & M32
                elif fn in (0x22, 0x23):                         # SUB(U)
                    uses = (rs, rt); dest, val = rdn, (rd(rs) - rd(rt)) & M32
                elif fn == 0x24:
                    uses = (rs, rt); dest, val = rdn, rd(rs) & rd(rt)
                elif fn == 0x25:
                    uses = (rs, rt); dest, val = rdn, rd(rs) | rd(rt)
                elif fn == 0x26:
                    uses = (rs, rt); dest, val = rdn, rd(rs) ^ rd(rt)
                elif fn == 0x27:
                    uses = (rs, rt); dest, val = rdn, ~(rd(rs) | rd(rt)) & M32
                elif fn == 0x2B:                                 # SLTU
                    uses = (rs, rt); dest, val = rdn, 1 if rd(rs) < rd(rt) else 0
                elif fn == 0x2A:                                 # SLT
                    uses = (rs, rt); a, b = rd(rs), rd(rt)
                    a = a - (1 << 32) if a & 0x80000000 else a
                    b = b - (1 << 32) if b & 0x80000000 else b
                    dest, val = rdn, 1 if a < b else 0
                else:
                    raise Fault(f"unmodelled SPECIAL funct {fn:#x} ({w:#010x}) at {cur:#x}")
            elif op == 0x1C:                                     # SPECIAL2
                if fn == 0x01:                                   # MADDU
                    if hi is None or lo is None:
                        raise Fault(f"MADDU on uninitialised HI/LO at {cur:#x}")
                    uses = (rs, rt); p = ((hi << 32) | lo) + rd(rs) * rd(rt)
                    hi, lo = (p >> 32) & M32, p & M32
                elif fn == 0x02:                                 # MUL (HI/LO become unpredictable)
                    uses = (rs, rt); dest, val = rdn, (rd(rs) * rd(rt)) & M32
                    hi = lo = None
                elif fn == 0x20:                                 # CLZ
                    uses = (rs,); dest, val = rdn, 32 - rd(rs).bit_length()
                else:
                    raise Fault(f"unmodelled SPECIAL2 funct {fn:#x} at {cur:#x}")
            elif op in (0x04, 0x05):                             # BEQ / BNE
                if was_delay:
                    raise Fault("branch in a delay slot")
                uses = (rs, rt); eq = rd(rs) == rd(rt)
                in_delay = True
                if eq == (op == 0x04):
                    npc = cur + 4 + (simm << 2); st.taken += 1
            elif op in (0x06, 0x07, 0x01):                       # BLEZ / BGTZ / REGIMM BLTZ,BGEZ
                if was_delay:
                    raise Fault("branch in a delay slot")
                uses = (rs,); v = rd(rs); v = v - (1 << 32) if v & 0x80000000 else v
                if op == 0x06:
                    t = v <= 0
                elif op == 0x07:
                    t = v > 0
                elif rt in (0, 0x10):                            # BLTZ / BLTZAL
                    t = v < 0
                elif rt in (1, 0x11):                            # BGEZ / BGEZAL
                    t = v >= 0
                else:
                    raise Fault(f"unmodelled REGIMM {rt} at {cur:#x}")
                in_delay = True
                if op == 0x01 and rt & 0x10:                     # the -AL forms always link
                    dest, val = 31, cur + 8
                if t:
                    npc = cur + 4 + (simm << 2); st.taken += 1
            elif op == 0x02 or (op == 0x03 and go):              # J / JAL
                if was_delay:
                    raise Fault("jump in a delay slot")
                npc = ((cur + 4) & 0xF0000000) | ((w & 0x03FFFFFF) << 2); in_delay = True; st.taken += 1
                if op == 0x03:
                    dest, val = 31, cur + 8
            elif op == 0x1F and fn == 0x20 and go:               # SPECIAL3 BSHFL: WSBH / SEB / SEH
                uses = (rt,); v = rd(rt)
                if sh == 0x02:
                    val = ((v & 0x00FF00FF) << 8) | ((v >> 8) & 0x00FF00FF)
                elif sh == 0x10:
                    val = (v & 0xFF) | (0xFFFFFF00 if v & 0x80 else 0)
                elif sh == 0x18:
                    val = (v & 0xFFFF) | (0xFFFF0000 if v & 0x8000 else 0)
                else:
                    raise Fault(f"unmodelled BSHFL {sh:#x} at {cur:#x}")
                dest = rdn
            elif op == 0x0A:                                     # SLTI
                uses = (rs,); v = rd(rs); v = v - (1 << 32) if v & 0x80000000 else v
                dest, val = rt, 1 if v < simm else 0
            elif op in (0x08, 0x09):                             # ADDI(U)
                uses = (rs,); dest, val = rt, (rd(rs) + simm) & M32
            elif op == 0x0B:                                     # SLTIU
                uses = (rs,); dest, val = rt, 1 if rd(rs) < (simm & M32) else 0
            elif op == 0x0C:
                uses = (rs,); dest, val = rt, rd(rs) & imm
            elif op == 0x0D:
                uses = (rs,); dest, val = rt, rd(rs) | imm
            elif op == 0x0E:
                uses = (rs,); dest, val = rt, rd(rs) ^ imm
            elif op == 0x0F:                                     # LUI
                dest, val = rt, imm << 16
            elif op in (0x23, 0x24, 0x25, 0x20, 0x21):           # LW LBU LHU LB LH
                uses = (rs,); a = (rd(rs) + simm) & M32
                n = 4 if op == 0x23 else 1 if op in (0x24, 0x20) else 2
                if a % n:
                    raise Fault(f"unaligned {n}-byte load at {a:#010x}, pc {cur:#x}")
                v = self.load(a, n, st)
                if op == 0x20 and v & 0x80:
                    v |= 0xFFFFFF00
                if op == 0x21 and v & 0x8000:
                    v |= 0xFFFF0000
                dest, val, this_load = rt, v, rt
            elif op == 0x26:                                     # LWR (little endian: bytes a .. a|3 -> low end)
                uses = (rs,); a = (rd(rs) + simm) & M32; k = 4 - (a & 3)
                v = self.load(a, k, st)
                if k < 4:
                    v |= (reg[rt] or 0) & (M32 << (8 * k)) & M32
                    dvalid = (valid[rt] & (15 << k) & 15) | ((1 << k) - 1)
                dest, val, this_load, this_lwr = rt, v, rt, rt
            elif op == 0x22:                                     # LWL (bytes a&~3 .. a -> high end)
                uses = (rs,); a = (rd(rs) + simm) & M32; k = (a & 3) + 1
                v = self.load(a & ~3, k, st) << (8 * (4 - k))
                if k < 4:
                    v |= (reg[rt] or 0) & ((1 << (8 * (4 - k))) - 1)
                    dvalid = (valid[rt] & ((1 << (4 - k)) - 1)) | (15 << (4 - k) & 15)
                if last_lwr == rt:
                    st.lwl_after_lwr += 1
                dest, val, this_load = rt, v & M32, rt
            elif op in (0x2B, 0x28, 0x29):                       # SW SB SH
                uses = (rs, rt); a = (rd(rs) + simm) & M32
                n = 4 if op == 0x2B else 1 if op == 0x28 else 2
                if a % n:
                    raise Fault(f"unaligned {n}-byte store at {a:#010x}, pc {cur:#x}")
                self.store(a, n, rd(rt), st)
            elif op == 0x2E:                                     # SWR (low bytes of rt -> a .. a|3)
                uses = (rs, rt); a = (rd(rs) + simm) & M32; k = 4 - (a & 3)
                self.store(a, k, rd(rt), st)
            elif op == 0x2A:                                     # SWL (high bytes of rt -> a&~3 .. a)
                uses = (rs, rt); a = (rd(rs) + simm) & M32; k = (a & 3) + 1
                self.store(a & ~3, k, rd(rt) >> (8 * (4 - k)), st)
            else:
                raise Fault(f"unmodelled opcode {op:#x} ({w:#010x}) at {cur:#x}")

            if last_load >= 0 and last_load in uses and last_load != 0:
                st.load_use += 1
            last_load, last_lwr = this_load, this_lwr
            if dest > 0:
                if dest in (26, 27, 30):
                    raise Fault(f"write to reserved register R{dest} at {cur:#x}")
                if not go:
                    if dest == 28:
                        st.notes.add("writes R28")
                    if dest == 23:
                        st.notes.add("writes R23 (REGTMP)")
                    if dest == 31:
                        if not allow_lr_scratch:
                            raise Fault(f"write to R31 (LR) at {cur:#x}")
                        st.notes.add("writes R31")
                reg[dest] = val
                valid[dest] = dvalid

        if reg[29] != sp:
            raise Fault(f"SP at return {reg[29]:#x}, expected {sp:#x}")
        if reg[30] != gval:
            raise Fault("R30 (g) changed")
        self.hi, self.lo, self.reg = hi, lo, reg
        return st
