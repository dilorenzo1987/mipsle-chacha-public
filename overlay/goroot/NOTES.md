# Go runtime patch: lock striping and fewer barriers for 64-bit atomics on 32-bit MIPS

`atomic_mipsx-lock-striping.patch` changes two files of the Go toolchain copy that overlay builds use
(`src/internal/runtime/atomic/atomic_mipsx.go` and `atomic_mipsx.s`, Go 1.27.4). `scripts/build-tailscaled.sh` applies it by
default; `--no-goroot-patch` builds with the unmodified runtime. The pristine toolchain in `.tools/go` is never
changed, and every build first restores the files from it.

## Why

32-bit MIPS has no 64-bit LL/SC, so Go implements every 64-bit atomic (`Xadd64`, `Load64`, `Store64`, `Cas64`,
`Xchg64`; `sync/atomic`'s 64-bit functions jump to them) with a spinlock. Upstream uses **one** lock for the
whole process (the source has a "TODO implement lock striping"; the arm port already stripes with 57 locks).
On the MT7621 one such operation costs ~265 ns, and operations on *unrelated* variables from different threads
serialize on that one lock. tailscaled does dozens of them per packet: `sync.Pool`, `internal/poll.fdMutex`
on every socket/TUN read and write, `sync.WaitGroup`, Tailscale's per-packet statistics counters,
wireguard-go's nonce and byte counters.

## What

64 locks instead of one, selected by `(addr >> 3) & 63`, each padded to its own cache line. The same address
always maps to the same lock, so the atomicity guarantees are unchanged. A first version with 57 locks (`% 57`, as on arm) was 25 % slower uncontended,
because integer division is slow on this CPU; the power of two avoids it.

Barriers: upstream's `spinLock`/`spinUnlock` execute four `SYNC`s per operation (before the LL, after the SC,
before and after the releasing store). The patch keeps the two that matter — after acquiring (acquire) and
before the releasing store (release) — so every 64-bit access is still fenced by a full `SYNC` on both sides,
exactly like Go's 32-bit atomics (`SYNC`, LL/SC, `SYNC`) and Linux's MIPS spinlocks. The `SYNC` before the LL
only ordered earlier accesses before the lock word (the one after the SC already orders them before the data),
and the one after the releasing store only hurried the store out. `SYNC` costs ~40 ns on this CPU.
Caveat: a store-buffering litmus test never showed reordering on the MT7621, not even for plain accesses, so
the device cannot confirm the barrier argument; it rests on the reasoning above.

## Verification and results (GL-MG1300)

- Go's `internal/runtime/atomic`, `sync/atomic` and `sync` tests pass on the device with the patch.
- Micro-benchmark, 64-bit atomic add: 1 thread 265 → 278 ns (+5 %); 2–8 threads on unrelated variables
  255–345 → ~145 ns per operation (about twice the throughput; not more, because the two hardware threads of a
  core share one pipeline). With the barrier change: 1 thread ~200 ns, 2–8 threads ~100–110 ns.
- tailscaled over a DERP relay, interleaved with the same build without the patch (both with GOMAXPROCS=3):
  −3.7 % CPU per MB; together with GOMAXPROCS=3 +8.8 % throughput and −7.4 % CPU per MB (striping only, before
  the barrier change).
