# tailscaled overlay

Files here are copied into `cmd/tailscaled/` of the Tailscale source tree for overlay builds
(`scripts/build-tailscaled.sh`, skipped with `--no-tailscaled-overlay`). Upstream files are not modified.

- `gomaxprocs_mipsle.go`: on linux/mipsle with 4 logical CPUs (MT7621: 2 cores x 2 VPEs), use 3 Go threads
  unless `GOMAXPROCS` is set in the environment.

  Measured on a GL-MG1300 (installed overlay build, 3 interleaved segments each; each segment = a tailscaled
  restart, then 3 x 30 MB downloads over a DERP relay):

  | GOMAXPROCS | Mbit/s | CPU-s per MB |
  |---|---|---|
  | 4 (Go default) | 10.94 | 1.633 |
  | 3 | 11.46 (+4.8 %) | 1.560 |
  | 2 | 10.35 | 1.463 |

  With 2 the cost per MB is lowest, but the remaining parallelism is too small. With 3, one hardware thread
  stays free for the kernel's packet work (Wi-Fi interrupts, TUN writes), and fewer threads contend for Go's
  locks behind 64-bit atomics on 32-bit MIPS (one process-wide lock in stock Go; 64 with the lock
  striping in `overlay/goroot/`, which overlay builds also apply).
