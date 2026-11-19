# mipsle-chacha

Faster Tailscale on the GL.iNet Mango 2 travel router (GL-MG1300): MIPS assembly for the ChaCha20-Poly1305
encryption that Tailscale uses, and a reproducible build of the community "tiny" `tailscaled` with it.
Hobby project.

## Summary

Tailscale encrypts all traffic with ChaCha20-Poly1305. For the router's MIPS processor, Go only has slow generic
code for it, and that limited Tailscale's throughput. This repository replaces that code with assembly written
for this processor and rebuilds the community "tiny" Tailscale build for the router with it. Two further steps
then made the rest of the work per packet cheaper.

Tailscale throughput on one Mango 2:

| Tailscale build on the router | Through a relay server (DERP) | Direct connection, download | Direct connection, upload |
|---|---|---|---|
| GL.iNet's stock binary (Tailscale 1.92.5, firmware 4.10.1) | about 3-4 Mbit/s (1) | not measured | not measured |
| Community "tiny" build by admonstrator (Tailscale 1.104.7), unpacked (2) | 7.2 Mbit/s | 18.1 Mbit/s | 14.7 Mbit/s |
| This project (same Tailscale version and feature set) | 14.0 Mbit/s (3) | 21.5 Mbit/s (4) | 17.9 Mbit/s (4) |

Through a relay this is about twice the throughput of the community build it is based on. Encryption alone, on
one processor core: 49 Mbit/s with Go's generic code, 286 Mbit/s with the assembly (5).

How it got there:

1. **Encryption in assembly** (2026-11-16): ChaCha20 and Poly1305 written for the router's processor.
   Relay +56 %, direct +19 % / +22 %.
2. **Less waiting between threads** (2026-11-17): tailscaled runs with three threads instead of four, the Go
   runtime's single lock for 64-bit counters is split into 64 locks, and two small patches remove per-packet
   work in Tailscale and wireguard-go. Relay +9 %, then +4 %.
3. **Less code per packet** (2026-11-19): profiles showed that tailscaled spent at least a fifth of its processor
   time waiting for program code to be loaded from memory, because the processor's cache is much smaller than
   the code a packet passes through. The encryption path was rewritten to be compact (about 85 cache lines per
   operation instead of 340-400). Relay +15 %, with 14.5 % less processor time per megabyte.

Status: this runs on the author's router, steps 1 and 2 since 2026-11-16/17, step 3 since 2026-11-19. The
combined seal/open routine of step 3 is new, security-critical assembly. It passed the tests described below and
a separate automated review, but there has been no human or third-party audit of any of the assembly.
`--no-aead` builds without that routine. No warranty.

Notes on the table:

- (1) The author's observation with the Tailscale binary that firmware 4.10.1 ships. It is not part of the
  measurement sessions in `results/` and was not taken under the same conditions as the other rows.
- (2) As released, the community build is compressed with UPX. On this router (128 MB RAM) that currently fails
  by default: during boot the kernel's out-of-memory killer ends tailscaled (the author's observation, November
  2026). A UPX-packed binary holds its whole unpacked image in memory, while an unpacked binary is paged in from
  flash on demand. Since 2026-11-18 the community updater has a `--no-upx` option that installs an uncompressed
  tiny build from releases that provide one. The author ran the build unpacked (`upx -d`); the values in this
  row are from that unpacked binary, and the builds from this repository are not compressed.
- (3) The 7.2 and the 14.0 were measured three days apart with different download servers, so the factor is
  approximate. The steps in between were each measured back to back within one session (+56 %, +9 %, +4 %,
  +15 %) and multiply to the same factor. The last step comes from a single session; its size is uncertain by
  about 5 percentage points.
- (4) Measured with the first version in an A/B against the community build. A short check of the current build
  gave about 23 Mbit/s down and 20-21 up (2026-11-19, two runs each, not an A/B).
- (5) Warm micro-benchmark with 1420-byte packets, both measured back to back on 2026-11-19.

In technical terms: MIPS32 little-endian (softfloat) assembly for ChaCha20, Poly1305 and the combined AEAD, and a
reproducible pipeline that builds Tailscale's `tailscaled` with it for a GL.iNet GL-MG1300 router.

## Goal

On `linux/mipsle` Go has no assembly for ChaCha20 or Poly1305, so WireGuard
(ChaCha20-Poly1305 in `golang.org/x/crypto`, used by `wireguard-go`) runs on the
generic Go code. On a small MIPS router that was the main throughput limit
(see Results; with the assembly, crypto is about a tenth of tailscaled's CPU
time). This project:

1. writes MIPS32 assembly for both primitives and for the combined seal/open (`overlay/`);
2. builds `tailscaled` so that it matches admonstrator's "tiny" GL.iNet build as
   closely as possible (same Tailscale tag, Go version, patches, build tags and
   flags), with or without the assembly;
3. applies the assembly to **both** x/crypto copies the binary contains:
   - `golang.org/x/crypto` v0.58.0 (module dependency: `wireguard-go`, data plane);
   - `vendor/golang.org/x/crypto` inside the Go standard library (`crypto/tls`,
     used for DERP and control connections);
4. reduces the per-packet work outside the crypto where a measurement shows that it pays (Go thread count, a Go
   runtime patch, two source patches).

## Layout

| Path | Contents |
|---|---|
| `overlay/chacha20/` | `chacha_mipsle.go`, `chacha_mipsle.s`, tests, `NOTES.md` |
| `overlay/poly1305/` | `sum_mipsle.go`, `sum_mipsle.s`, tests, `NOTES.md` |
| `overlay/chacha20poly1305/` | Seal/open in one assembly routine: `chacha20poly1305_mipsle.go`, `.s`, tests, `NOTES.md` |
| `overlay/tailscaled/` | Extra `cmd/tailscaled` file: GOMAXPROCS=3 on 4-thread mipsle, `NOTES.md` |
| `overlay/goroot/` | Go runtime patch: lock striping and fewer barriers for 64-bit atomics on 32-bit MIPS, `NOTES.md` |
| `overlay/patches/` | Source patches for Tailscale and wireguard-go (see "Beyond crypto") |
| `scripts/apply-overlay.sh` | Copies the overlay into an x/crypto tree and/or a GOROOT's vendored x/crypto |
| `scripts/build-tailscaled.sh` | The build pipeline (baseline or overlay) |
| `scripts/setup-tools.sh` | Downloads and verifies the Go toolchain |
| `scripts/mango-swap.sh` | Runs on the router: installs a new binary and rolls back if it does not come up |
| `scripts/bench-ab.sh`, `scripts/ab-compare.py` | Interleaved A/B of two overlay revisions on the device (warm or cold benchmark) |
| `scripts/mutate-poly1305.sh`, `scripts/mutants-poly1305.py` | Single-instruction mutation check of the Poly1305 assembly on the device |
| `scripts/icache-stall.py` | Estimates from a CPU profile where tailscaled waits for instruction-cache misses |
| `bench/` | `main.go`: throughput with 1420-byte packets; `sweep/`: ns per case for A/B runs; `cold/`: cost of one operation with the caches evicted first |
| `sim/` | Strict MIPS32r2 interpreter and the checks that run the assembly and built binaries in it (correctness, mutation check, instructions and cache lines per operation) |
| `pgo/` | CPU profiles of tailscaled on the router, used for profile-guided optimization of overlay builds |
| `results/` | Measured results |
| `.tools/go/` | Go 1.27.4 toolchain, never modified (gitignored) |
| `work/` | Caches: Tailscale checkout, admon repo, patched GOROOT, patched x/crypto and wireguard-go, GOPATH, GOCACHE (gitignored) |
| `build/` | Build outputs (gitignored) |

## The reference: admonstrator's tiny build

The reference is `1.104.7-tiny.by.admon.1457` (the build the router ran before this project, unpacked) from
[admonstrator/glinet-tailscale-updater](https://github.com/admonstrator/glinet-tailscale-updater).
Its workflow (`.github/workflows/build-tailscale.yaml`):

- checks out upstream `tailscale/tailscale` at the release tag. For v1.104.7 that is
  commit `cbc74fe48ef1b1649f69a4d9a602319427e25102`, the upstream tag commit and
  the `vcs.revision` in the reference binary;
- applies its GL.iNet patches with `scripts/apply-tailscale-patches.sh`. Today that
  is a single patch, `patches/0002-nft-connmark-restore-gl-coexist.patch`, which makes
  the nftables PREROUTING connmark restore copy the full ct mark so GL.iNet's policy
  routing bits survive. This patch is why the module version is `v1.104.7+dirty`;
- computes the build tags with `go run ./cmd/featuretags --min --add=<KEEP list>`
  (47 tags: `ts_include_cli` plus `ts_omit_*`);
- stamps the version with `go run ./cmd/mkversion` plus the suffix
  `-tiny.by.admon.<run number>`, using
  `-ldflags "-w -s -X tailscale.com/version.longStamp=… -X tailscale.com/version.shortStamp=…"`;
- builds with `CGO_ENABLED=0 GOOS=linux GOARCH=mipsle GOMIPS=softfloat go build -trimpath`;
- compresses the binary with `upx --lzma --best` for release. This pipeline does not
  use UPX; the outputs are unpacked. (On the Mango 2 the compressed release currently fails by default: during
  boot the kernel's out-of-memory killer ends tailscaled, see note 2 in the Summary. All measurements of the
  tiny build in this repository used the unpacked binary.)

`scripts/build-tailscaled.sh` reproduces these steps. It pins admon's repo at
`e5aa293`, its HEAD when 1.104.7 was built, and runs admon's own patch script, which
also checks the result. Run with admon's own stamp, the pipeline rebuilds the
reference byte for byte:

```sh
bash scripts/build-tailscaled.sh --no-overlay --suffix -tiny.by.admon.1457 --variant admon-repro
```

The output had the same sha256 as the unpacked reference, `a12877d7…b54b`.

## How to build

Requirements: bash with git, patch and sha256sum (Linux, or Git Bash on Windows) and the Go 1.27.4
toolchain in `.tools/go` (`bash scripts/setup-tools.sh` downloads and verifies it; it needs curl, and unzip on
Windows). The scripts are not marked executable in git, so run them with `bash`. The first run clones the repos
and downloads modules, so it needs network access. Later runs reuse the caches in `work/`.

Runs share state in `work/`. Every run, including `--check`, hard-resets
`work/tailscale` and rewrites the patched trees, so never run two at once.

```sh
bash scripts/build-tailscaled.sh --no-overlay   # baseline -> build/tailscaled-mipsle-baseline
bash scripts/build-tailscaled.sh                # overlay (+ PGO, runtime patch, source patches) -> build/tailscaled-mipsle-chacha
bash scripts/build-tailscaled.sh --no-aead      # overlay build without the assembly seal/open routine
bash scripts/build-tailscaled.sh --check        # show what gets compiled; no build
```

Options:

| Option | Effect |
|---|---|
| `--no-overlay` | Baseline: pristine GOROOT, unmodified `go.mod`. The build info equals the reference except for the version stamp |
| `--check` | Prepare everything, then print `GoFiles`/`SFiles` of the chacha20, poly1305 and chacha20poly1305 packages (both copies) as resolved in `tailscaled`'s real build graph (`go list -deps`), plus the stdlib packages that import the vendored chacha20poly1305 |
| `--overlay-dir DIR` | Use a different overlay root, e.g. a scratch dummy |
| `--suffix S` | Version suffix. Defaults: `-tiny.mipsle-chacha` (overlay), `-tiny.mipsle-base` (baseline) |
| `--variant NAME` | Output file `build/tailscaled-mipsle-NAME` |
| `--ref BIN` | Diff `go version -m` of the result against a reference binary |
| `--no-pgo` | Overlay build without profile-guided optimization. Overlay builds use `pgo/2026-11-17_merged-mixed-derp.pprof` by default (two profiles from the router merged); baseline builds never use PGO |
| `--pgo FILE` | Use a different CPU profile for PGO (e.g. one recorded with `tailscale debug --cpu-profile` on a newer version) |
| `--no-tailscaled-overlay` | Overlay build without `overlay/tailscaled/` (GOMAXPROCS=3 on 4-thread mipsle) |
| `--no-goroot-patch` | Overlay build with the unmodified Go runtime (without `overlay/goroot/`'s lock striping) |
| `--goroot-patch FILE` | Use a different patch for the Go toolchain copy |
| `--no-source-patches` | Overlay build without `overlay/patches/` (the patches for Tailscale and wireguard-go) |
| `--no-aead` | Overlay build without `overlay/chacha20poly1305/`: the ChaCha20 and Poly1305 assembly stay and are joined by x/crypto's generic Go code |

Each run:

1. resets `work/tailscale` to the pinned tag commit (`git reset --hard` +
   `git clean -fdx`; `core.autocrlf=false`, because CRLF would break `patch` and
   change embedded files) and applies admon's patches;
2. checks that `featuretags --min --add=<KEEP>` reproduces the reference tag list,
   and fails if it does not;
3. computes the version stamp with `mkversion` plus the suffix;
4. overlay builds only:
   - creates `work/goroot-patched`, a one-time copy of `.tools/go`;
   - creates `work/xcrypto-patched`, a copy of x/crypto v0.58.0 from the
     checksum-verified module cache;
   - restores the chacha20, poly1305 and chacha20poly1305 package dirs in both copies
     from pristine sources;
   - runs `apply-overlay.sh`;
   - copies `overlay/tailscaled/*.go` into `cmd/tailscaled/` (skipped with `--no-tailscaled-overlay`);
   - restores the files a previous GOROOT patch touched from the pristine toolchain, then applies
     `overlay/goroot/atomic_mipsx-lock-striping.patch` to `work/goroot-patched` (skipped with
     `--no-goroot-patch`);
   - applies `overlay/patches/tailscale/*.patch` to the reset checkout and
     `overlay/patches/wireguard-go/*.patch` to `work/wireguard-go-patched`, a fresh copy of the wireguard-go
     module from the checksum-verified module cache (skipped with `--no-source-patches`);
   - writes `work/modfile/go.mod`, a copy of Tailscale's `go.mod` plus
     `replace golang.org/x/crypto => work/xcrypto-patched` and, with source patches,
     `replace github.com/tailscale/wireguard-go => work/wireguard-go-patched`. It is used through
     `-modfile`, so Tailscale's own `go.mod` is not edited;
   - builds with `work/goroot-patched/bin/go`, so the patched GOROOT is the
     standard library;
5. builds and writes `<out>`, `<out>.sha256` and `<out>.buildinfo.txt`, then
   checks that the version stamp is present in the binary.

The build environment is isolated: `GOENV=off`, `GOTOOLCHAIN=local`,
`GOPATH`/`GOCACHE` in `work/`, and `GOROOT`/`GOFLAGS`/`GOWORK` unset.

## How the overlay is applied

`bash scripts/apply-overlay.sh [--overlay-dir DIR] [--pristine-xcrypto DIR] [--pristine-goroot DIR] [--with-tests] [--skip NAME] <xcrypto-dir|-> <goroot-dir|->`

For each package (`overlay/chacha20` goes to `chacha20/`, `overlay/poly1305` goes to
`internal/poly1305/`, `overlay/chacha20poly1305` goes to `chacha20poly1305/`), in the x/crypto tree and in
`<GOROOT>/src/vendor/golang.org/x/crypto`:

- the non-test `*.go` and `*.s` files are copied into the package dir. Test files
  are copied only with `--with-tests`, and only into the x/crypto tree;
- the `//go:build <expr>` line of `chacha_noasm.go`, `mac_noasm.go` or `chacha20poly1305_noasm.go` is rewritten
  to `//go:build (<expr>) && (!mipsle || !gc || purego)`. The script wraps whatever
  expression the file has. The stdlib's vendored x/crypto is an older snapshot
  (`v0.52.1-0.20260526024921-9beb694f9766`) with different expressions than v0.58.0.
  The generic code the overlay relies on (`chacha_generic.go`, `sum_generic.go`,
  `poly1305.go`, the non-test files of `chacha20poly1305/` and `internal/alias`) is identical in both;
- a package with no overlay files, or one named with `--skip`, is left alone: generic code, no rewrite;
- it is idempotent. With `--pristine-*`, the package dirs are first restored from
  pristine copies, so files from an older overlay disappear.

## Safety and testing approach

- The build scripts never touch the router; they only write to `work/` and `build/`. Installing a
  binary is a separate step (`scripts/mango-swap.sh`, run on the router). The device benchmark and
  mutation scripts (`scripts/bench-ab.sh`, `scripts/mutate-poly1305.sh`) copy test binaries to the
  router's `/tmp` over ssh (`ROUTER_SSH` from a local, unpublished `device.env`) and delete them again.
- The baseline build is checked against the reference binary with `go version -m`:
  same Go version, tags, GOMIPS, VCS revision and dependency versions. With
  admon's stamp it is byte-identical.
- The overlay plumbing was proven with a throwaway dummy overlay (not in this
  repo):
  - `--check` listed the mipsle `.go`/`.s` files for both copies of chacha20 and
    poly1305;
  - the full build succeeded;
  - the dummy assembly symbol appeared in the linked binary under both
    `golang.org/x/crypto/chacha20` and `vendor/golang.org/x/crypto/chacha20`.
- Done before an overlay binary was first used (and after every assembly change):
  - test the assembly against the generic implementation, with known-answer
    vectors and randomized comparisons (`overlay/*/…_test.go`), on the device;
  - run `--check`;
  - build end to end.
- The assembly is also run off the device, in a strict interpreter (`sim/`). It faults on any read or write
  outside the declared buffers, on unaligned word accesses and on uninitialised reads, and every result is
  compared with a reference written from RFC 8439. For the seal/open routine this includes crafted inputs for
  the rare cases of the final Poly1305 reduction and a mutation check (each instruction deleted in turn: 646 of
  650 mutants caught, the other four cannot change a result). `sim/aead_ops.py --verify N` runs random
  operations through the Seal/Open functions of a complete tailscaled binary, in both x/crypto copies.
- The seal/open routine (`overlay/chacha20poly1305/`, 2026-11-19) is new. Besides the tests it went through a
  separate automated review pass by a second AI agent. There has been no human or third-party audit of any of
  the assembly. `--no-aead` builds without that routine.
- For an overlay build, the expected `go version -m` differences from the
  reference: the `golang.org/x/crypto v0.58.0 h1:…` dep line loses its hash and
  gets a `=> <abs path>/work/xcrypto-patched (devel)` replacement line, and with
  source patches the `github.com/tailscale/wireguard-go` line likewise gets
  `=> <abs path>/work/wireguard-go-patched (devel)`; with PGO
  (default) a `build -pgo=<profile>` line is added and some `build` settings
  are listed in a different order. The GOROOT patch, the Tailscale source patch and `overlay/tailscaled/`
  leave no trace in the build info (only in the binary). The paths are embedded in
  the binary, so overlay builds are byte-reproducible only from the same checkout
  path.
- `purego` builds and non-mipsle targets are unaffected: the guard only
  removes the generic fallback for `mipsle && gc && !purego`.

## Results

Measured on one GL-MG1300; details and methods are in `results/`. "Relay" is a download from a peer that is
reachable only through a custom DERP relay, where each packet is encrypted twice (WireGuard, and TLS to the relay).

| Step | Relay download | CPU time per MB | Measured as |
|---|---|---|---|
| GL.iNet's stock binary (Tailscale 1.92.5, firmware 4.10.1) | about 3-4 Mbit/s | | the author's observation, not measured in these sessions |
| Community tiny build (admonstrator), unpacked | 7.2 Mbit/s | | |
| ChaCha20 and Poly1305 in assembly (2026-11-16) | 11.2 Mbit/s, +56 % | | A/B, 2 runs each |
| Tuning pass of the assembly, PGO (2026-11-16/17) | within the run-to-run spread | about 0-1 % | interleaved segments |
| 3 Go threads, lock striping (2026-11-17) | +8.8 % | -7.4 % | blocks of plain restarts, replicated |
| Fewer barriers, Poly1305 `Sum` without a state copy, two source patches, merged PGO profile (2026-11-17) | +3.7 % | -3.1 % | blocks of plain restarts; the preset rule was only half met |
| Compact ChaCha20 (2026-11-19) | +7.6 % | -8.3 % | three builds in nine blocks, one profile per block |
| Seal/open in one assembly routine on top (2026-11-19) | +15 % for both steps: 12.1 -> 14.0 Mbit/s | -14.5 % for both steps | same session |

Absolute values differ between sessions (the download server changed on 2026-11-19, and the cost per MB varies from
one process start to the next), so each step is given relative to the build before it, measured in the same session.

Direct connection (exit node over direct UDP), A/B of the first version against the community build: download
18.1 -> 21.5 Mbit/s (+19 %), upload 14.7 -> 17.9 Mbit/s (+22 %). The later steps were not A/B-tested on the direct
path; a short check of the current build gave about 23 Mbit/s down and 20-21 up.

Encryption alone (`bench/main.go`, 1 thread, 1420-byte packets, 2026-11-19): ChaCha20-Poly1305 seal 49.5 Mbit/s in
pure Go, 286 Mbit/s with the assembly (OpenSSL 1.1.1t's assembly on the same router: 213 Mbit/s). With the caches
evicted before each operation, as between two packets in real traffic, opening one 1280-byte WireGuard packet
took 94 us with the code of 2026-11-17 and takes 55 us now (`bench/cold`).

Result files: `results/2026-11-16_gl-mg1300.md` (first version), `results/2026-11-17_sweep-e2e-pgo.md` (tuning
pass, PGO, where the run-to-run spread comes from), `results/2026-11-19_cache-lines.md` (cache lines, compact
ChaCha20, seal/open routine, and the two steps of 2026-11-17).

## The assembly

- Cost model (`results/2026-11-19_cache-lines.md`): on the MT7621 a packet's crypto code is not in the instruction
  cache when the operation starts, and fetching one 32-byte line of code takes about 155 ns, as long as executing
  about 135 instructions. The code is therefore written to touch few cache lines, even where that costs
  instructions. Warm micro-benchmarks cannot see this and favour the opposite (unrolling).
- ChaCha20 (`overlay/chacha20/`): all 16 state words in registers, native MIPS32r2 `ROTR`, the ten double rounds
  as a loop, no per-call precompute, aligned and LWL/LWR paths, bufSize 64. 1368 bytes of code; a call touches
  29-34 cache lines. (Until 2026-11-19 the rounds were fully unrolled: 4920 bytes, 140-145 lines per call, 6 %
  fewer instructions per block.) Design and register map: `overlay/chacha20/NOTES.md`.
- Poly1305 (`overlay/poly1305/`): radix 2^32 in place on the generic `macState`, MULTU/MADDU
  (MADDU hand-encoded), column carries added in the accumulator, lazy carry fold; bound proof in
  `overlay/poly1305/NOTES.md`.
- Seal/open (`overlay/chacha20poly1305/`, new on 2026-11-19): one routine does the whole AEAD operation - key
  block, cipher, MAC, constant-time tag comparison before any plaintext is written - with the ChaCha20 loop and
  the Poly1305 block of the two files above inside it. An operation touches 82-92 cache lines instead of 227-284
  (compact ChaCha20 with x/crypto's Go code around it) or 338-395 (before). `overlay/chacha20poly1305/NOTES.md`
  has the design, the new arithmetic (final reduction and tag) and the verification.
- CPU requirement: the ChaCha20 assembly and the seal/open routine use `ROTR` and need a MIPS32r2 CPU. Go's
  mipsle baseline is MIPS32r1, and nothing in the build guards against running them on an r1 core (SIGILL). The
  Poly1305 assembly uses only MIPS32r1 instructions.
- Verification: upstream test vectors, differential tests against the generic Go code (and a math/big model for
  Poly1305), a 300k-iteration soak, single-instruction mutants of the Poly1305 block (41, all caught), all run
  on the device; for ChaCha20 and the seal/open routine also the interpreter checks in `sim/` (see "Safety and
  testing approach").

## Beyond crypto

- `overlay/tailscaled/`: tailscaled runs with 3 Go threads instead of 4 on the MT7621 (two cores with two
  hardware threads each).
- `overlay/goroot/`: the Go runtime used for the build splits its single global lock for 64-bit atomics on 32-bit
  MIPS into 64 locks and executes two memory barriers per operation instead of four.
- `overlay/patches/tailscale/`: the DERP client re-arms its read deadline every eighth of the timeout instead of
  for every frame. `overlay/patches/wireguard-go/`: the batch loops of the receive, send and GRO paths walk a
  slice of the entries in the batch instead of iterating maps, whose iteration cost depends on their capacity.
- Profile-guided optimization with CPU profiles recorded on the router (`pgo/`); its effect is about 0-1 %.
- Measured effects: see Results. What limits the relay path now is per-packet work in the kernel (TUN and socket
  system calls, about a quarter of tailscaled's CPU time), the Go runtime and Tailscale's packet handling;
  crypto is about a tenth.

## License

BSD 3-Clause, see `LICENSE`. The overlay files are meant to be dropped into `golang.org/x/crypto`
(BSD 3-Clause, The Go Authors).
