# mipsle-chacha

MIPS32 little-endian (softfloat) assembly for ChaCha20 and Poly1305, and a
reproducible pipeline that builds Tailscale's `tailscaled` with it for a
GL.iNet GL-MG1300 router. Hobby project.

## Goal

On `linux/mipsle` Go has no assembly for ChaCha20 or Poly1305, so WireGuard
(ChaCha20-Poly1305 in `golang.org/x/crypto`, used by `wireguard-go`) runs on the
generic Go code. That code is expected to be the main throughput limit on a
small MIPS router; `bench/` and the Results section are meant to confirm or
refute this. This project:

1. writes MIPS32 assembly for both primitives (`overlay/`);
2. builds `tailscaled` so that it matches admonstrator's "tiny" GL.iNet build as
   closely as possible (same Tailscale tag, Go version, patches, build tags and
   flags), with or without the assembly;
3. applies the assembly to **both** x/crypto copies the binary contains:
   - `golang.org/x/crypto` v0.58.0 (module dependency: `wireguard-go`, data plane);
   - `vendor/golang.org/x/crypto` inside the Go standard library (`crypto/tls`,
     used for DERP and control connections).

## Layout

| Path | Contents |
|---|---|
| `overlay/chacha20/` | `chacha_mipsle.go`, `chacha_mipsle.s`, tests, `NOTES.md` |
| `overlay/poly1305/` | `sum_mipsle.go`, `sum_mipsle.s`, tests, `NOTES.md` |
| `scripts/apply-overlay.sh` | Copies the overlay into an x/crypto tree and/or a GOROOT's vendored x/crypto |
| `scripts/build-tailscaled.sh` | The build pipeline (baseline or overlay) |
| `bench/` | Throughput benchmark (1420-byte packets); `bench/sweep` for interleaved A/B runs |
| `pgo/` | CPU profile of tailscaled on the router, used for profile-guided optimization of overlay builds |
| `results/` | Measured results |
| `.tools/go/` | Go 1.27.4 toolchain, never modified (gitignored) |
| `work/` | Caches: Tailscale checkout, admon repo, patched GOROOT, patched x/crypto, GOPATH, GOCACHE (gitignored) |
| `build/` | Build outputs (gitignored) |

## The reference: admonstrator's tiny build

The router currently runs `1.104.7-tiny.by.admon.1457` from
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
  use UPX; the outputs are unpacked.

`scripts/build-tailscaled.sh` reproduces these steps. It pins admon's repo at
`e5aa293`, its HEAD when 1.104.7 was built, and runs admon's own patch script, which
also checks the result. Run with admon's own stamp, the pipeline rebuilds the
reference byte for byte:

```sh
scripts/build-tailscaled.sh --no-overlay --suffix -tiny.by.admon.1457 --variant admon-repro
```

The output had the same sha256 as the unpacked reference, `a12877d7…b54b`.

## How to build

Requirements: Git Bash (or any bash with git, patch, sha256sum) and the Go 1.27.4
toolchain in `.tools/go` (`scripts/setup-tools.sh` downloads and verifies it). The first run clones the repos and downloads modules,
so it needs network access. Later runs reuse the caches in `work/`.

Runs share state in `work/`. Every run, including `--check`, hard-resets
`work/tailscale` and rewrites the patched trees, so never run two at once.

```sh
scripts/build-tailscaled.sh --no-overlay   # baseline -> build/tailscaled-mipsle-baseline
scripts/build-tailscaled.sh                # overlay + PGO -> build/tailscaled-mipsle-chacha
scripts/build-tailscaled.sh --check        # show what gets compiled; no build
```

Options:

| Option | Effect |
|---|---|
| `--no-overlay` | Baseline: pristine GOROOT, unmodified `go.mod`. The build info equals the reference except for the version stamp |
| `--check` | Prepare everything, then print `GoFiles`/`SFiles` of the chacha20 and poly1305 packages (both copies) as resolved in `tailscaled`'s real build graph (`go list -deps`), plus the stdlib packages that import the vendored chacha20poly1305 |
| `--overlay-dir DIR` | Use a different overlay root, e.g. a scratch dummy |
| `--suffix S` | Version suffix. Defaults: `-tiny.mipsle-chacha` (overlay), `-tiny.mipsle-base` (baseline) |
| `--variant NAME` | Output file `build/tailscaled-mipsle-NAME` |
| `--ref BIN` | Diff `go version -m` of the result against a reference binary |
| `--no-pgo` | Overlay build without profile-guided optimization. Overlay builds use `pgo/2026-11-16_A_mixed90s.pprof` by default; baseline builds never use PGO |
| `--pgo FILE` | Use a different CPU profile for PGO (e.g. one recorded with `tailscale debug --cpu-profile` on a newer version) |

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
   - restores the chacha20 and poly1305 package dirs in both copies from pristine
     sources;
   - runs `apply-overlay.sh`;
   - writes `work/modfile/go.mod`, a copy of Tailscale's `go.mod` plus
     `replace golang.org/x/crypto => work/xcrypto-patched`, used through
     `-modfile`, so upstream files are never edited;
   - builds with `work/goroot-patched/bin/go`, so the patched GOROOT is the
     standard library;
5. builds and writes `<out>`, `<out>.sha256` and `<out>.buildinfo.txt`, then
   checks that the version stamp is present in the binary.

The build environment is isolated: `GOENV=off`, `GOTOOLCHAIN=local`,
`GOPATH`/`GOCACHE` in `work/`, and `GOROOT`/`GOFLAGS`/`GOWORK` unset.

## How the overlay is applied

`scripts/apply-overlay.sh [--overlay-dir DIR] [--pristine-xcrypto DIR] [--pristine-goroot DIR] [--with-tests] <xcrypto-dir|-> <goroot-dir|->`

For each package (`overlay/chacha20` goes to `chacha20/`, `overlay/poly1305` goes to
`internal/poly1305/`), in the x/crypto tree and in
`<GOROOT>/src/vendor/golang.org/x/crypto`:

- the non-test `*.go` and `*.s` files are copied into the package dir. Test files
  are copied only with `--with-tests`, and only into the x/crypto tree;
- the `//go:build <expr>` line of `chacha_noasm.go` or `mac_noasm.go` is rewritten
  to `//go:build (<expr>) && (!mipsle || !gc || purego)`. The script wraps whatever
  expression the file has. The stdlib's vendored x/crypto is an older snapshot
  (`v0.52.1-0.20260526024921-9beb694f9766`) with different expressions than v0.58.0.
  The generic code the overlay relies on (`chacha_generic.go`, `sum_generic.go`,
  `poly1305.go`) is identical in both;
- a package with no overlay files is left alone: generic code, no rewrite;
- it is idempotent. With `--pristine-*`, the package dirs are first restored from
  pristine copies, so files from an older overlay disappear.

## Safety and testing approach

- Nothing here touches the router. The build scripts only write to `work/` and
  `build/`. Installing a binary on the router is a separate, manual step.
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
- Planned before an overlay binary is used:
  - test the assembly against the generic implementation, with known-answer
    vectors and randomized comparisons (`overlay/*/…_test.go`);
  - run `--check`;
  - build end to end.
- For an overlay build, the expected `go version -m` difference from the
  reference is exactly one line. The `golang.org/x/crypto v0.58.0 h1:…` dep line
  becomes `=> <abs path>/work/xcrypto-patched (devel)`. That path is embedded in
  the binary, so overlay builds are byte-reproducible only from the same checkout
  path.
- `purego` builds and non-mipsle targets are unaffected: the guard only
  removes the generic fallback for `mipsle && gc && !purego`.

## Results

Measured on a GL-MG1300 on 2026-11-16 (details: `results/2026-11-16_gl-mg1300.md`).

| | pure Go / admon tiny | mipsle asm / mipsle-chacha | gain |
|---|---|---|---|
| ChaCha20-Poly1305 seal, 1 thread, 1420 B | 49.4 Mbit/s | 265 Mbit/s (OpenSSL: 213) | 5.4x |
| tailscaled via exit node, direct UDP, download | 18.1 Mbit/s | 21.5 Mbit/s | +19 % |
| tailscaled via exit node, direct UDP, upload | 14.7 Mbit/s | 17.9 Mbit/s | +22 % |
| tailscaled via DERP relay (TLS), download | 7.2 Mbit/s | 11.2 Mbit/s | +56 % |

## ChaCha20/Poly1305 assembly

- ChaCha20 (`overlay/chacha20/`): all 16 state words in registers, native MIPS32r2 `ROTR`, fully
  unrolled rounds, counter-independent first-round quarter rounds precomputed per call, aligned and
  LWL/LWR paths, bufSize 64. Design and register map: `overlay/chacha20/NOTES.md`.
- Poly1305 (`overlay/poly1305/`): radix 2^32 in place on the generic `macState`, MULTU/MADDU
  (MADDU hand-encoded), column carries added in the accumulator, lazy carry fold; bound proof in
  `overlay/poly1305/NOTES.md`.
- Verification: upstream test vectors, differential tests against the generic Go code (and a
  math/big model for Poly1305), 300k-iteration soak, single-instruction mutants (19 on the first
  version, 41 on the current block) all caught; all run on the device.
- The overlay in this repository is newer than the build measured above: a later tuning pass made
  Poly1305 about 13 % and ChaCha20-Poly1305 about 2–4 % faster in micro-benchmarks. End to end on the
  router the difference is within the run-to-run spread: crypto is now only about 8 % of tailscaled's
  CPU time, most of the rest is kernel work (TUN writes) and Tailscale's packet handling. Overlay builds
  now also use profile-guided optimization from a CPU profile recorded on the router: slightly better in
  every comparison, but also within the spread. Details: `results/2026-11-17_sweep-e2e-pgo.md`.

## License

BSD 3-Clause, see `LICENSE`. The overlay files are meant to be dropped into `golang.org/x/crypto`
(BSD 3-Clause, The Go Authors).
