# Building and contributing

## Prerequisites

- The [Rust toolchain](https://rustup.rs/). The pinned nightly and components are
  declared in `rust-toolchain.toml`.
- [`bpf-linker`](https://github.com/aya-rs/bpf-linker): install the matching
  prebuilt binary from its GitHub releases into a directory on `PATH`. CI uses
  v0.13.0. Building it with `cargo install` additionally requires the LLVM
  version expected by that release; it is not a self-contained Rust-only install.

## Build

```bash
cargo xtask build
```

Binaries are in `target/release/`. Run them on Linux using the
[quick start](../README.md#quick-start) and
[kernel/privilege requirements](../README.md#requirements).

## Development tasks (`cargo xtask`)

Use `cargo xtask` for development tasks:

| Command                     | What it does                                            |
| --------------------------- | ------------------------------------------------------- |
| `cargo xtask build`         | Build the release binaries (compiles the eBPF object).  |
| `cargo xtask fmt [--check]` | Format the workspace; `--check` verifies only.          |
| `cargo xtask lint`          | Clippy across the host workspace with `-D warnings`.    |
| `cargo xtask test`          | Run the host unit-test suite.                           |
| `cargo xtask check`         | The local-CI gate: fmt-check + lint + test.             |
| `cargo xtask clean`         | Remove build artifacts and the VM test cache.           |
| `cargo xtask vm-test`       | Full privileged end-to-end suite in a QEMU VM.          |
| `cargo xtask docker-build`  | Build the `FROM scratch` daemon image.                  |
| `cargo xtask docker-test`   | Run the containerized daemon end-to-end.                |
| `cargo xtask dist`          | Cross-compile release tarballs for the target matrix.   |
| `cargo xtask npm-dist`      | Build musl release tarballs and pack scoped npm packages. |

Run `cargo xtask check` before submitting changes. See [Testing](testing.md)
for privileged VM coverage and [Architecture](architecture.md) before changing
authentication, routing or completion.

## Man pages

Man pages for both binaries live in [`packaging/man/`](../packaging/man)
(`fstrace.1`, `fstrace-daemon.1`). Read them without installing:

```bash
man ./packaging/man/fstrace.1
```

Or install them system-wide:

```bash
sudo install -m 0644 packaging/man/fstrace.1 packaging/man/fstrace-daemon.1 \
  /usr/local/share/man/man1/
sudo mandb
```

The npm package ships the same man pages, so `npm i -g @fstrace/fstrace` registers
`man fstrace` and `man fstrace-daemon` automatically.

## Cross-compilation & release artifacts

`fstrace` supports four release targets — (arm64, x64) × (glibc, musl):

| Target                          | Arch    | libc  | Linking      |
| ------------------------------- | ------- | ----- | ------------ |
| `x86_64-unknown-linux-gnu`      | x86-64  | glibc | dynamic      |
| `x86_64-unknown-linux-musl`     | x86-64  | musl  | fully static |
| `aarch64-unknown-linux-gnu`     | aarch64 | glibc | dynamic      |
| `aarch64-unknown-linux-musl`    | aarch64 | musl  | fully static |

Build every target and stage a `.tar.gz` per target (binaries + man pages +
README) under `dist/`. README links point to the matching `vVERSION` tag:

```bash
cargo xtask dist
# Or one target at a time:
cargo xtask dist --target aarch64-unknown-linux-musl
```

The eBPF object uses the selected target architecture automatically.

### Toolchain requirements

- `rustup target add` is run for you by `cargo xtask dist`. The aarch64
  **glibc** target needs a cross linker on an x64 Linux host:

  ```bash
  sudo apt-get install -y gcc-aarch64-linux-gnu
  ```

  This is wired up in [`.cargo/config.toml`](../.cargo/config.toml). Both musl
  targets link fully static via `rust-lld` and need no extra C toolchain.

`cargo xtask docker-build` builds for the host architecture by default. To
cross-build an image, use `cargo xtask docker-build --arch aarch64` (or
`--arch x86-64`); the binary and image platform are selected together.

For npm package staging, tests and publishing, see [npm releases](npm-releases.md).
