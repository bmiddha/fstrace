# Building from source

## Prerequisites

- A Linux kernel built with BTF (`CONFIG_DEBUG_INFO_BTF=y`) and `fexit`/BPF
  trampoline support, plus the BPF ring buffer. In practice this means **kernel
  5.8 or newer** (most distro kernels since Ubuntu 20.10 / Debian 11). See
  [Kernel version support](kernel-support.md) for the verified matrix.
- Root privileges (`CAP_BPF` + `CAP_PERFMON`, or `CAP_SYS_ADMIN`) to run the
  `fstrace-daemon`, which loads the eBPF programs. The `fstrace` client needs no
  privileges.
- The [Rust toolchain](https://rustup.rs/). The pinned nightly and components are
  declared in `rust-toolchain.toml`.
- [`bpf-linker`](https://github.com/aya-rs/bpf-linker): `cargo install bpf-linker`.

## Build & run

```bash
cargo build --release
# Start the privileged daemon once (backgrounded here):
sudo ./target/release/fstrace-daemon &
# Then trace without sudo — fd 3 works because there is no sudo:
./target/release/fstrace bash -c 'echo foo >> /tmp/foo' 3>&1
```

See [Architecture: the fstrace daemon](architecture.md) for the daemon/client
split and [Reports and file descriptor 3](reports-and-fd3.md) for the
`FSTRACE_REPORT_FILE` alternative.

For verbose diagnostics, raise the log level with `RUST_LOG` (see
[Logging](logging.md)); `FSTRACE_DEBUG=1` is a shorthand for
`RUST_LOG=fstrace=debug`:

```bash
RUST_LOG=fstrace=trace ./target/release/fstrace bash -c 'echo foo >> /tmp/foo' 3>&1
```

## Development tasks (`cargo xtask`)

The entire repo lifecycle is driven through the `xtask` binary, so there are no
loose shell scripts to remember — every task is Rust:

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

Run `cargo xtask check` before pushing to reproduce the CI lint/test gate
locally.

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

The npm package ships the same man pages, so `npm i -g fstrace` registers
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
README) under `dist/`:

```bash
cargo xtask dist
# Or one target at a time:
cargo xtask dist --target aarch64-unknown-linux-musl
```

The eBPF object is compiled per userspace arch automatically (the loader reads
syscall-argument registers in an arch-aware way), so the same command produces a
working tracer on both x86-64 and aarch64.

### Toolchain requirements

- `rustup target add` is run for you by `cargo xtask dist`, but the aarch64
  targets need a cross **linker** on the host:

  ```bash
  sudo apt-get install -y gcc-aarch64-linux-gnu
  ```

  This is wired up in [`.cargo/config.toml`](../.cargo/config.toml). The musl
  targets link fully static via `rust-lld` and need no extra C toolchain.
