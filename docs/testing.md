# Testing

Host-side unit tests (path normalization, filters, debounce, classification,
resolution) run without privileges:

```bash
cargo xtask test        # or: cargo test --release --workspace --exclude fstrace-ebpf
```

Run `cargo xtask check` to reproduce the full CI lint/test gate locally
(format check + clippy + unit tests).

The privileged loader and enabled syscall set are exercised end-to-end inside a
throwaway QEMU VM, so the eBPF programs never load on the host. The harness is
written entirely in Rust: `xtask` drives the VM orchestration, the `fstrace-vmtest`
crate provides the in-guest suite, and a thin companion binary, `fstrace-scenario`,
performs the raw syscalls that `fstrace` traces (kept dependency-light so the
traced process carries no harness noise):

```bash
cargo xtask vm-test
# Or select a guest architecture explicitly (including cross-emulation):
cargo xtask vm-test --arch aarch64 --release 6.12
cargo xtask vm-test --arch x86-64 --release 6.12
```

This builds static (musl) binaries, downloads a prebuilt upstream kernel, builds
an initramfs from a Docker image rootfs, and direct-kernel-boots the pair in
QEMU to run the full privileged suite (per-syscall reports, PATH_MAX stress,
exit-code/signal/env passthrough, concurrent clients, per-process logging,
systemd socket activation, and a namespace-isolation test that runs the daemon
in a separate pid + mount namespace via `unshare` — mirroring the containerized
deployment — and verifies host-namespace clients still get correct traces,
including fork-following across the boundary) as an unprivileged user inside the
guest.

The guest architecture defaults to the host. The harness selects the matching
static binaries, kernel download, Docker rootfs platform, QEMU machine, and
serial console together. Install `qemu-system-x86` for x64 or `qemu-system-arm`
for ARM64, plus `docker`, `cpio`, `binutils`, `curl`, `zstd`, and `sudo`.
Cross-architecture guests use TCG rather than KVM. ARM64 tests require kernel
6.0+ for BPF trampolines. Legacy syscall scenarios use libc wrappers that issue
the corresponding `*at` calls on ARM64; expected reports remain identical.

### Testing specific kernel versions

`--release <name>` selects a different prebuilt upstream kernel. The kernel image
comes from the Ubuntu mainline archive
([`xtask/src/kernel.rs`](../xtask/src/kernel.rs)) and the guest userspace from a
Docker image ([`xtask/src/initramfs.rs`](../xtask/src/initramfs.rs)); the two are
pinned independently, and the in-guest binaries are static musl, so the result
reflects the kernel only:

```bash
cargo xtask vm-test --release 5.15     # LTS
cargo xtask vm-test --release 7.2-rc   # mainline
```

Available selectors: `5.10`, `5.15`, `6.1`, `6.6`, `6.12`, `6.18`, `7.1`,
`7.2-rc` (default `6.12`). Override the userspace image with
`FSTRACE_VM_IMAGE=docker.io/library/alpine:latest`.

### Testing different userspaces

The guest userspace is any Docker image, selected with `FSTRACE_VM_IMAGE`. The
suite is verified against both **glibc + shadow-utils** (`ubuntu:latest`, the
default) and **musl + BusyBox** (`alpine:latest`), so the harness stays portable
across libcs and coreutils:

```bash
FSTRACE_VM_IMAGE=docker.io/library/alpine:latest cargo xtask vm-test --release 6.12
```

CI runs every x64 kernel against both images, and ARM64 kernels from 6.1
onward against both images on native ARM64 runners. Host tests and Clippy also
run on both architectures. CI execution is distinct from local compile coverage.

See [Kernel version support](kernel-support.md) for the full verified matrix and
the minimum supported kernel. CI runs this suite across all supported LTS,
stable, and mainline kernels.


The containerized daemon can also be exercised directly, on any host with a
rootful container runtime and a BTF-enabled kernel:

```bash
cargo xtask docker-test
```

This builds the `FROM scratch` image, starts the daemon as a privileged
container with its socket bind-mounted to the host, traces a command from the
host namespace, and asserts the report.

> **Note:** eBPF/BTF replaces the previous `ptrace`+`seccomp` implementation.
> This requires a modern, BTF-enabled kernel; in exchange, tracing runs with far
> less per-syscall overhead.
