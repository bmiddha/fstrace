# Testing

Unit tests run without privileges:

```bash
cargo xtask test        # or: cargo test --release --workspace --exclude fstrace-ebpf
```

`cargo xtask check` runs formatting, Clippy and unit tests.

The privileged suite runs in a disposable QEMU VM, not on the host.
`xtask` starts the VM, `fstrace-vmtest` runs the tests, and `fstrace-scenario`
provides small syscall fixtures:

```bash
cargo xtask vm-test
# Or select a guest architecture explicitly (including cross-emulation):
cargo xtask vm-test --arch aarch64 --release 6.12
cargo xtask vm-test --arch x86-64 --release 6.12
```

The harness builds static musl binaries, downloads a kernel, and builds an
initramfs from a Docker image. The guest runs the daemon as root and clients
as an unprivileged user. Tests cover syscall reports, PATH_MAX, exit codes,
signals, environment, concurrent clients, logging and socket activation.

The guest architecture defaults to the host. Binaries, kernel, rootfs and QEMU
settings follow the selected architecture. Install `qemu-system-x86` for x64 or
`qemu-system-arm` for ARM64, plus `docker`, `cpio`, `binutils`, `curl`, `zstd`,
and `sudo`.
Cross-architecture guests use TCG rather than KVM. ARM64 tests require kernel
6.4+ for kernel-function fentry/fexit (ftrace direct calls). Legacy syscall
scenarios use libc wrappers that issue the corresponding `*at` calls on ARM64;
expected reports remain identical.
The exec scenarios cover successful exec, non-leader thread exec, and relative
`execveat` directory fds, including ARM64's reset of argument registers on exec.

Lifecycle tests check exact inherited cwd/dirfd paths, surviving workers after
leader exit, failed nonleader exec and thread churn. Authentication tests reject
arbitrary PIDs, wrong tokens, missing no-new-privileges and registration after a
privileged exec. A setuid fixture elevates only when untraced. Namespace tests
use a daemon in its own PID/mount namespace, a host client, a nested-PID-namespace
client, and unauthenticated requests.

Report tests use read-only FD 3, `/dev/full`, and an unread pipe receiving
4,090-byte paths. The pressure test must fail within the deadline, stay below
64 MiB client RSS, and leave the daemon usable. It takes about 30 seconds.
Unit tests also cover delayed events after `FINISH`, bad streams, missing/lossy
`DONE`, write/flush errors, blocked writers, cancellation, helper reaping,
external child reaping, duplicate ownership, TID reuse and cache cleanup.
Review regressions cover retained peer sockets after cancellation, initially
empty shared FD tables, missing path bases, required-hook startup failure,
SIGPIPE, non-UTF8 argv, and nonthread `CLONE_FS` cwd sharing across exec.

## Kernels and CI

Minimum requirements are [listed in the README](../README.md#requirements).
x64 5.8 and 5.9 meet the feature floor but are outside the CI matrix.
ARM64 6.1 cannot attach kernel-function probes: ftrace direct calls arrived
in 6.4.

`--release <name>` selects a kernel from the Ubuntu mainline archive
([downloader](../xtask/src/kernel.rs)). The
[Docker rootfs](../xtask/src/initramfs.rs) is selected separately; test binaries
are static musl:

```bash
cargo xtask vm-test --release 5.15     # LTS
cargo xtask vm-test --release 7.2-rc   # mainline
```

Available selectors: `5.10`, `5.15`, `6.1`, `6.6`, `6.12`, `6.18`, `7.1`,
`7.2-rc` (default `6.12`). Override the userspace image with
`FSTRACE_VM_IMAGE=docker.io/library/alpine:latest`.

Pinned versions live in [`RELEASES`](../xtask/src/vm.rs).
[CI](../.github/workflows/ci.yml) runs all selectors on x64 and 6.6+ on ARM64,
each with Ubuntu/glibc and Alpine/musl. It also runs unit tests and Clippy on
both architectures. A configured job is not proof of a successful run; check
the results for the commit being tested. Socket activation is skipped when
`systemd-socket-activate` is absent from the rootfs.

The fork hook reads task fields using the running kernel's BTF, not fixed
tracepoint-record offsets.

### Testing different userspaces

Set `FSTRACE_VM_IMAGE` to choose the rootfs. The suite supports **glibc +
shadow-utils** (`ubuntu:latest`, the default) and **musl + BusyBox**
(`alpine:latest`):

```bash
FSTRACE_VM_IMAGE=docker.io/library/alpine:latest cargo xtask vm-test --release 6.12
```

The downloader decompresses ARM64 zstd EFI zboot images for QEMU. The harness
shows the full guest console, including loader and daemon errors.

An opt-in downloader integration test requires `curl`, `ar`, GNU `tar`, and
`zstd`, and downloads the pinned 6.18 ARM64 kernel:

```bash
cargo test -p xtask downloaded_arm64_zboot_image -- --ignored
```

## Maintaining the matrix

The weekly [schedule](../.github/workflows/kernel-maintenance-cron.yml) calls
[kernel maintenance](../.github/workflows/kernel-maintenance.yml), which asks
Copilot to update `RELEASES`, the CI matrix and this guide from
[kernel.org](https://www.kernel.org/releases.json). Versions must have prebuilt
images in the Ubuntu mainline archive for the tested architectures.

The workflow skips while a maintenance issue is open and supports manual
dispatch with `dry_run`. Enable Copilot coding agent for the repository.
If needed, supply `COPILOT_AGENT_TOKEN` with issue-write permission.

## Container check

The containerized daemon can also be exercised directly, on any host with a
rootful container runtime and a BTF-enabled kernel:

```bash
cargo xtask docker-test
```

This builds the `FROM scratch` image, starts a privileged daemon with a
bind-mounted socket, and checks a host command's report.
