# Kernel version support

`fstrace` loads eBPF `fexit` probes and a `BPF_MAP_TYPE_RINGBUF`, and it follows
process trees via the `sched_process_fork` tracepoint. Those features set a hard
lower bound on the kernel version.

## Requirements

| Feature                                   | Introduced | Why fstrace needs it                              |
| ----------------------------------------- | ---------- | ------------------------------------------------- |
| BTF (`CONFIG_DEBUG_INFO_BTF=y`)           | 5.2        | Resolve `fexit` attach targets from `vmlinux`     |
| `fexit` / BPF trampolines                 | 5.5        | Every syscall probe is an `fexit` program         |
| BPF ring buffer (`BPF_MAP_TYPE_RINGBUF`)  | 5.8        | The `EVENTS` map that carries events to userspace |

**Minimum supported kernel: 5.8** (the ring buffer is the newest hard
requirement). The kernel must also be built with BTF, which every mainstream
distro kernel and every upstream release since ~5.5 enables.

### Features missing on older kernels

- **< 5.2** — no BTF, so `fexit` targets cannot be resolved from `vmlinux`.
  fstrace cannot attach at all.
- **< 5.5** — no BPF trampolines, so `fexit` programs cannot be created. Every
  fstrace syscall probe is `fexit`, so nothing attaches.
- **< 5.8** — no `BPF_MAP_TYPE_RINGBUF`. The `EVENTS` map fails to create
  (`EINVAL`) and the loader aborts. This is the **binding floor**; empirically
  5.4 fails here while 5.10 passes.
- **>= 6.16** — the `sched_process_fork` tracepoint record changed its `*_comm`
  fields from `char[16]` to `__data_loc`, moving `child_pid`. Handled at
  runtime (see the gotcha below); no minimum-version impact.

## Test methodology

The kernel and the userspace are pinned **independently** so the kernel version
is the only variable under test:

- **Kernel** — a *prebuilt* upstream `bzImage` downloaded by
  [`xtask/src/kernel.rs`](../xtask/src/kernel.rs) from the
  [Ubuntu mainline archive](https://kernel.ubuntu.com/mainline/), which
  publishes a BTF-enabled image for every upstream tag (LTS, stable, and
  mainline release candidates). Images are cached under `tests/vm/.cache/kernels/`.
- **Userspace** — an initramfs built by
  [`xtask/src/initramfs.rs`](../xtask/src/initramfs.rs) from a Docker
  image rootfs (`ubuntu:latest` by default) plus the host-built **static-musl**
  fstrace binaries and an `/init` that runs the privileged guest suite. The
  suite is verified against both `ubuntu:latest` (glibc + shadow-utils) and
  `alpine:latest` (musl + BusyBox); select one with `FSTRACE_VM_IMAGE`.

QEMU direct-kernel-boots the pair (`-kernel` + `-initrd`) and the host scrapes
the serial console for a `FSTRACE_VM_RESULT:<code>` sentinel. The host never
loads the eBPF programs, so a buggy program cannot affect it. Because the guest
binaries are static musl, the result reflects the **kernel** only, not the
image's libc.

Run any kernel locally with:

```bash
cargo xtask vm-test --release 6.12      # or 5.10, 5.15, 6.1, 6.6, 6.18, 7.1, 7.2-rc
```

Override the userspace image with `FSTRACE_VM_IMAGE` (verified against both
`docker.io/library/ubuntu:latest` and `docker.io/library/alpine:latest`).

## Verified matrix

The matrix covers every active upstream **longterm** series, plus the current
**stable** and **mainline** lines released since the newest LTS. Every kernel
runs the full privileged suite (23 syscall/behavioural tests + namespace
isolation). `systemd-socket-activate` is absent from the minimal initramfs, so
that one test reports **SKIP** (treated as a pass).

| Kernel   | Tier     | `--release` | Result | Notes                 |
| -------- | -------- | ----------- | :----: | --------------------- |
| 5.10.260 | LTS      | `5.10`      | Pass   | 23/23 + namespace-iso |
| 5.15.211 | LTS      | `5.15`      | Pass   | 23/23 + namespace-iso |
| 6.1.177  | LTS      | `6.1`       | Pass   | 23/23 + namespace-iso |
| 6.6.144  | LTS      | `6.6`       | Pass   | 23/23 + namespace-iso |
| 6.12.95  | LTS      | `6.12`      | Pass   | 23/23 + namespace-iso |
| 6.18.38  | LTS      | `6.18`      | Pass   | 23/23 + namespace-iso |
| 7.1.3    | stable   | `7.1`       | Pass   | 23/23 + namespace-iso |
| 7.2-rc2  | mainline | `7.2-rc`    | Pass   | 23/23 + namespace-iso |

Kernels **5.8 and 5.9** are below the tested set but above the ring-buffer floor,
so they are expected to work; they are simply not part of the LTS/stable/mainline
matrix. Anything **< 5.8 is unsupported** (see the requirements table).

## Tested LTS + stable + mainline kernels in CI

CI runs the VM suite against the full matrix above
(see [`.github/workflows/ci.yml`](../.github/workflows/ci.yml)), against **both**
the `ubuntu:latest` (glibc) and `alpine:latest` (musl/BusyBox) userspaces. Each
job downloads the prebuilt kernel and boots it via QEMU; no kernel is compiled.

## Keeping the matrix current (automated)

The tested set is refreshed automatically by an **agent workflow** that delegates
the bump to the GitHub Copilot coding agent:

- [`.github/workflows/kernel-maintenance.yml`](../.github/workflows/kernel-maintenance.yml)
  — a reusable (`workflow_call` / `workflow_dispatch`) workflow. It files a task
  issue describing exactly what to change — track the latest `mainline` RC and
  `stable` release and rotate the `longterm` (LTS) lines from
  [`kernel.org/releases.json`](https://www.kernel.org/releases.json), updating
  the `RELEASES` source of truth in
  [`xtask/src/vm.rs`](../xtask/src/vm.rs), the `vm-e2e` matrix in `ci.yml`, and
  this document — and assigns it to the `copilot-swe-agent` bot, which opens a
  PR. The existing vm-e2e matrix then validates every proposed kernel.
- [`.github/workflows/kernel-maintenance-cron.yml`](../.github/workflows/kernel-maintenance-cron.yml)
  — the pipeline: a weekly schedule (Mondays 06:00 UTC) that calls the reusable
  workflow. It is idempotent — it skips itself while a `kernel-maintenance` issue
  is still open — and can also be run on demand (with an optional dry run) from
  the Actions tab.

Assigning the agent works with the default `GITHUB_TOKEN` when *Copilot coding
agent* is enabled for the repository; if your org requires a PAT to start the
agent, add a `COPILOT_AGENT_TOKEN` secret (fine-grained, `issues: write`).

## Kernel-version gotcha: `sched_process_fork` field offsets

The tracepoint record layout is **not** ABI-stable. Around Linux 6.16 the
`parent_comm`/`child_comm` fields changed from fixed `char[16]` arrays to
`__data_loc` dynamic strings, which moved `child_pid` from byte **44** to byte
**20**. A hardcoded offset silently reads garbage on newer kernels, so
fork-following breaks (children stop being traced) even though every other test
passes.

fstrace avoids this by reading the real offset from
`/sys/kernel/tracing/events/sched/sched_process_fork/format` at load time and
passing it to the eBPF program via a config map
([`fstrace/src/loader.rs`](../fstrace/src/loader.rs),
[`fstrace-ebpf/src/main.rs`](../fstrace-ebpf/src/main.rs)).
