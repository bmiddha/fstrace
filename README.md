# fstrace

[![Build](https://github.com/bmiddha/fstrace/actions/workflows/ci.yml/badge.svg)](https://github.com/bmiddha/fstrace/actions/workflows/ci.yml)

fstrace reports a command's filesystem accesses using Linux eBPF.

## Install

```sh
npm i -g @fstrace/fstrace
```

The npm/pnpm package provides `fstrace` and `fstrace-daemon` for **Linux x64 and ARM64**,
on glibc or musl. npm must install optional dependencies to get the matching
static binaries. Node.js **22+**, `sh`, `dirname`, and `readlink` must be on
`PATH`, including under `sudo`. You can also [build from source](docs/building.md).

## Quick start

Start the privileged daemon, then run clients as your normal user:

```bash
sudo fstrace-daemon &
fstrace touch /tmp/foo 3>&1
```

Arguments, including non-UTF8 Unix bytes, pass through unchanged: `fstrace ls --help` traces
`ls --help`. Use `fstrace --help` or `man fstrace` for the command reference.

## Requirements

- Kernel **5.8+ on x64, 6.4+ on ARM64**, with BTF
  (`CONFIG_DEBUG_INFO_BTF=y`), BPF trampolines, ring buffers and ftrace support.
  ARM64 needs ftrace direct calls, not just its older BPF trampoline support.
- Root, or `CAP_BPF` + `CAP_PERFMON` (or `CAP_SYS_ADMIN`), for the daemon.
  The client needs no elevation.
- Matching client and daemon builds. `FSTRACE2` does not accept the old
  PID-only handshake.

**Traced commands cannot gain privileges through sudo, setuid executables or
file capabilities.** `PR_SET_NO_NEW_PRIVS` applies to the traced child and its
descendants, not the client or embedding caller.

See [deployment](docs/deployment.md) for services, containers and seccomp
requirements, and [testing](docs/testing.md#kernels-and-ci) for kernel coverage.

## Reports

Reports go to **file descriptor 3**. Use `3>&1` for stdout, `3>reports.txt` for
a file, or `FSTRACE_REPORT_FILE=/path/to/report` instead of FD 3. sudo normally
closes inherited FDs 3 and above; if needed, redirect inside its shell:

```sh
sudo sh -c 'fstrace touch /tmp/foo 3>&1'
```

Each line is `<access><type> <path>`, for example `WF /tmp/foo`.

| Field | Values |
| --- | --- |
| Access | `R` read, `W` write/create, `D` delete; `E` is reserved for enumeration |
| Type | `F` file, `D` directory, `X` missing, `L` symlink, `?` unknown |

Metadata-only `stat`/`access`/`readlink` and `getdents` calls are not traced.
Paths use captured cwd and FD state, never live `/proc` lookups. Relative paths
through inherited, duplicated or otherwise uncaptured directory FDs fail with
`trace incomplete`. This is not an audit trail: concurrent path changes,
renamed directories and untracked `fcntl`/`close_range`/`unshare` can leave
cached paths stale. Report text represents non-UTF8 path bytes lossily.

Closed or read-only FD 3 is rejected before launch. Report write/flush errors,
event loss, unresolved path bases, a broken daemon stream or missing completion fail the trace.
Success waits for accepted events to drain after root-command exit, not for
orphaned descendants to finish. Otherwise the command's exit code is returned;
signal `N` becomes `128+N`, and exec failure returns 127.

Pipe/socket writes have a 30-second deadline without changing the caller's
shared `O_NONBLOCK` flag. Pipes use a separate writer or a cancellable, reaped
helper for cross-UID inherited pipes; that helper needs `close_range` (Linux
5.9+). Sockets use nonblocking sends. The traced command keeps its original FD.
Disk/device writes have no deadline.

## Guides

- [Configuration](docs/configuration.md): filters, debounce, logging and profiling.
- [Deployment](docs/deployment.md): systemd, containers and other service managers.
- [Building](docs/building.md): contributor setup and cross-compilation.
- [Testing](docs/testing.md): local checks, VM suites and kernel maintenance.
- [Architecture](docs/architecture.md): protocol and lifecycle rules for maintainers.
- [npm releases](docs/npm-releases.md): package staging and publishing.
