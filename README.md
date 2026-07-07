# fstrace

[![Build](https://github.com/bmiddha/fstrace/actions/workflows/ci.yml/badge.svg)](https://github.com/bmiddha/fstrace/actions/workflows/ci.yml)

fstrace uses [eBPF](https://ebpf.io/) (via [Aya](https://aya-rs.dev/)) to check file system accesses of a program.

```bash
fstrace touch /tmp/foo 3>&1

RX /vscode/bin/linux-x64/384ff7382de624fb94dbaf6da11977bba1ecd427/bin/remote-cli/touch
RX /usr/local/share/nvm/versions/node/v18.20.4/bin/touch
RX /usr/local/sbin/touch
RX /usr/local/bin/touch
RX /usr/sbin/touch
RF /usr/bin/touch
RX /etc/ld.so.preload
RF /etc/ld.so.cache
RF /lib/x86_64-linux-gnu/libc.so.6
WF /tmp/foo
```

Each line is `<access_type><file_type> <file_path>` — see
[Output format](docs/output-format.md) for the full legend.

## Install

```sh
npm i -g fstrace
```

Or [build from source](docs/building.md).

## Quick start

fstrace is split into a privileged **`fstrace-daemon`** (loads eBPF, runs once as
root) and an unprivileged **`fstrace`** client (traces your commands without
`sudo`). Start the daemon once, then trace freely:

```bash
sudo fstrace-daemon &                             # one-time, privileged
fstrace bash -c 'echo foo >> /tmp/foo' 3>&1       # unprivileged
```

Reports go to **file descriptor 3**; redirect it with `3>&1` (stdout) or
`3>reports.txt`. See [Reports and file descriptor 3](docs/reports-and-fd3.md).

## Documentation

- [Output format](docs/output-format.md) — how to read reports.
- [Configuration](docs/configuration.md) — filters, debounce, and the
  environment-variable reference.
- [Logging (`RUST_LOG`)](docs/logging.md) — verbosity control and logging to files.
- [Reports and file descriptor 3](docs/reports-and-fd3.md) — the report stream
  and running under `sudo`.
- [Architecture: the fstrace daemon](docs/architecture.md) — the daemon/client
  split, systemd units, and socket activation.
- [Deployment](docs/deployment.md) — Docker/OCI containers, SysV/OpenRC init
  scripts, and other supervisors.
- [Building from source](docs/building.md) — prerequisites and build steps.
- [Testing](docs/testing.md) — unit tests and the end-to-end VM/container suites.
- [Kernel version support](docs/kernel-support.md) — the minimum kernel, the
  verified LTS/stable/mainline matrix, and how to run it.
