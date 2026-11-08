# Running the daemon

Start the daemon as root before clients connect. It runs in the foreground
under any init system, or without one.

Use matching builds and the same `FSTRACE_SOCKET` path on both sides. The
[README](../README.md#requirements) covers kernel and privilege requirements.

## systemd

Install the provided units:

```sh
sudo cp packaging/systemd/fstrace.socket packaging/systemd/fstrace.service \
  /etc/systemd/system/
sudo systemctl enable --now fstrace.socket
```

The first connection starts the daemon. It adopts systemd's socket through
`LISTEN_FDS`/`LISTEN_PID`, or binds its own when started directly. Keep the
unit's `ListenStream=` and clients' `FSTRACE_SOCKET` in sync.

## Docker / OCI containers

The daemon's static musl binary needs no runtime libraries. Build its
[`FROM scratch` image](../packaging/docker/Dockerfile) with:

```bash
cargo xtask docker-build      # -> image tag fstrace-daemon:xtask-test
```

Run the **daemon** in the container and bind-mount its socket directory to the
host, so unprivileged clients on the host connect to it without sudo. It needs
the eBPF capabilities (or `--privileged`) and a kernel with BTF:

```bash
mkdir -p /run/fstrace
docker run -d --name fstrace-daemon --privileged \
  -v /run/fstrace:/run/fstrace \
  -v /sys/kernel/btf:/sys/kernel/btf:ro \
  fstrace-daemon:xtask-test

fstrace ls 3>&1                          # trace on the host, no sudo
```

Neither `--pid=host` nor a host `/proc` mount is required. The kernel authenticates
each client's actual child; the daemon does not trust supplied PIDs. It can run
in a different PID and mount namespace from clients. It mounts missing tracefs
at `/sys/kernel/tracing`, so no tracefs bind mount is needed.

The runtime must be **rootful**: rootless containers cannot create BPF maps
(`EPERM`). `cargo xtask docker-test` checks this setup; the VM suite checks
namespace isolation with `unshare` (see [Testing](testing.md)).

## Client seccomp profiles
If the client runs under a custom seccomp profile, allow `clone` with
`CLONE_PIDFD`, `pidfd_send_signal`, and `waitid` with `P_PIDFD`. All supported
kernels provide them. Blocked calls fail explicitly; cleanup never falls back
to unsafe numeric PIDs.

The cross-UID report-pipe helper also needs `close_range` (Linux 5.9+); allow it
when using inherited pipes owned by another user.

## SysV init / OpenRC (`/etc/init.d`)

Install the [init script](../packaging/init.d/fstrace), which uses
`start-stop-daemon`:

```sh
install -m 0755 packaging/init.d/fstrace /etc/init.d/fstrace
update-rc.d fstrace defaults        # Debian
rc-update add fstrace default       # OpenRC
```

Override `DAEMON`, `DAEMON_ARGS`, or `FSTRACE_SOCKET` in `/etc/default/fstrace`
(the script sources it if present); keep `FSTRACE_SOCKET` in sync with the
clients.

## Other supervisors

Run `fstrace-daemon` as a foreground service under runit, s6, supervisord or
another supervisor. No daemonization flags or wrapper script are needed.
