# Deployment without systemd (containers, init scripts, supervisors)

The daemon is a plain foreground process, so it runs under any init system or
none at all — it only needs to be started once, as root, before clients connect.
The client waits for nothing special: as soon as the socket exists, unprivileged
clients can connect.

See [Architecture](architecture.md) for systemd units and socket activation.

## Docker / OCI containers

A `FROM scratch` image for the daemon ships at
[`packaging/docker/Dockerfile`](../packaging/docker/Dockerfile). Because the
daemon is a fully static (musl, static-PIE) binary that loads eBPF purely
through syscalls (aya is pure Rust — no libbpf), the image needs nothing else.
Build it with the xtask helper (compiles the static daemon and bakes the image):

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

No `--pid=host` is required: the daemon never inspects `/proc` and routes kernel
events solely by their root-namespace pid, so it stays correct even though it
runs in a *different pid and mount namespace* than its host clients. No tracefs
bind-mount is needed either: when tracefs is absent the privileged daemon mounts
it itself at `/sys/kernel/tracing`, so a `FROM scratch` image with only the BTF
mount is enough. The container runtime must be **rootful** — a rootless container
cannot create BPF maps (`EPERM`). `cargo xtask docker-test` runs this whole flow
end-to-end (build image, start the privileged container, trace a host command,
assert the report); the VM suite additionally exercises the same
namespace-split with `unshare` on every run (see [Testing](testing.md)).

To instead run the daemon *and* an unprivileged workload in one container, start
the daemon in your entrypoint, wait for the socket, then hand off:

```sh
#!/bin/sh
# entrypoint.sh
set -e
fstrace-daemon &                       # privileged, backgrounded
for _ in $(seq 1 50); do
  [ -S /run/fstrace/fstrace.sock ] && break
  sleep 0.1
done
exec "$@"                              # your (unprivileged) workload
```

## SysV init / OpenRC (`/etc/init.d`)

A ready-to-use LSB script ships in the repo at
[`packaging/init.d/fstrace`](../packaging/init.d/fstrace). It uses
`start-stop-daemon` to background and track the pid, waits for the socket on
start, clears a stale socket left by an unclean shutdown, and supports
`start|stop|restart|force-reload|status`. Install and enable it with:

```sh
install -m 0755 packaging/init.d/fstrace /etc/init.d/fstrace
update-rc.d fstrace defaults        # Debian
rc-update add fstrace default       # OpenRC
```

Override `DAEMON`, `DAEMON_ARGS`, or `FSTRACE_SOCKET` in `/etc/default/fstrace`
(the script sources it if present); keep `FSTRACE_SOCKET` in sync with the
clients.

## runit / s6 / supervisord and other supervisors

Point the supervisor at `fstrace-daemon` as a normal long-running foreground
service (no daemonization flags needed), e.g. a runit `run` script is just:

```sh
#!/bin/sh
exec fstrace-daemon
```

## Nothing at all

In a throwaway environment you can simply background it:

```bash
sudo fstrace-daemon &            # or: sudo nohup fstrace-daemon >/var/log/fstrace.log 2>&1 &
```

In every case set `FSTRACE_SOCKET` on both the daemon and the clients if you
want a non-default socket path.
