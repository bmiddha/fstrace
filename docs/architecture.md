# Architecture: the fstrace daemon

Loading eBPF requires elevated privileges, but you should not have to run every
traced command as root. `fstrace` is therefore split into two parts:

- **`fstrace-daemon`** — a privileged background process. It loads and attaches
  the eBPF programs once, owns the kernel ring buffer and the traced-pid map,
  and serves clients over a Unix socket. This is the *only* component that needs
  root (`CAP_BPF`/`CAP_SYS_ADMIN`).
- **`fstrace`** — the unprivileged client. It runs as the invoking user, forks
  and execs your command, asks the daemon to trace it, and turns the kernel
  events streamed back over the socket into resolved, filtered reports. Path
  resolution reads the client's *own* `/proc/<pid>` entries, so no elevation is
  needed.

Start the daemon once (as root), then run as many clients as you like without
`sudo`:

```bash
# One-time, privileged: start the daemon (foreground; use a service manager or
# `&`/nohup to background it).
sudo ./target/release/fstrace-daemon &

# Unprivileged from here on — note fd 3 works because there is no sudo:
./target/release/fstrace bash -c 'echo foo >> /tmp/foo' 3>&1
```

The daemon supports **multiple simultaneous clients** and routes each client
only the events for its own process tree (including forked descendants). Point
both sides at a custom socket with `FSTRACE_SOCKET` to run an isolated daemon.

Because the daemon never inspects `/proc` and routes events solely by their
root-namespace pid, it stays correct even when it runs in a *different pid and
mount namespace* than its clients — which is what makes the
[containerized deployment](deployment.md) work.

A minimal systemd unit:

```ini
# /etc/systemd/system/fstrace.service
[Unit]
Description=fstrace eBPF daemon
[Service]
ExecStart=/usr/bin/fstrace-daemon
Restart=on-failure
[Install]
WantedBy=multi-user.target
```

For init systems other than systemd (containers, SysV/OpenRC, runit/s6,
supervisord, or nothing at all), see [Deployment](deployment.md).

## Socket activation (start on demand)

The daemon implements the systemd `sd_listen_fds(3)` protocol, so it can be
**socket-activated**: systemd owns the listening socket and starts the daemon
automatically on the first client connection. Ready-to-use units live in
[`packaging/systemd/`](../packaging/systemd):

```bash
sudo cp packaging/systemd/fstrace.socket packaging/systemd/fstrace.service \
  /etc/systemd/system/
sudo systemctl enable --now fstrace.socket   # start listening; no daemon yet

# First client connection transparently launches the daemon:
fstrace bash -c 'echo foo >> /tmp/foo' 3>&1
```

If systemd passes the socket (`LISTEN_FDS`/`LISTEN_PID`), the daemon adopts it
instead of binding its own; otherwise it binds the socket directly (the manual
`fstrace-daemon &` case above). Keep `ListenStream=` in the `.socket` unit in
sync with the client's `FSTRACE_SOCKET`.
