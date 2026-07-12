# Logging (`RUST_LOG`)

All binaries use [`tracing`](https://docs.rs/tracing) with the standard
`RUST_LOG` [env-filter](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html)
syntax, so you can dial verbosity up or down per module:

```bash
# Everything fstrace emits at trace level (handshake, routing, per-access decisions):
RUST_LOG=fstrace=trace fstrace ls / 3>/dev/null

# Just the daemon's event router at trace, everything else quiet:
RUST_LOG=fstrace::daemon=trace fstrace-daemon

# Global debug:
RUST_LOG=debug fstrace ls / 3>/dev/null
```

Levels used: `debug` logs one line per raw kernel event; `trace` additionally
logs client↔daemon handshake steps, per-pid event routing in the daemon, and
each filter/debounce/report decision in the client. When `RUST_LOG` is unset the
default is `warn` (or `debug` when `FSTRACE_DEBUG=1`, a shorthand for
`RUST_LOG=fstrace=debug`).

## Writing logs to files

By default logs go to stderr. To capture them instead, in order of precedence:

```bash
# One explicit file (all output appended here):
RUST_LOG=fstrace=trace FSTRACE_LOG_FILE=/var/log/fstrace.log fstrace ls / 3>/dev/null

# One file per process under a directory — the daemon writes
# fstrace-daemon.log and each client writes fstrace-<pid>.log, so concurrent
# clients and the daemon never interleave:
sudo env RUST_LOG=fstrace=trace FSTRACE_LOG_DIR=/var/log/fstrace fstrace-daemon &
RUST_LOG=fstrace=trace FSTRACE_LOG_DIR=/var/log/fstrace fstrace ls / 3>/dev/null
```

`FSTRACE_LOG_DIR` is created if it does not exist. `FSTRACE_DEBUG_FILE` remains
supported as a legacy alias for `FSTRACE_LOG_FILE`.

## Aggregate performance profiling

Set `FSTRACE_PROFILE=1` in both the daemon and client environments to emit
low-volume timing summaries instead of one log entry per event:

```bash
sudo env FSTRACE_PROFILE=1 FSTRACE_LOG_FILE=/tmp/fstrace-daemon.profile \
  fstrace-daemon &
FSTRACE_PROFILE=1 FSTRACE_LOG_FILE=/tmp/fstrace-client.profile \
  fstrace npm run build 3>/dev/null
```

The client summary separates event classification/path resolution, filtering,
debouncing, report formatting/writes, queue latency, and post-exit draining.
The daemon summary covers event encoding/routing, queue drops, wire bytes, and
socket writes. The eBPF summary reports per-syscall capture time, pathname-copy
time and bytes, successful ring-buffer submissions, and ring-buffer drops.
Per-syscall detail is sorted by total processing time.

Profiling is opt-in because it reads clocks and updates counters for every
traced event. Normal runs do not collect those timings. eBPF interval snapshots
are global to the daemon, so profile one client at a time when exact attribution
matters.
