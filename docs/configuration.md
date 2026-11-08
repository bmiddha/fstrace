# Configuration

Use environment variables to filter reports and control diagnostics.

## Filters

Lists are colon-separated. A negative match wins; otherwise a positive match
allows the path. Unmatched paths are ignored.

- `FSTRACE_FILTER_PREFIX`: Only allow paths that start with this prefix. Defaults to `/`.
- `FSTRACE_FILTER_SUBSTRING`: Only allow paths that contain this substring.
- `FSTRACE_NEGATIVE_FILTER_PREFIX`: Ignore paths that start with this prefix.
- `FSTRACE_NEGATIVE_FILTER_SUBSTRING`: Ignore paths that contain this substring.

An empty or unset positive prefix defaults to `/`, so all absolute paths pass
unless excluded. A positive substring adds matches; it does not narrow that
default prefix.

```sh
FSTRACE_FILTER_PREFIX=/tmp:/home FSTRACE_NEGATIVE_FILTER_PREFIX=/tmp/cache \
  fstrace make 3>reports.txt
```

## Other settings

| Variable | Purpose |
| --- | --- |
| `FSTRACE_DEBOUNCE` | Set to `1` to suppress duplicate reports; default off. `SIGUSR1` clears the cache. |
| `FSTRACE_REPORT_FILE` | Report path instead of FD 3; see [reports](../README.md#reports). |
| `FSTRACE_SOCKET` | Socket path for both daemon and client; default `/run/fstrace/fstrace.sock`. |

## Logging

Logs go to stderr by default. `RUST_LOG` uses
[`tracing` filter syntax](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html):

```sh
RUST_LOG=fstrace=trace fstrace ls / 3>/dev/null
RUST_LOG=fstrace::daemon=trace fstrace-daemon
```

`debug` includes raw events; `trace` adds handshake, routing and report decisions.
Without `RUST_LOG`, the default is `warn`, or `debug` with `FSTRACE_DEBUG=1`.
Profiling enables its own summary logs.

Log destinations, in precedence order:

1. `FSTRACE_LOG_FILE`: append to one file.
2. `FSTRACE_LOG_DIR`: create a directory with `fstrace-daemon.log` and
   `fstrace-<pid>.log` so processes do not share a file.
3. `FSTRACE_DEBUG_FILE`: legacy alias for a shared log file.
4. stderr.

## Profiling

Set `FSTRACE_PROFILE=1` on both sides for aggregate timings:

```sh
sudo env FSTRACE_PROFILE=1 FSTRACE_LOG_FILE=/tmp/daemon.profile fstrace-daemon &
FSTRACE_PROFILE=1 FSTRACE_LOG_FILE=/tmp/client.profile fstrace make 3>/dev/null
```

Summaries cover client path resolution, filtering, debounce, reporting and
draining; daemon routing, queues and socket writes; and per-syscall eBPF capture,
path copies and ring submissions/losses. Normal runs skip timing collection.
Kernel snapshots are daemon-wide: profile one client at a time for exact
attribution.
