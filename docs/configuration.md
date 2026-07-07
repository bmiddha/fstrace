# Configuration

fstrace is configured through environment variables.

## `FSTRACE_DEBOUNCE` (Default=`0`)

Debounce file access events. Send `SIGUSR1` to flush the debounce cache.

## Filters

Filter logic:

```
if FSTRACE_NEGATIVE_FILTER_PREFIX
  IGNORE
if FSTRACE_NEGATIVE_FILTER_SUBSTRING
  IGNORE
if FSTRACE_FILTER_PREFIX
  ALLOW
if FSTRACE_FILTER_SUBSTRING
  ALLOW

default
  IGNORE
```

Multiple paths can be specified by separating them with a colon `:`.

- `FSTRACE_FILTER_PREFIX`: Only allow paths that start with this prefix. Defaults to `/`.
- `FSTRACE_FILTER_SUBSTRING`: Only allow paths that contain this substring.
- `FSTRACE_NEGATIVE_FILTER_PREFIX`: Ignore paths that start with this prefix.
- `FSTRACE_NEGATIVE_FILTER_SUBSTRING`: Ignore paths that contain this substring.

## Environment variable reference

- `FSTRACE_DEBOUNCE`: Debounce file access events (see above).
- `FSTRACE_FILTER_PREFIX` / `FSTRACE_FILTER_SUBSTRING` /
  `FSTRACE_NEGATIVE_FILTER_PREFIX` / `FSTRACE_NEGATIVE_FILTER_SUBSTRING`: Path
  filters (see above).
- `FSTRACE_LOG_FILE`: Write log output to this explicit file path (all binaries). See [Logging](logging.md).
- `FSTRACE_LOG_DIR`: Write log output into this directory, one file per process (`fstrace-daemon.log`, `fstrace-<pid>.log`), so the daemon and concurrent clients never interleave.
- `FSTRACE_DEBUG_FILE`: Legacy alias for `FSTRACE_LOG_FILE` (single shared file).
- `FSTRACE_REPORT_FILE`: Write the report stream to this path instead of file descriptor 3. Recommended when running under `sudo` (see [Reports and file descriptor 3](reports-and-fd3.md)).
- `FSTRACE_SOCKET`: Path to the daemon's Unix socket (default `/run/fstrace/fstrace.sock`). Both the daemon and the client honour it; set it to run a private daemon.
