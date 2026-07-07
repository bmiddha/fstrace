# Reports and file descriptor 3

By default reports are written to **file descriptor 3**, so you redirect it with
`3>&1` (to stdout) or `3>reports.txt` (to a file).

Because loading eBPF requires elevated privileges, that work is delegated to the
privileged [`fstrace-daemon`](architecture.md) so the `fstrace` client itself
runs **without `sudo`** — meaning a `3>&1` from your shell just works. If you
nonetheless run the client under `sudo`, note that `sudo` **closes inherited
file descriptors ≥ 3**, which discards a `3>&1` set up by your outer shell. Use
one of these instead:

```bash
# Put the redirection *inside* the elevated shell:
sudo sh -c './target/release/fstrace bash -c "echo foo >> /tmp/foo" 3>&1'

# Or point reports at a file with FSTRACE_REPORT_FILE (survives sudo):
sudo env FSTRACE_REPORT_FILE=/dev/stdout ./target/release/fstrace bash -c 'echo foo >> /tmp/foo'
```

If fd 3 is not open and `FSTRACE_REPORT_FILE` is unset, `fstrace` exits with an
error explaining how to fix the invocation.
