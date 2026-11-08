# Protocol and lifecycle

For maintainers changing the kernel probes, routing or client runtime.
For install and use, start with the [README](../README.md); service setup is in
[Deployment](deployment.md).

## Registration and authorization

Client and daemon must come from matching builds; the `FSTRACE2` socket protocol
is incompatible with the earlier PID-only registration.

Each connection gets a random, one-use 128-bit token. A required `prctl` fentry
hook binds it to the caller; the fork hook records that task's next child using
the running kernel's BTF. The child sets `PR_SET_NO_NEW_PRIVS`, acknowledges the
token, and stops. Before tracing, the kernel checks the live parent, task start
times, unchanged credentials and exec generation, and the no-new-privileges bit.
The daemon rejects supplied PIDs and duplicate ownership. Registration expires
after 10 seconds.

Membership uses global TID plus task start time, so old cleanup cannot remove a
new task with a reused TID. Events carry this identity and a session generation,
never kernel task or credential pointers.

No host PID namespace, host `/proc`, root-only socket, or translated
`SO_PEERCRED` PID is needed. Isolated daemons and nested-PID-namespace clients
are supported. Path bases come only from captured state and the initial cwd,
not namespace-dependent `/proc` IDs. Unknown bases fail the trace.

## Task state and completion

Routing and cwd/FD caches track each thread. Fork/clone records arrive before
child events and identify the TGID and shared `fs_struct`/`files_struct` state.
Clients copy or share caches accordingly. Thread exit keeps surviving threads'
state. Nonleader exec transfers ownership from the old TID and start time to
the new identity in order. Exec detaches files and drops close-on-exec FDs;
cwd remains shared with surviving `CLONE_FS` processes.

After reaping the root command, the client sends `FINISH`. The daemon stops new
capture, waits for active BPF producers, and drains through the final ring
producer position. It drains the outbound queue before sending `DONE` directly,
so a full queue cannot drop completion. Cancellation uses the same fence before
removing ownership. The session ends with the root command; it drains accepted
events but does not wait indefinitely for orphaned descendants.

Lost ring, lifecycle, map or queue events fail the trace, even without profiling.
Kernel loss is global and may fail overlapping sessions. Bad or truncated
frames, unexpected EOF, missing or lossy `DONE`, and report write/flush errors
also fail the trace. Completion and socket writes have 30-second deadlines.

Limits are 64 connections and 1,024 queued events per client on each side
(about 8 MiB per full queue). Overload cancels the affected session. Dispatch
batches keep busy traces from delaying cancellation.
Admission remains charged until the handler exits. The writer shuts down both
socket directions after `DONE`, unblocking a control read even if the peer
never sends `FINISH`.

Cleanup signals and waits through atomically created pidfds, so external child
reaping cannot redirect cleanup to a reused PID. Parent-death checks also cover
the gap between fork and setting the parent-death signal.

Exec drops FDs with unknown flags rather than risking stale close-on-exec state.
Other path-resolution limits are listed in the [README](../README.md#reports).

Every compiled hook is required. Failed attachment stops startup before the
daemon publishes its socket. The child resets SIGPIPE to its default before
exec; byte-preserving argv conversion happens before clone.
