//! The privileged `fstrace-daemon` binary. Loads the eBPF programs once and
//! serves multiple unprivileged `fstrace` clients over a Unix socket.

fn main() -> ! {
    fstrace::daemon::main()
}
