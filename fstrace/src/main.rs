//! The `fstrace` binary: trace filesystem accesses of a command using eBPF.

fn main() -> ! {
    fstrace::runtime::entrypoint()
}
