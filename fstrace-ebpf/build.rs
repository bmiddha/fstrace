//! Building this crate has an undeclared dependency on the `bpf-linker` binary.
//! This build script causes cargo to rebuild the crate whenever the mtime of
//! `which bpf-linker` changes.
use which::which;

fn main() {
    let bpf_linker = which("bpf-linker").unwrap();
    println!("cargo:rerun-if-changed={}", bpf_linker.to_str().unwrap());
}
