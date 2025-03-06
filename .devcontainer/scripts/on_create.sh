#!/bin/bash
set -evx

sudo apt-get update

KERNEL_RELEASE=$(uname -r)

sudo apt-get install -y \
  clang \
  llvm \
  libbpf-dev \
  build-essential \
  linux-headers-generic \
  linux-headers-$(KERNEL_RELEASE) \
  linux-tools-common \
  linux-tools-generic \
  linux-tools-$(KERNEL_RELEASE)

sudo ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/asm

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
. "$HOME/.cargo/env"
rustup install stable
rustup toolchain install nightly --component rust-src
cargo install bpf-linker
cargo install cargo-generate
