set -ev
sudo apt-get update
sudo apt-get install -y clang llvm libbpf-dev build-essential linux-headers-amd64 bpftool
sudo ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/asm
sudo mount -t tracefs nodev /sys/kernel/tracing
