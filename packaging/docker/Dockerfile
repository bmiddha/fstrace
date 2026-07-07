# Minimal container image for the privileged fstrace daemon.
#
# The daemon is a fully static (musl, static-PIE) binary and loads its eBPF
# programs purely through syscalls (aya is pure Rust — no libbpf/libelf), so it
# needs nothing else in the image: FROM scratch is enough. When tracefs is not
# already mounted (as in a bare scratch container) the privileged daemon mounts
# it itself, so only the BTF bind-mount below is required.
#
# Build the static daemon first, then the image (see `cargo xtask docker-build`,
# which automates both steps):
#
#   rustup target add x86_64-unknown-linux-musl
#   cargo build --release --target x86_64-unknown-linux-musl \
#       -p fstrace --bin fstrace-daemon
#   docker build -f packaging/docker/Dockerfile \
#       -t fstrace-daemon \
#       target/x86_64-unknown-linux-musl/release
#
# Run it (privileged for eBPF; bind-mount a host dir for the socket so
# unprivileged host clients can reach the daemon). The daemon never inspects
# /proc and only routes kernel events by their (root-namespace) pid, so it works
# correctly from inside its own pid + mount namespace — no --pid=host required:
#
#   mkdir -p /run/fstrace
#   docker run -d --name fstrace-daemon \
#       --privileged \
#       -v /run/fstrace:/run/fstrace \
#       -v /sys/kernel/btf:/sys/kernel/btf:ro \
#       fstrace-daemon
#
# Then trace on the host without sudo:
#
#   fstrace ls 3>&1
#
# The build context is expected to contain the prebuilt `fstrace-daemon`
# binary (the command above uses the musl target dir as the context).

FROM scratch

COPY fstrace-daemon /fstrace-daemon

# Socket lives under a directory the host bind-mounts in, so clients on the host
# can connect. Override with FSTRACE_SOCKET (must match the clients).
ENV FSTRACE_SOCKET=/run/fstrace/fstrace.sock

ENTRYPOINT ["/fstrace-daemon"]
