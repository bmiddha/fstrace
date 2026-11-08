# Build with cargo xtask docker-build (optionally --arch aarch64 or --arch x86-64).
# Manual builds need a static fstrace-daemon binary in the build context.
# Mount and privilege requirements: docs/deployment.md.

FROM scratch

COPY fstrace-daemon /fstrace-daemon

# Share this socket directory with clients; paths must match.
ENV FSTRACE_SOCKET=/run/fstrace/fstrace.sock

ENTRYPOINT ["/fstrace-daemon"]
