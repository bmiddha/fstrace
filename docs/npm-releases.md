# npm distribution and releases

For maintainers staging or publishing packages. Installation and runtime
requirements are in the [README](../README.md#install).

The public entry package is **`@fstrace/fstrace`**. Its commands remain
`fstrace` and `fstrace-daemon`; it does not embed native binaries or download
anything in an install hook. Exact-version optional dependencies provide them:

| Package | npm selectors | Contents |
| --- | --- | --- |
| `@fstrace/fstrace` | Linux, x64 or ARM64 | Launchers, man pages, README |
| `@fstrace/linux-x64` | Linux, x64 | Static musl client and daemon |
| `@fstrace/linux-arm64` | Linux, ARM64 | Static musl client and daemon |

Neither platform package has a `libc` selector: the fully static binaries run
on glibc **and** musl hosts. Unsupported operating systems and architectures
are rejected by npm and by the launcher's resolver. Missing optional packages,
version mismatches, and missing/non-executable binaries produce explicit errors.

Each command has a fixed-name shell launcher. It uses Node only to resolve the correct package, then `exec`s
the native binary. There is no intermediary forwarding process: arguments,
environment, working directory, stdin/stdout/stderr, **FD 3** (reports), other
inherited descriptors, exit codes, and signals keep their native semantics.

## Stage and test without publishing

Packing requires Node.js 22+ and npm. The packed install test also needs pnpm
(CI uses 12.17.0).

Keep the version in `Cargo.toml`'s `[workspace.package]`, all three
`node/*/package.json` files, and both wrapper optional-dependency pins identical.
The pack command fails on drift rather than silently publishing mixed versions.

```sh
cargo xtask npm-dist
# Or consume the existing dist/fstrace-VERSION-*-unknown-linux-musl.tar.gz files:
cargo xtask npm-dist --skip-build
```

This reuses `cargo xtask dist` and stages only package allowlisted files. It
checks each binary's ELF architecture and rejects a dynamic interpreter before
packing to `dist/npm/`. Source package directories are templates, not complete
publishable artifacts; always publish the generated tarballs.

On Linux, run:

```sh
node --test node/tests/launcher.test.cjs
node node/test-packed.mjs
```

The packed test serves the actual platform tarballs from a temporary loopback
registry. npm selects its native optional dependency, both commands run from
real npm local/global installs and pnpm shell shims. Deleting the platform package verifies the
missing-dependency diagnostic. No registry account or network publication is
needed. Launcher fixtures separately verify argument quoting, environment,
working directory, I/O, inherited FD 3 and FD 4, exit codes, and signal status.
CI performs these checks on Node.js 22 and 26 on native Linux x64 and ARM64
runners, with both glibc userspace and an Alpine/musl container.
Inside a disposable privileged Linux guest, set `FSTRACE_PACKED_TRACE_TEST=1`
to also exercise actual reports, arguments, FD 3/4, exit codes and signals
through npm and pnpm installs.

## Publishing prerequisites

No registry credentials or scope ownership are assumed. A maintainer must:

1. Own or have publish rights in the npm **`@fstrace`** scope and all three names.
2. Bootstrap the packages if they do not exist yet, using an authorized npm
   login and the generated tarballs. npm trusted publishing must be configured
   for each existing package; the workflow cannot provision that registry setup.
3. Configure each package's GitHub Actions trusted publisher for repository
   `bmiddha/fstrace`, workflow **`npm.yml`**, environment **`npm`**. Configure
   that GitHub environment with appropriate reviewers and allowed release tags.
4. Ensure the workflow's selected `vVERSION` tag points to the intended release
   commit. The npm versions and Rust version must match that tag; packaged
   README links use it to find the matching documentation.

The manually dispatched **npm distribution** workflow defaults to
**`publish: false`**: it only builds, packs, tests, and uploads artifacts.
It does not publish on pushes or pull requests. After setup and release review,
dispatch it on `vVERSION` with `publish: true` to publish public packages using
OIDC trusted publishing and provenance (no long-lived npm token). The publish job
uses Node 26 and npm 12 for trusted publishing; this is
release tooling, not a higher runtime minimum. Packing and install tests run
on the supported minimum, Node.js 22. Both architecture install
tests must pass before publishing, and the publish job rejects a nonmatching tag.

The platform packages publish **before** the wrapper so a new wrapper cannot
reference binaries that have not been uploaded. npm publishing is not atomic:
if only some publishes succeed, inspect registry versions before retrying;
already-published versions cannot be overwritten. No GitHub Release or GHCR
publishing is performed by this workflow.
