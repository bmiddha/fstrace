# Output format

File access reports are printed to file descriptor 3 in the following format:

```
<access_type><file_type> <file_path>
```

- `<access_type>`: `R` for read, `W` for write/create, `D` for delete. `E` is
  reserved for directory enumeration.
- `<file_type>`: `F` for file, `D` for directory, `X` for does not exist, `L`
  for symbolic link, `?` when the type is unknown.

fstrace intentionally does not attach probes for the metadata-only
`stat`/`access`/`readlink` families or for `getdents` directory enumeration.
Those calls dominate dependency-resolution workloads while duplicating paths
already reported by `open`/`openat`; omitting them matches the original
ptrace tracer's production seccomp filter.

See [Reports and file descriptor 3](reports-and-fd3.md) for how to redirect the
report stream (and how to handle `sudo`).
