# Output format

File access reports are printed to file descriptor 3 in the following format:

```
<access_type><file_type> <file_path>
```

- `<access_type>`: `R` for read, `W` for write/create, `D` for delete, `E` for enumerate
- `<file_type>`: `F` for file, `D` for directory, `X` for does not exist

See [Reports and file descriptor 3](reports-and-fd3.md) for how to redirect the
report stream (and how to handle `sudo`).
