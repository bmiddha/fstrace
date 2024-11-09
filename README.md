# fstrace

fstrace uses `ptrace` to check file system accesses of a program.

```bash
fstrace touch /tmp/foo 3>&1

RX /vscode/bin/linux-x64/384ff7382de624fb94dbaf6da11977bba1ecd427/bin/remote-cli/touch
RX /usr/local/share/nvm/versions/node/v18.20.4/bin/touch
RX /usr/local/sbin/touch
RX /usr/local/bin/touch
RX /usr/sbin/touch
RF /usr/bin/touch
RX /etc/ld.so.preload
RF /etc/ld.so.cache
RF /lib/x86_64-linux-gnu/libc.so.6
WF /tmp/foo
```

## Output format

File access reports are printed to file descriptor 3 in the following format:

```
<access_type><file_type> <file_path>
```

- `<access_type>`: `R` for read, `W` for write, `D` for delete, `C` for create, `E` for enumerate
- `<file_type>`: `F` for file, `D` for directory, `X` for does not exist

## Installing

```sh
npm i -g fstrace
```

## Building from source

Prerequisites

- [CMake](https://cmake.org/)
- [Node.js](https://nodejs.org/) - Need node.h to build node addon


```bash
cmake -S. -B ./build -DCMAKE_BUILD_TYPE=Release # or Debug
cmake --build ./build --target all
cmake --build ./build --target test
build/fstrace bash -c 'echo "foo" >> /tmp/foo' 3>&1
```
