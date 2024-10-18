# fstrace

## Building

```bash
cmake -S. -B ./build -DCMAKE_BUILD_TYPE=Release # or Debug
cmake --build ./build --target all
build/fstrace bash -c 'echo "foo" >> /tmp/foo' 3>&1
```

### Prerequisites

- [CMake](https://cmake.org/)
- [Node.js](https://nodejs.org/) - Need node.h to build node addon
