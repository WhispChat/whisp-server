# whisp-protobuf
This repository contains the `.proto` files used for structured communication
between the Whisp client(s) and server.

## Prerequisites
* CMake >=3.12
* Make
* C++17 compiler
* [Google Protocol Buffers](https://developers.google.com/protocol-buffers) >=3.13.0

## Building
This repository compiles the `.proto` files into source files that can then be
used by clients. To build these source files, you need to have Google's Protocol
Buffers installed (see
https://github.com/protocolbuffers/protobuf/blob/master/src/README.md for
installation instructions for Unix and Windows). This repository doesn't build
any binaries, just the source files to be included in other programs. These
files can be generated as following:

1. Clone repository:
```bash
git clone git@github.com:WhispChat/whisp-protobuf.git
```
2. Create build directory:
```bash
mkdir build
```
3. Enter build directory and generate code:
```
cd build/
cmake .. && make -j
```

This will generate the source files in their respective output directories. For
example, the C++ source files are built and copied to the `cpp/` folder. This is
so other repositories can use git submodules to stay in sync with protocol
changes.
