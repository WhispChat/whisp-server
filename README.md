# whisp-server
This repository contains the code for the chat server for the Whisp chat
platform.

## Prerequisites
- CMake >=3.12
- Make
- C++17 compiler
- [Google Protocol Buffers](https://developers.google.com/protocol-buffers) >=3.13.0

## Installation
1. Clone repository:
```bash
git clone --recurse-submodules git@github.com:WhispChat/whisp-server.git
```
2. Create build directory:
```bash
mkdir build
```
3. Enter build directory and build code:
```bash
cd build/
cmake .. && make -j
```

This will create the binary `whisp-server` in the `build/src` directory.
