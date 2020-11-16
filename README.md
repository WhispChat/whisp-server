# whisp-server
This repository contains the code for the chat server for the Whisp chat
platform.

## Prerequisites
- CMake >=3.13
- Make
- C++17 compiler
- [Google Protocol Buffers](https://developers.google.com/protocol-buffers) >=3.13.0
- libsqlite3 >=3.26

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

**NOTE**
> The path to the SQLite3 file location is set to `../whisp.db` by default.
> This is so if you run `src/whisp-server` from the `build` directory, the database file will be saved in the root directory of the project.
> This path can be overwritten by the `-s` flag.

## Database Initialization
You can simply initialize the SQLite3 database from the command line:
```bash
sqlite3 whisp.db < sql/whisp.sql
```
Make sure when you run the server binary that the SQLite3 path is set correctly
(see note above).
