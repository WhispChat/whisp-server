# whisp-server
This repository contains the code for the chat server for the Whisp chat
platform.

## Prerequisites
- CMake >=3.12
- Make
- C++17 compiler
- [Google Protocol Buffers](https://developers.google.com/protocol-buffers) >=3.13.0
- libsqlite3-dev >=3.26
- OpenSSL (libssl-dev) >=1.1

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

**NOTE**
> The database contains a default channel (general) and an admin account that can be accessed by logging in with the following credentials:
> * Username: admin
> * Password: password123

## OpenSSL setup
To generate the public key, private key, and certificate required to run the
Whisp server using SSL, run the following commands in the `ssl/` folder:
```bash
openssl ecparam -genkey -name prime256v1 -noout -out private_key.pem
openssl ec -in private_key.pem -pubout -out public_key.pem
```
This will generate a keypair using the P-256 elliptic curve algorithm. To create
the required certificate, run the following command:
```bash
openssl req -new -x509 -sha256 -key private_key.pem -out cert.pem
```
