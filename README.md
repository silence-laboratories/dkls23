# Implementation of DKLs23 and related code

The cates in this repository uses create sl-mpc-mate and sl-oblivious
from https://gitlab.com/com.silencelaboratories/sl-crypto

# Crates

## dkls23-rs

This is the core crate. The main functions are:

```rust
dkls23::keygen::dkg::run()

dkls23::sign::dsg::run()
```

## crates/msg-relay-svc

Driver of simple implmentation of a message relay service.

A few examples how to run it:

```shell
cargo run -p msg-relay-svc

# or, with some trace output
RUST_LOG=info cargo run -p msg-relay-svc

# and listen on more then one addr:port
RUST_LOG=info LISTEN="0.0.0.0:8080 127.0.0.1:8081" cargo run -p msg-relay-svc
```

It understand IPv6 addresses too.

## crates/msg-relay

A reusable reference implementation of a message relay.
`msg-relay-svc` is built using this one.

## crates/msg-releay-client

This is client library to access message relay service.

An implementation of sl_mpc_mate::message::Relay trait.

## crates/dkls-party

This commad line utility to execute all steps of distributed
key generation (DKG) and distributed signature generation (DSG).

The simplest way to build and run it would be:

```shell
cargo run -p dkls-party -q --release -- --help
```

## crates/dkls-party/scripts/dkg.sh

This is a hleper script to generate all required keys, create
and initial message (setup message) and execute distributed
key generation and save result keyshares to files.

```shell
# create a directory for keyshares and various addtional files
mkdir ./data

# we assume that msg-relay-svc is running on this machine and
# it listens on 127.0.0.1:8080 (this is default)

# the following command will execute distributed key generation
#
# N=5 - number of participants
# T=3 - theshold
#
# show trace output as much as possible and place all data files
# into directory `./data`
#
RUST_LOG=debug DEST=./data ./crates/dkls-party/scripts/dkg.sh 5 3

# a last line of output pf dsg.sh will be public key of new key

# make sure there are keyshares

ls -l ./data/keyshare.*

```

## crates/dkls-party/dsg.sh

We generated key, now we are ready to genreate a signature

```shell
# we will use ./data directory populated by dkg.sh script

# This command will generate a signature for message "test"
# using first 3 keyshares
#
RUST_LOG=debug DEST=./data ./crates/dkls-party/scripts/dsg.sh "test" 0 1 2
```

Please, read comments in these scripts to get more details.
