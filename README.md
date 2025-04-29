<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
# Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Structure](#structure)
- [Installing, Testing, Benchmarks](#installing-testing-benchmarks)
  - [Building](#building)
  - [Running Tests](#running-tests)
  - [Documentation](#documentation)
  - [Benchmarks](#benchmarks)
    - [Criterion](#criterion)
    - [Detailed Metrics (total message sizes sent and received)](#detailed-metrics-total-message-sizes-sent-and-received)
  - [Examples](#examples)
- [Crates structure](#crates-structure)
  - [Protocols](#protocols)
  - [Primitives](#primitives)
  - [E2E Security](#e2e-security)
- [Security](#security)
- [Security Audit](#security-audit)
  - [Summary of Changes After the Security Audit](#summary-of-changes-after-the-security-audit)
  - [Message Serialization](#message-serialization)
- [Contributing](#contributing)
- [Reach out to us](#reach-out-to-us)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Introduction
DKLs23 is a high-performance threshold ECDSA signing protocol with dynamic quorum management. 

This is a production-ready, audited implementation that powers the [Silent Shard SDK](https://silencelaboratories.com/silent-shard) and has undergone a comprehensive [security audit](./docs/ToB-SilenceLaboratories_2024.04.10.pdf) by Trail of Bits.

## Features

- Distributed Key Generation (DKG)
- Distributed Signature Generation (DSG)
- Key refresh
- Import a singleton key and distribute it among parties
- Export a threshold key to a singleton one
- Quorum Change: change dynamically the set of participants adding or removing
- Migration: Migrate from compatible curve protocols like: GG** or CMP to DKLs23

## Structure
The repository is structured as follows:

```
crates/                   
├── msg-relay/           # Message relay crate
└── dkls-metrics/        # Metrics crate
docs/                    # Audit reports and whitepapers
examples/                # Examples (keygen, sign, refresh)
scripts/                 # Utility scripts
src/                     
├── keygen/              # Key generation module
├── proto/               # Protocol definitions
├── setup/               # Setup module
├── sign/                # Signing module
├── key_export.rs        # Key export functionality
├── key_import.rs        # Key import functionality
├── lib.rs               # Library entry point
├── pairs.rs             # Key pairs functionality
├── proto.rs             # Protocol implementation
└── setup.rs             # Setup implementation
```

## Installing, Testing, Benchmarks
### Building
`cargo build
`
### Running Tests
`cargo test
`

 ### Documentation
 Rustdoc reference is published here:

https://dkls23.silencelaboratories.com/docs/

### Benchmarks
Up-to-date benchmarks can be found here:

https://dkls23.silencelaboratories.com/

#### Criterion
`cd crates/dkls-metrics/benches`

`cargo bench`
#### Detailed Metrics (total message sizes sent and received)
`cargo run -p dkls-metrics -r -- dkg --n 3 --t 2 --dsg
`
### Examples
Under <a href="./examples/">`/examples/`</a> directory there are examples on how to perform keygen, sign and refresh.

Running the examples:

- `cargo run --example keygen`
- `cargo run --example sign`
- `cargo run --example refresh`



##  Crates structure

### Protocols 

<table>
  <tr>
    <td><b> Name </b></td>
    <td><b> Reference </b></td>
    <td><b> Code </b></td>
    <td><b> Audited </b></td>

  </tr>
  <tr>
    <td>DKG</td>
    <td><a href="https://eprint.iacr.org/2022/374.pdf">paper</a></td>
    <td><a href="./src/keygen/dkg.rs">code</a></td>
    <td>Yes</td>

  </tr>
  <tr>
    <td>DSG</td>
    <td><a href="https://eprint.iacr.org/2023/765.pdf">paper</a></td>
    <td><a href="./src/sign/dsg.rs">code</a></td>
    <td>Yes</td>

  </tr>
  <tr>
    <td>Refresh</td>
    <td>reference</td>
    <td><a href="./src/keygen/key_refresh.rs">code</a></td>
    <td>Yes</td>

  </tr>
  <tr>
    <td>Import</td>
    <td>reference</td>
    <td><a href="./src/key_import.rs">code</a></td>
    <td>No</td>

  </tr>
  <tr>
    <td>Export</td>
    <td>reference</td>
    <td><a href="./src/key_export.rs">code</a></td>
    <td>No</td>

  </tr>
<tr>
    <td>Quorum Change</td>
    <td><a href="https://github.com/silence-laboratories/dkls23/blob/core-after-audit/docs/dwtss.pdf">reference</a></td>
    <td><a href="./src/keygen/quorum_change.rs">code</a></td>
    <td>No</td>

  </tr>
<tr>
    <td>Migration</td>
    <td>reference</td>
    <td><a href="./src/keygen/migration.rs">code</a></td>
    <td>No</td>

  </tr>

</table>


### Primitives

<table>
  <tr>
    <td><b> Name </b></td>
    <td><b> Reference </b></td>
    <td><b> Code </b></td>
    <td><b> Audited </b></td>

  </tr>
  <tr>
    <td>1-2 OT</td>
    <td><a href="https://eprint.iacr.org/2019/706.pdf">paper</a></td>
    <td><a href="https://github.com/silence-laboratories/sl-crypto/blob/main/crates/sl-oblivious/src/endemic_ot.rs">code</a></td>
    <td>Yes</td>

  </tr>
  <tr>
    <td>Base OT</td>
    <td><a href="https://eprint.iacr.org/2015/546.pdf">paper</a></td>
    <td><a href="https://github.com/silence-laboratories/sl-crypto/blob/main/crates/sl-oblivious/src/soft_spoken/soft_spoken_ot.rs">code</a></td>
    <td>Yes</td>
  
</tr>
  <tr>
    <td>Extended OT</td>
    <td><a href="https://eprint.iacr.org/2022/192.pdf">paper</a></td>
    <td><a href="https://github.com/silence-laboratories/sl-crypto/tree/main/crates/sl-oblivious/src/soft_spoken">code</a></td>
    <td>Yes</td> 

</tr>
  <tr>
    <td>Polynomial Arithmetics</td>
    <td>reference</td>
    <td><a href="https://github.com/silence-laboratories/sl-crypto/blob/main/crates/sl-mpc-mate/src/math.rs">code</a></td>
    <td>Yes</td>
</tr>
 <tr>
    <td>Matrix Arithmetics</td>
    <td>reference</td>
    <td><a href="https://github.com/silence-laboratories/sl-crypto/blob/main/crates/sl-mpc-mate/src/matrix.rs
">code</a></td>
    <td>Yes</td>
</tr>
</table>

### E2E Security

<table>
  <tr>
    <td><b> Name </b></td>
    <td><b> Code </b></td>
    <td><b> Audited </b></td>

  </tr>
  <tr>
    <td>Key Agreement: x25519+Curve25519</td>
    <td><a href="https://github.com/silence-laboratories/dkls23/blob/core-after-audit/src/proto/scheme.rs">code</a></td>
    <td>Yes</td>

  </tr>
  <tr>
    <td>Authenticated Encryption: ChaCha20Poly1305</td>
    <td><a href="https://github.com/silence-laboratories/dkls23/blob/core-after-audit/src/proto/encrypted.rs">code</a></td>
    <td>Yes</td>

</tr>
  <tr>
    <td>Sender authenticity: EdDSA+Curve25519</td>
    <td><a href="https://github.com/silence-laboratories/dkls23/blob/core-after-audit/src/proto/signed.rs">code</a></td>
    <td>Yes</td> 

</tr>

</table>

## Security

If you discover a vulnerability, please follow the instructions in [SECURITY](SECURITY.md).

## Security Audit

Trail of Bits has performed a security audit in February, 2024 on the following commits:
- `1510c2fafe3c` from the [dkls23](https://github.com/silence-laboratories/dkls23/commit/1510c2fafe3cd6866581ce3e2c43c565561b929b) repository.
- `a6b014722a29` from the [sl-crypto](https://github.com/silence-laboratories/sl-crypto/commit/a6b014722a29027d813bcb58720412da68f63d07) repository.

The report is available here:
- [Security Assessment Report: Silent Shard - Trail of Bits, Feb 2024](./docs/ToB-SilenceLaboratories_2024.04.10.pdf).

### Summary of Changes After the Security Audit

#### Setup Messages

The `run()` functions are now generic over the setup message type.
All setup message types must implement the trait
`ProtocolParticipant`, which contains associated types that define how
to sign and verify broadcast messages.

#### Message Serialization

We implemented what we call zero-copy message serialization. We
redefined all messages sent between parties and their components to be
arrays of bytes. This transformation allows us to safely cast a byte
slice `&[u8]` into a reference to some message structure if the sizes
are equal.

This allows us to implement in-place message construction. We allocate
a memory buffer of an appropriate size, take a mutable reference to
some message structure, and pass it to a message constructor. Then we
calculate the message signature or encrypt the message in place
without any extra memory copying.

This provides not only memory efficiency but also more secure code
because we have exactly one copy of secret material in memory and
overwrite it with in-place encryption.

Key share representation also uses the same technique. We allocate a
memory buffer for the key share at the beginning of the key generation
execution and fill it piece by piece. This allows us to avoid extra
memory copies.

Key share for a 3-party case is about 130kb; messages are: 16kb, 37kb,
and 49kb.

## Contributing

Please refer to [CONTRIBUTING](CONTRIBUTING.md).

## Reach out to us
Don`t hesitate to contact us if you need any assistance.

info@silencelaboratories.com  
security@silencelaboratories.com

**Happy signing!**
