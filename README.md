<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->

[//]: # (**Table of Contents**  *generated with [DocToc]&#40;https://github.com/thlorenz/doctoc&#41;*)

- [DKLs23](#dkls23)
- [Functionality](#functionality)
- [Build](#build)
- [Tests](#tests)
- [Bench](#bench)
- [Articles and links](#articles-and-links)
- [Code Structure](#code-structure)
- [Summary of Changes After Security Audit](#summary-of-changes-after-security-audit)
  - [Setup Messages](#setup-messages)
  - [Message Serialization](#message-serialization)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## DKLs23
The repository implements threshold ECDSA signatures implementing DKLs23 protocol.

## Functionality

- Distributed Key Generation (DKG)
- Distributed Signature Generation (DSK)
- Proactive Security with Key rotation/refresh
- Import a singleton key and distributed among parties
- Export a threshold key to a singleton one

## Build
`cargo build
`
## Tests
`cargo test
`
## Bench

`cd crates/dkls-metrics/benches`

`cargo bench`


## Protocols 


<table>
  <tr>
    <td><b> Name </b></td>
    <td><b> Reference </b></td>
    <td><b> Code </b></td>
  </tr>
  <tr>
    <td>DKG</td>
    <td><a href="https://eprint.iacr.org/2022/374.pdf">paper</a></td>
    <td><a href="src/keygen/dkg.rs">code</a></td>
  </tr>
  <tr>
    <td>DSG</td>
    <td><a href="https://eprint.iacr.org/2023/765.pdf">paper</a></td>
    <td><a href="src/sign/dsg.rs">code</a></td>
  </tr>
  <tr>
    <td>Refresh</td>
    <td>reference</td>
    <td><a href="src/keygen/key_refresh.rs.rs">code</a></td>
  </tr>
  <tr>
    <td>Import</td>
    <td><a href="sss"></a>reference</td>
    <td><a href="/src/key_import.rs">code</a></td>
  </tr>
  <tr>
    <td>Export</td>
    <td><a href="sss">reference</a></td>
    <td><a href="/src/key_export.rs">code</a></td>
  </tr>

</table>

## Primitives


<table>
  <tr>
    <td><b> Name </b></td>
    <td><b> Reference </b></td>
    <td><b> Code </b></td>
  </tr>
  <tr>
    <td>1-2 OT</td>
    <td><a href=" https://eprint.iacr.org/2019/706.pdf">paper</a></td>
    <td><a href="src/keygen/dkg.rs">code</a></td>
  </tr>
  <tr>
    <td>Base OT</td>
    <td><a href="https://eprint.iacr.org/2015/546.pdf">paper</a></td>
    <td><a href="src/sign/dsg.rs">code</a></td>
  </tr>
  <tr>
    <td>Extended OT</td>
    <td><a href="https://eprint.iacr.org/2022/192.pdf">paper</a></td>
    <td><a href="src/keygen/key_refresh.rs.rs">code</a></td>
  </tr>

</table>


## Summary of Changes After Security Audit

### Setup Messages

The `run()` functions are now generic over the setup message type.
All setup message types must implement the trait
`ProtocolParticipant`, which contains associated types that define how
to sign and verify broadcast messages.

### Message Serialization

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
