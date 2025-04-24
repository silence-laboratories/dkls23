// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! A rust  threshold ECDSA signatures library implementing DKLs23 protocol.
//!
//! ## Functionality
//! - Distributed Key Generation (DKG)
//! - Distributed Signature Generation (DSG)
//! - Key refresh protocol that refreshes the secret key shares without changing the common public key.
//! - Import a singleton key and distribute it among parties
//! - Export a threshold key to a singleton one
//! - Quorum Change: change dynamically the set of participants by adding or removing nodes
//! - Migration: Migrate from compatible curve protocols like: GG** or CMP to DKLs23
//!
//! ## Examples
//! The mod common module can be replicated  from the dkls23 github [repo](https://github.com/silence-laboratories/dkls23/examples/common.rs) under examples folder
//! ### KeyGen
//! ```
//! use dkls23::keygen;
//! use k256::elliptic_curve::group::GroupEncoding;
//! use rand::Rng;
//! use rand_chacha::ChaCha20Rng;
//! use rand_core::SeedableRng;
//! use std::sync::Arc;
//!
//! mod common;
//!
//! #[tokio::main]
//! pub async fn main() {
//!     let t: u8 = 2;
//!     let n: u8 = 3;
//!     let coord = sl_mpc_mate::coord::SimpleMessageRelay::new();
//!
//!     let mut parties = tokio::task::JoinSet::new();
//!
//!     for setup in common::shared::setup_keygen(t, n, None) {
//!         parties.spawn({
//!             let relay = coord.connect();
//!             let mut rng = ChaCha20Rng::from_entropy();
//!             keygen::run(setup, rng.gen(), relay)
//!         });
//!     }
//!     let mut shares = vec![];
//!     while let Some(fini) = parties.join_next().await {
//!         if let Err(ref err) = fini {
//!             println!("error {err:?}");
//!         } else {
//!             match fini.unwrap() {
//!                 Err(err) => panic!("err {:?}", err),
//!                 Ok(share) => shares.push(Arc::new(share)),
//!            }
//!         }
//!     }
//!
//!     for keyshare in shares.iter() {
//!         println!("PK{}", hex::encode(keyshare.public_key().to_bytes()));
//!     }
//! }
//! ```
//! ### Key Refresh
//! ```
//! use dkls23::keygen::key_refresh::KeyshareForRefresh;
//! use k256::elliptic_curve::group::GroupEncoding;
//! use rand::Rng;
//! use rand_chacha::ChaCha20Rng;
//! use rand_core::SeedableRng;
//! use sl_mpc_mate::coord::SimpleMessageRelay;
//! use std::sync::Arc;
//! use tokio::task::JoinSet;
//!
//! mod common;
//!
//! #[tokio::main]
//! pub async fn main() {
//!     let old_shares = common::shared::gen_keyshares(2, 3).await;
//!     let coord = SimpleMessageRelay::new();
//!     let mut parties = JoinSet::new();
//!
//!     let key_shares_for_refresh: Vec<KeyshareForRefresh> = old_shares
//!         .iter()
//!         .map(|share| KeyshareForRefresh::from_keyshare(share, None))
//!         .collect();
//!
//!     let mut rng = ChaCha20Rng::from_entropy();
//!     for (setup, share) in common::shared::setup_keygen(2, 3, None)
//!         .into_iter()
//!         .zip(key_shares_for_refresh)
//!         .collect::<Vec<_>>()
//!     {
//!         // run the keyrefresh protocol for each node
//!         parties.spawn(dkls23::keygen::key_refresh::run(
//!             setup,
//!             rng.gen(),
//!             coord.connect(),
//!             share,
//!         ));
//!     }
//!
//!     let mut new_shares = vec![];
//!     while let Some(fini) = parties.join_next().await {
//!         let fini = fini.unwrap();
//!
//!         if let Err(ref err) = fini {
//!             println!("error {}", err);
//!         }
//!
//!        assert!(fini.is_ok());
//!
//!         // Print all the new PK of the refreshed share
//!         let new_share = fini.unwrap();
//!         let pk = hex::encode(new_share.public_key().to_bytes());
//!
//!         new_shares.push(Arc::new(new_share));
//!
//!         println!("PK {}", pk);
//!     }
//!
//!     //check that this is equal the old key share public key
//!     println!(
//!         "Old PK{}",
//!         hex::encode(old_shares[0].public_key().to_bytes())
//!     );
//!
//! }
//! ```
//!
//! ### Sign
//! ```
//! use tokio::task::JoinSet;
//!
//! use rand::Rng;
//! use rand_chacha::ChaCha20Rng;
//! use rand_core::SeedableRng;
//!
//! use k256::ecdsa::{RecoveryId, VerifyingKey};
//!
//! use dkls23::sign;
//! use sl_mpc_mate::coord::SimpleMessageRelay;
//!
//! mod common;
//!
//! #[tokio::main]
//! async fn main() {
//!     let coord = SimpleMessageRelay::new();
//!
//!     // We locally generate some key shares in order to test the signing procedure.
//!     let shares = common::shared::gen_keyshares(2, 3).await;
//!
//!     //fetch the public verification key from one of the keyshares
//!     let vk = VerifyingKey::from_affine(shares[0].public_key().to_affine()).unwrap();
//!
//!     //define a chain path for the signature: m is the default one
//!     let chain_path = "m";
//!
//!     //Here the parties are simulated as in a real world example but locally as a set of rust async tasks:
//!     let mut parties = JoinSet::new();
//!
//!     for setup in common::shared::setup_dsg(&shares[0..2], chain_path) {
//!         let mut rng = ChaCha20Rng::from_entropy();
//!         let relay = coord.connect();
//!
//!         parties.spawn(sign::run(setup, rng.gen(), relay));
//!     }
//!
//!     // After all the tasks have finished we extract the signature and verify it against the public key
//!     while let Some(fini) = parties.join_next().await {
//!         let fini = fini.unwrap();
//!
//!         if let Err(ref err) = fini {
//!             println!("error {err:?}");
//!         }
//!
//!         let (sign, recid) = fini.unwrap();
//!
//!         let hash = [1u8; 32];
//!
//!         let recid2 = RecoveryId::trial_recovery_from_prehash(&vk, &hash, &sign).unwrap();
//!
//!         assert_eq!(recid, recid2);
//!     }
//! }
//!```
//!
//! ## Networking
//! Communication between nodes  is happening through a relayer in a pull messaging mode:
//! Everything is posted on the relayer and the receiver knows when and what to ask. That was a design
//! decision that maps best the nature of MPC protocols whereby any mpc node depending on the protocol knows what type of messages to expect and from
//! where.
//!
//! The relayer follows the Actor model: It spawns from the caller task, does the assigned task
//! independently and return the result in the main task. The library itself does not expose networking stack
//! ,but instead a generic combination of shared state between rust tasks and message channel passing where
//! receiver and sender channels are interleaved for p2p and broadcast communication. That is a local `SimpleMessageRelay`.
//! In a real setup the relayer can be an independent network entity, where all the nodes can talk to. It
//! can be implemented with a variety of existing  networking protocols such as websockets; as long as it follows the
//! underlying pull logic : Each receiver knows what message to subscribe for and so it asks the relayer to deliver it
//! as long as it arrives from the expected sender.
//!
//!
//!
//! ## Data Serialization
//! The library implements zero-copy message serialization. All messages sent between parties
//! and their components are defined as arrays of bytes. This transformation enables us to safely cast a byte
//! slice `&[u8]` into a reference to some message structure if the sizes
//! are equal.
//!
//! This allows to implement in-place message construction:  Allocate
//! a memory buffer of an appropriate size, take a mutable reference to
//! some message structure, and pass it to a message constructor. Then
//! calculate the message signature or encrypt the message in place
//! without any extra memory copying.
//! This provides not only memory efficiency but also more secure code
//! because there is exactly one copy of secret material in memory and
//! overwrite it with in-place encryption.
//! Key share representation also uses the same technique. Allocates a
//! memory buffer for the key share at the beginning of the key generation
//! execution and fill it piece by piece. Thus, memory copies are not happening
#![deny(missing_docs, unsafe_code)]

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// DKLs23 keygen.
pub mod keygen;

/// DKLs23 sign.
pub mod sign;

/// Setup messages.
pub mod setup;

/// Misc helper functions.
pub mod proto;

/// Seed for our RNG.
pub type Seed = <ChaCha20Rng as SeedableRng>::Seed;

/// Exports a threshold key to a singleton one by consolidating all shares of other nodes.
pub mod key_export;
/// Imports a singleton external key and secret shares it among parties to use dkls23 related mpc protocols.
pub mod key_import;

pub(crate) mod pairs;

/// Version of domain labels
pub const VERSION: u16 = 1;

pub use k256;
pub use sl_mpc_mate::coord::{MessageSendError, Relay};
pub use sl_mpc_mate::message::{InstanceId, MsgId};
