// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! DKLs23 rust implementation
#![deny(missing_docs, unsafe_code)]

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// DKLs23 keygen protocol
pub mod keygen;

/// DKLs23 signing protocol
pub mod sign;

/// Setup message creation/parsing
pub mod setup;

/// Misc protocol helper functions.
pub mod proto;

/// Seed for our RNG
pub type Seed = <ChaCha20Rng as SeedableRng>::Seed;

/// Key Export related functions and structs
pub mod key_export;
/// Key Import related functions and structs
pub mod key_import;

pub(crate) mod pairs;

/// Version of domain labels
pub const VERSION: u16 = 1;

pub use k256;
pub use sl_mpc_mate::coord::{MessageSendError, Relay};
pub use sl_mpc_mate::message::{InstanceId, MsgId};
