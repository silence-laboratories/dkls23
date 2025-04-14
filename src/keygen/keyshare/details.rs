// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! Internal details of the key share implementation
//!
//! This module contains the core data structures that make up a key share in the
//! distributed key generation protocol. These structures are designed to be
//! memory-safe and efficiently serializable.
//!
//! # Safety
//!
//! The structures in this module use `bytemuck` traits to ensure safe memory
//! operations and alignment requirements. All structures are marked with
//! `#[repr(C)]` to guarantee a stable memory layout.

use bytemuck::{AnyBitPattern, NoUninit};

use sl_oblivious::soft_spoken::{ReceiverOTSeed, SenderOTSeed};

use crate::proto::*;

/// Core information about a key share
///
/// This structure contains all the essential information about a key share,
/// including protocol parameters, cryptographic material, and metadata.
///
/// # Memory Layout
///
/// The structure is marked with `#[repr(C)]` to ensure a stable memory layout
/// and uses `AnyBitPattern` and `NoUninit` for safe memory operations.
///
/// # Fields
///
/// * `magic` - A marker to identify valid key shares
/// * `extra` - Size of additional data associated with the key share
/// * `total_parties` - Total number of participants in the protocol
/// * `threshold` - The threshold value for key reconstruction
/// * `party_id` - The ID of the party holding this share
/// * `final_session_id` - The final session identifier
/// * `root_chain_code` - The root chain code for key derivation
/// * `public_key` - The public key of the generated key
/// * `key_id` - A unique identifier for the key
/// * `s_i` - The secret share value
#[derive(Clone, Copy, AnyBitPattern, NoUninit)]
#[repr(C)]
pub struct KeyshareInfo {
    /// A marker to identify valid key shares
    pub magic: [u8; 4],

    /// Size in bytes of extra data associated with Keyshare
    pub(crate) extra: [u8; 4],

    /// Total number of parties in the protocol
    pub total_parties: u8,

    /// Threshold value for key reconstruction
    pub threshold: u8,

    /// Party ID of the sender
    pub party_id: u8,

    /// Final session ID from the protocol
    pub final_session_id: [u8; 32],

    /// Root chain code (used to derive child public keys)
    pub root_chain_code: [u8; 32],

    /// Public key of the generated key
    pub public_key: PointBytes,

    /// Key ID for identification
    pub key_id: [u8; 32],

    /// Secret share value
    pub(crate) s_i: ScalarBytes,
}

// Ensure proper memory alignment
const _: () = assert!(core::mem::align_of::<KeyshareInfo>() == 1);

/// Information about another party in the protocol
///
/// This structure contains the oblivious transfer seeds used for communication
/// with another party in the protocol.
///
/// # Memory Layout
///
/// The structure is marked with `#[repr(C)]` to ensure a stable memory layout
/// and uses `AnyBitPattern` and `NoUninit` for safe memory operations.
///
/// # Fields
///
/// * `send_ot_seed` - Seed for sending oblivious transfer messages
/// * `recv_ot_seed` - Seed for receiving oblivious transfer messages
#[derive(Clone, Copy, AnyBitPattern, NoUninit)]
#[repr(C)]
pub(crate) struct OtherParty {
    /// Seed for sending oblivious transfer messages
    pub(crate) send_ot_seed: SenderOTSeed,

    /// Seed for receiving oblivious transfer messages
    pub(crate) recv_ot_seed: ReceiverOTSeed,
}

// Ensure proper memory alignment
const _: () = assert!(core::mem::align_of::<OtherParty>() == 1);

/// Information about each party in the protocol
///
/// This structure contains the necessary information about each party's
/// contribution to the key share.
///
/// # Memory Layout
///
/// The structure is marked with `#[repr(C)]` to ensure a stable memory layout
/// and uses `AnyBitPattern` and `NoUninit` for safe memory operations.
///
/// # Fields
///
/// * `rank` - The rank of the party
/// * `big_s` - The party's contribution to the public key
/// * `x_i` - The x-coordinate for the party's share (must be non-zero)
/// * `zeta_seed` - A random seed for additional security
#[derive(Clone, Copy, AnyBitPattern, NoUninit)]
#[repr(C)]
pub(crate) struct EachParty {
    /// The rank of the party
    pub(crate) rank: u8,

    /// The party's contribution to the public key
    pub(crate) big_s: PointBytes,

    /// The x-coordinate for the party's share (must be non-zero)
    pub(crate) x_i: ScalarBytes,

    /// A random seed for additional security
    pub(crate) zeta_seed: [u8; 32],
}

// Ensure proper memory alignment
const _: () = assert!(core::mem::align_of::<EachParty>() == 1);
