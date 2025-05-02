// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use bytemuck::{AnyBitPattern, NoUninit};

use sl_oblivious::soft_spoken::{ReceiverOTSeed, SenderOTSeed};

use crate::proto::*;

#[derive(Clone, Copy, AnyBitPattern, NoUninit)]
#[repr(C)]
pub struct KeyshareInfo {
    /// A marker
    pub magic: [u8; 4],

    /// Size in bytes of extra data assosiated with Keyshare.
    pub(crate) extra: [u8; 4],

    /// Total number of parties
    pub total_parties: u8,

    /// Threshold value
    pub threshold: u8,

    /// Party Id of the sender
    pub party_id: u8,

    /// Final session ID
    pub final_session_id: [u8; 32],

    /// Root chain code (used to derive child public keys)
    pub root_chain_code: [u8; 32],

    /// Public key of the generated key.
    pub public_key: PointBytes,

    /// Key ID
    pub key_id: [u8; 32],

    /// S_i
    pub(crate) s_i: ScalarBytes,
}

const _: () = assert!(core::mem::align_of::<KeyshareInfo>() == 1);

#[derive(Clone, Copy, AnyBitPattern, NoUninit)]
#[repr(C)]
pub(crate) struct OtherParty {
    pub(crate) send_ot_seed: SenderOTSeed,
    pub(crate) recv_ot_seed: ReceiverOTSeed,
}

const _: () = assert!(core::mem::align_of::<OtherParty>() == 1);

#[derive(Clone, Copy, AnyBitPattern, NoUninit)]
#[repr(C)]
pub(crate) struct EachParty {
    pub(crate) rank: u8,            //
    pub(crate) big_s: PointBytes,   //
    pub(crate) x_i: ScalarBytes,    // NonZero
    pub(crate) zeta_seed: [u8; 32], //
}

const _: () = assert!(core::mem::align_of::<EachParty>() == 1);
