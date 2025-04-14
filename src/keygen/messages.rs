// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! This module defines the message types used in the DKG and quorum change protocols.
//! These messages are exchanged between participants during different rounds of the protocols.
//! All message types are designed to be efficiently serialized and deserialized using
//! the `bytemuck` crate.

use sl_oblivious::{endemic_ot::EndemicOTMsg2, soft_spoken::PPRFOutput};

use crate::proto::*;

/// Message type for the third round of the key generation protocol.
///
/// This message is sent peer-to-peer between participants and contains:
/// - The participant's share of the secret key
/// - The second message of the base oblivious transfer protocol
/// - The output of the pseudorandom function
/// - Session identification information
/// - Random values used for commitments
/// - Seeds for key derivation
#[derive(Clone, Copy, bytemuck::AnyBitPattern, bytemuck::NoUninit)]
#[repr(C)]
pub struct KeygenMsg3 {
    /// The participant's share of the secret key
    pub d_i: ScalarBytes,

    /// The second message of the base oblivious transfer protocol
    pub base_ot_msg2: EndemicOTMsg2,

    /// The output of the pseudorandom function
    pub pprf_output: PPRFOutput,

    /// The chain code session ID
    pub chain_code_sid: [u8; 32],

    /// A random 32-byte value used for commitments
    pub r_i_2: [u8; 32],

    /// Seeds used for key derivation between participants
    pub seed_i_j: [u8; 32],
}

const _: () = assert!(core::mem::align_of::<KeygenMsg3>() == 1);

/// Message type for the first peer-to-peer message in the quorum change protocol.
///
/// This message contains the second commitment value used to verify the participant's
/// contribution to the quorum change.
#[derive(Clone, Copy, bytemuck::AnyBitPattern, bytemuck::NoUninit)]
#[repr(C)]
pub struct QCP2PMsg1 {
    /// The second commitment value
    pub commitment_2_i: [u8; 32],
}

const _: () = assert!(core::mem::align_of::<QCP2PMsg1>() == 1);

/// Message type for the second peer-to-peer message in the quorum change protocol.
///
/// This message contains the participant's share of the secret key, a random value,
/// and the root chain code used for key derivation.
#[derive(Clone, Copy, bytemuck::AnyBitPattern, bytemuck::NoUninit)]
#[repr(C)]
pub struct QCP2PMsg2 {
    /// The participant's share of the secret key
    pub p_i: ScalarBytes,
    /// A random 32-byte value used for commitments
    pub r_2_i: [u8; 32],
    /// The root chain code used for key derivation
    pub root_chain_code: [u8; 32],
}

const _: () = assert!(core::mem::align_of::<QCP2PMsg2>() == 1);

/// Message type for the second oblivious transfer message in the quorum change protocol.
///
/// This message contains the second message of the base oblivious transfer protocol,
/// the output of the pseudorandom function, and seeds for key derivation.
#[derive(Clone, Copy, bytemuck::AnyBitPattern, bytemuck::NoUninit)]
#[repr(C)]
pub struct QCOTMsg2 {
    /// The second message of the base oblivious transfer protocol
    pub base_ot_msg2: EndemicOTMsg2,

    /// The output of the pseudorandom function
    pub pprf_output: PPRFOutput,

    /// Seeds used for key derivation between participants
    pub seed_i_j: [u8; 32],
}

const _: () = assert!(core::mem::align_of::<QCOTMsg2>() == 1);
