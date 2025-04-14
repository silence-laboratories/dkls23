// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use k256::{ProjectivePoint, Scalar};

use sl_oblivious::{rvole::RVOLEOutput, soft_spoken::Round1Output};

use bytemuck::{AnyBitPattern, NoUninit};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::proto::{PointBytes, ScalarBytes};

/// Type for the sign gen message 1.
#[derive(Clone, Copy, AnyBitPattern, NoUninit)]
#[repr(C)]
pub struct SignMsg1 {
    /// Session id
    pub session_id: [u8; 32],

    /// Commitment hash
    pub commitment_r_i: [u8; 32],

    /// Participant encryption public key
    pub enc_pk: [u8; 32],

    /// Party Id (form Keyshare)
    pub party_id: u8,
}

/// Type for the sign gen message 2. P2P
#[derive(Clone, Copy, AnyBitPattern, NoUninit)]
#[repr(C)]
pub struct SignMsg2 {
    /// final_session_id
    pub final_session_id: [u8; 32],

    /// encrypted data
    pub mta_msg1: Round1Output,
}

/// Type for the sign gen message 3. P2P
#[derive(Clone, Copy, AnyBitPattern, NoUninit)]
#[repr(C)]
pub struct SignMsg3 {
    /// final_session_id
    pub final_session_id: [u8; 32],

    /// encrypted data
    pub mta_msg2: RVOLEOutput,

    /// Encrypted data
    pub digest_i: [u8; 32],

    /// Encrypted data
    pub pk_i: PointBytes,

    /// Encrypted data
    pub big_r_i: PointBytes,

    /// encrypted data
    pub blind_factor: [u8; 32],

    /// Encrypted data
    pub gamma_v: PointBytes,

    /// Encrypted data
    pub gamma_u: PointBytes,

    /// Encrypted psi scalar
    pub psi: ScalarBytes,
}

/// Type for the sign gen message 4.
#[derive(Clone, Copy, AnyBitPattern, NoUninit)]
#[repr(C)]
pub struct SignMsg4 {
    /// Session id
    pub session_id: [u8; 32],

    /// s_0 Scalar
    pub s_0: ScalarBytes,

    /// s_1 Scalar
    pub s_1: ScalarBytes,
}

/// Result after pre-signature of party_i
#[derive(Clone, Copy, AnyBitPattern, NoUninit, Zeroize)]
#[repr(C)]
pub struct PreSign {
    /// final_session_id
    pub final_session_id: [u8; 32],

    /// s_0 Scalar
    pub(crate) s_0: ScalarBytes,

    /// s_1 Scalar
    pub(crate) s_1: ScalarBytes,

    /// phi_i Scalar
    pub(crate) phi_i: ScalarBytes,

    /// R point
    pub(crate) r: PointBytes,

    /// public_key
    pub(crate) public_key: PointBytes,

    pub(crate) party_id: u8,
}

/// Partial signature of party_i
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct PartialSignature {
    /// final_session_id
    pub final_session_id: [u8; 32],

    /// public_key
    pub public_key: ProjectivePoint,

    /// 32 bytes message_hash
    pub message_hash: [u8; 32],

    /// s_0 Scalar
    pub s_0: Scalar,

    /// s_1 Scalar
    pub s_1: Scalar,

    /// R point
    pub r: ProjectivePoint,
}
