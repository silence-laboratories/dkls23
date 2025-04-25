// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! Message types for the Distributed Signature Generation (DSG) Protocol
//!
//! This module defines the message structures used in the DSG protocol for
//! communication between participants. These messages are designed to be
//! memory-safe and efficiently serializable.
//!
//! # Safety
//!
//! The message structures use `bytemuck` traits to ensure safe memory
//! operations and alignment requirements. All structures are marked with
//! `#[repr(C)]` to guarantee a stable memory layout.

use k256::{ProjectivePoint, Scalar};

use sl_oblivious::{rvole::RVOLEOutput, soft_spoken::Round1Output};

use bytemuck::{AnyBitPattern, NoUninit};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::proto::{PointBytes, ScalarBytes};

/// Message type for the first round of the signature generation protocol
///
/// This message contains the initial commitment and public key information
/// that each participant broadcasts to all other participants.
///
/// # Memory Layout
///
/// The structure is marked with `#[repr(C)]` to ensure a stable memory layout
/// and uses `AnyBitPattern` and `NoUninit` for safe memory operations.
#[derive(Clone, Copy, AnyBitPattern, NoUninit)]
#[repr(C)]
pub struct SignMsg1 {
    /// Session identifier for the protocol run
    pub session_id: [u8; 32],

    /// Hash of the commitment value
    pub commitment_r_i: [u8; 32],

    /// Participant's encryption public key
    pub enc_pk: [u8; 32],

    /// Party ID from the key share
    pub party_id: u8,
}

/// Message type for the second round of the signature generation protocol (P2P)
///
/// This message is sent peer-to-peer between participants and contains
/// the final session ID and encrypted data for the MtA protocol.
///
/// # Memory Layout
///
/// The structure is marked with `#[repr(C)]` to ensure a stable memory layout
/// and uses `AnyBitPattern` and `NoUninit` for safe memory operations.
#[derive(Clone, Copy, AnyBitPattern, NoUninit)]
#[repr(C)]
pub struct SignMsg2 {
    /// Final session identifier
    pub final_session_id: [u8; 32],

    /// Encrypted data for the MtA protocol
    pub mta_msg1: Round1Output,
}

/// Message type for the third round of the signature generation protocol (P2P)
///
/// This message is sent peer-to-peer between participants and contains
/// various encrypted data points and commitments needed for the signature.
///
/// # Memory Layout
///
/// The structure is marked with `#[repr(C)]` to ensure a stable memory layout
/// and uses `AnyBitPattern` and `NoUninit` for safe memory operations.
#[derive(Clone, Copy, AnyBitPattern, NoUninit)]
#[repr(C)]
pub struct SignMsg3 {
    /// Final session identifier
    pub final_session_id: [u8; 32],

    /// Encrypted data for the RVOLE protocol
    pub mta_msg2: RVOLEOutput,

    /// Encrypted digest value
    pub digest_i: [u8; 32],

    /// Encrypted public key component
    pub pk_i: PointBytes,

    /// Encrypted R point component
    pub big_r_i: PointBytes,

    /// Encrypted blind factor
    pub blind_factor: [u8; 32],

    /// Encrypted gamma_v point
    pub gamma_v: PointBytes,

    /// Encrypted gamma_u point
    pub gamma_u: PointBytes,

    /// Encrypted psi scalar value
    pub psi: ScalarBytes,
}

/// Message type for the fourth round of the signature generation protocol
///
/// This message contains the final signature components that each participant
/// broadcasts to all other participants.
///
/// # Memory Layout
///
/// The structure is marked with `#[repr(C)]` to ensure a stable memory layout
/// and uses `AnyBitPattern` and `NoUninit` for safe memory operations.
#[derive(Clone, Copy, AnyBitPattern, NoUninit)]
#[repr(C)]
pub struct SignMsg4 {
    /// Session identifier
    pub session_id: [u8; 32],

    /// s_0 Scalar
    pub s_0: ScalarBytes,

    /// s_1 Scalar
    pub s_1: ScalarBytes,
}

/// Result of the pre-signature phase for a party
///
/// This structure contains all the necessary information from the pre-signature
/// phase that will be needed to complete the signature in the finish phase.
///
/// # Memory Layout
///
/// The structure is marked with `#[repr(C)]` to ensure a stable memory layout
/// and uses `AnyBitPattern` and `NoUninit` for safe memory operations.
/// It also implements `Zeroize` to ensure sensitive data is securely erased.
#[derive(Clone, Copy, AnyBitPattern, NoUninit, Zeroize)]
#[repr(C)]
pub struct PreSign {
    /// Final session identifier
    pub final_session_id: [u8; 32],

    /// First signature component (s_0)
    pub(crate) s_0: ScalarBytes,

    /// Second signature component (s_1)
    pub(crate) s_1: ScalarBytes,

    /// Phi_i scalar value
    pub(crate) phi_i: ScalarBytes,

    /// R point value
    pub(crate) r: PointBytes,

    /// Public key value
    pub(crate) public_key: PointBytes,

    /// Party ID
    pub(crate) party_id: u8,
}

/// Partial signature from a single party
///
/// This structure contains a party's contribution to the final signature.
/// It implements `Zeroize` and `ZeroizeOnDrop` to ensure sensitive data
/// is securely erased when the structure is dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct PartialSignature {
    /// Final session identifier
    pub final_session_id: [u8; 32],

    /// Public key value
    pub public_key: ProjectivePoint,

    /// Hash of the message being signed
    pub message_hash: [u8; 32],

    /// s_0 Scalar
    pub s_0: Scalar,

    /// s_1 Scalar
    pub s_1: Scalar,

    /// R point value
    pub r: ProjectivePoint,
}
