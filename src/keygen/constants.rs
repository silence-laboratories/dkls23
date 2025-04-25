// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! Protocol Constants and Message Tags
//!
//! This module defines all the constants used throughout the DKG protocol,
//! including message tags, labels for cryptographic operations, and protocol-specific
//! identifiers. These constants ensure consistent message handling and cryptographic
//! operations across all protocol participants.

use crate::VERSION;
use sl_mpc_mate::message::MessageTag;
use sl_oblivious::label::Label;

/// Label used for the key generation protocol.
/// This label is used to derive protocol-specific keys and nonces.
pub const DKG_LABEL: Label = Label::new(VERSION, 100);

/// Label used for the first commitment in the protocol.
/// This commitment is used to ensure participants are bound to their initial values.
pub const COMMITMENT_1_LABEL: Label = Label::new(VERSION, 101);

/// Label used for the second commitment in the protocol.
/// This commitment is used to ensure participants are bound to their final values.
pub const COMMITMENT_2_LABEL: Label = Label::new(VERSION, 102);

/// Label used for the first discrete logarithm proof.
/// This proof ensures the validity of certain cryptographic operations.
pub const DLOG_PROOF1_LABEL: Label = Label::new(VERSION, 103);

/// Label used for the second discrete logarithm proof.
/// This proof ensures the validity of certain cryptographic operations.
pub const DLOG_PROOF2_LABEL: Label = Label::new(VERSION, 104);

/// Label used to create a discrete logarithm session ID from the final session ID and root chain code.
/// This is used to ensure proper session management and key derivation.
pub const DLOG_SESSION_ID_WITH_CHAIN_CODE: Label = Label::new(VERSION, 105);

/// Label used for the quorum change protocol.
/// This label is used to derive protocol-specific keys and nonces for quorum changes.
pub const QC_LABEL: Label = Label::new(VERSION, 106);

/// Label used for the first commitment in the quorum change protocol.
/// This commitment is used to ensure participants are bound to their initial values.
pub const QC_COMMITMENT_1_LABEL: Label = Label::new(VERSION, 107);

/// Label used for the second commitment in the quorum change protocol.
/// This commitment is used to ensure participants are bound to their final values.
pub const QC_COMMITMENT_2_LABEL: Label = Label::new(VERSION, 108);

/// Message tag for the first round of the DKG protocol.
/// This message contains initial commitments and setup information.
pub const DKG_MSG_R1: MessageTag = MessageTag::tag(1);

/// Message tag for the second round of the DKG protocol.
/// This message contains responses to the initial commitments.
pub const DKG_MSG_R2: MessageTag = MessageTag::tag(2);

/// Message tag for the first round of oblivious transfer in the DKG protocol.
/// This message is sent peer-to-peer between participants.
pub const DKG_MSG_OT1: MessageTag = MessageTag::tag(3);

/// Message tag for the third round of the DKG protocol.
/// This message contains final commitments and proofs.
pub const DKG_MSG_R3: MessageTag = MessageTag::tag(4);

/// Message tag for the fourth round of the DKG protocol.
/// This message contains the final key shares and verification information.
pub const DKG_MSG_R4: MessageTag = MessageTag::tag(5);

/// Message tag for the initial round of the quorum change protocol.
/// This message contains the request to change the quorum.
pub const QC_MSG_R0: MessageTag = MessageTag::tag(10);

/// Message tag for the first round of the quorum change protocol.
/// This message contains initial commitments for the quorum change.
pub const QC_MSG_R1: MessageTag = MessageTag::tag(11);

/// Message tag for the second round of the quorum change protocol.
/// This message contains responses to the quorum change commitments.
pub const QC_MSG_R2: MessageTag = MessageTag::tag(12);

/// Message tag for the first peer-to-peer message in the quorum change protocol.
/// This message is sent directly between participants.
pub const QC_MSG_P2P_1: MessageTag = MessageTag::tag(13);

/// Message tag for the second peer-to-peer message in the quorum change protocol.
/// This message is sent directly between participants.
pub const QC_MSG_P2P_2: MessageTag = MessageTag::tag(14);

/// Message tag for the first oblivious transfer message in the quorum change protocol.
/// This message is used for secure information exchange.
pub const QC_MSG_OT1: MessageTag = MessageTag::tag(15);

/// Message tag for the second oblivious transfer message in the quorum change protocol.
/// This message is used for secure information exchange.
pub const QC_MSG_OT2: MessageTag = MessageTag::tag(16);

/// Message tag used to communicate the final result of a keyshare creation or update operation.
/// This message is sent after all protocol rounds are complete.
pub const DKG_RECONCILE: MessageTag = MessageTag::tag(u64::MAX - 1);

/// First available message tag for user applications.
///
/// Applications should use `MessageTag::tag2(DKG_MSG_APP, app-specific-value)` to create
/// application-specific message tags. This ensures tags don't conflict with protocol messages.
///
/// The value is set to `u32::MAX - 1` to avoid potential conflicts with `ABORT_MESSAGE_TAG`
/// which is equal to `MessageTag::tag2(u32::MAX, u32::MAX)`.
pub const DKG_MSG_APP: u32 = u32::MAX - 1;
