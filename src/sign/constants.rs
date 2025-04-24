// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! Constants for the Distributed Signature Generation (DSG) Protocol
//!
//! This module defines various constants used throughout the DSG protocol,
//! including message tags and cryptographic labels. These constants ensure
//! consistent identification and routing of protocol messages.

use sl_mpc_mate::message::MessageTag;
use sl_oblivious::label::Label;

use crate::VERSION;

/// Protocol label for the Distributed Signature Generation protocol
///
/// This label is used to identify and namespace all messages and cryptographic
/// operations related to the DSG protocol.
pub const DSG_LABEL: Label = Label::new(VERSION, 200);

/// Label for cryptographic commitments in the protocol
///
/// This label is used to identify commitment operations, ensuring they are
/// properly namespaced and cannot be confused with other protocol operations.
pub const COMMITMENT_LABEL: Label = Label::new(VERSION, 201);

/// Label for digest operations in the protocol
///
/// This label is used to identify digest operations, ensuring they are
/// properly namespaced and cannot be confused with other protocol operations.
pub const DIGEST_I_LABEL: Label = Label::new(VERSION, 202);

/// Label for Pairwise Multiplicative-to-Additive (MtA) operations
///
/// This label is used to identify MtA operations between pairs of participants,
/// ensuring they are properly namespaced and cannot be confused with other
/// protocol operations.
pub const PAIRWISE_MTA_LABEL: Label = Label::new(VERSION, 203);

/// Label for Pairwise Randomization operations
///
/// This label is used to identify randomization operations between pairs of
/// participants, ensuring they are properly namespaced and cannot be confused
/// with other protocol operations.
pub const PAIRWISE_RANDOMIZATION_LABEL: Label = Label::new(VERSION, 204);

/// Message tag for the first round of broadcast messages
///
/// This tag identifies messages sent during the first round of the protocol,
/// where participants broadcast their initial commitments.
pub const DSG_MSG_R1: MessageTag = MessageTag::tag(1);

/// Message tag for the second round of peer-to-peer messages
///
/// This tag identifies messages sent during the second round of the protocol,
/// where participants exchange information in a peer-to-peer manner.
pub const DSG_MSG_R2: MessageTag = MessageTag::tag(2);

/// Message tag for the third round of peer-to-peer messages
///
/// This tag identifies messages sent during the third round of the protocol,
/// where participants exchange additional information in a peer-to-peer manner.
pub const DSG_MSG_R3: MessageTag = MessageTag::tag(3);

/// Message tag for the fourth round of broadcast messages
///
/// This tag identifies messages sent during the fourth round of the protocol,
/// where participants broadcast their final contributions to the signature.
pub const DSG_MSG_R4: MessageTag = MessageTag::tag(4);
