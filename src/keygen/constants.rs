// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//!

use crate::VERSION;
use sl_mpc_mate::message::MessageTag;
use sl_oblivious::label::Label;

/// LABEL for the keygen protocol
pub const DKG_LABEL: Label = Label::new(VERSION, 100);

/// LABEL for the commitment 1
pub const COMMITMENT_1_LABEL: Label = Label::new(VERSION, 101);

/// LABEL for the commitment 2
pub const COMMITMENT_2_LABEL: Label = Label::new(VERSION, 102);

/// LABEL for the DLOG proof 1
pub const DLOG_PROOF1_LABEL: Label = Label::new(VERSION, 103);

/// LABEL for the DLOG proof 2
pub const DLOG_PROOF2_LABEL: Label = Label::new(VERSION, 104);

/// LABEL to create dlog sessionID from final_session_id and root_chain_code
pub const DLOG_SESSION_ID_WITH_CHAIN_CODE: Label = Label::new(VERSION, 105);

/// LABEL for the quorum change protocol
pub const QC_LABEL: Label = Label::new(VERSION, 106);

/// LABEL for the quorum change commitment 1
pub const QC_COMMITMENT_1_LABEL: Label = Label::new(VERSION, 107);

/// LABEL for the commitment 2
pub const QC_COMMITMENT_2_LABEL: Label = Label::new(VERSION, 108);

/// Broadcast message KeygenMsg1
pub const DKG_MSG_R1: MessageTag = MessageTag::tag(1);

/// Broadcast message KeygenMsg2
pub const DKG_MSG_R2: MessageTag = MessageTag::tag(2);

/// Tag for P2P EndemicOTMsg1 message
pub const DKG_MSG_OT1: MessageTag = MessageTag::tag(3);

/// Message handled by KeygenParty<R3>
pub const DKG_MSG_R3: MessageTag = MessageTag::tag(4);

/// Message handled by KeygenParty<R4>
pub const DKG_MSG_R4: MessageTag = MessageTag::tag(5);

/// Broadcast message QuorumChangeMsg0
pub const QC_MSG_R0: MessageTag = MessageTag::tag(10);

/// Broadcast message QuorumChangeMsg1
pub const QC_MSG_R1: MessageTag = MessageTag::tag(11);

/// Broadcast message QuorumChangeMsg2
pub const QC_MSG_R2: MessageTag = MessageTag::tag(12);

/// Tag for P2P 1 message
pub const QC_MSG_P2P_1: MessageTag = MessageTag::tag(13);

/// Tag for P2P 2 message
pub const QC_MSG_P2P_2: MessageTag = MessageTag::tag(14);

/// Tag for P2P OT message 1
pub const QC_MSG_OT1: MessageTag = MessageTag::tag(15);

/// Tag for P2P OT message 2
pub const QC_MSG_OT2: MessageTag = MessageTag::tag(16);

/// Tag for final message to communicate result of keyshare
/// create/update operation.
pub const DKG_RECONCILE: MessageTag = MessageTag::tag(u64::MAX - 1);

/// First tag available for user applications.  Use
/// MessageTag::tag2(DKG_MSG_APP, app-specific-value) to create
/// application specific message tags.
///
/// The value is u32::MAX - 1 to avoid potential clash with ABORT_MESSAGE_TAG
/// that is equal to MessageTag::tag2(u32::MAX, u32::MAX).
pub const DKG_MSG_APP: u32 = u32::MAX - 1;
