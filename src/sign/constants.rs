//!

use crate::VERSION;
use sl_mpc_mate::{label::Label, message::MessageTag};


/// LABEL for the signature protocol
pub const DSG_LABEL: Label = Label::new(VERSION, 200);

/// LABEL for the commitment
pub const COMMITMENT_LABEL: Label = Label::new(VERSION, 201);

/// LABEL for the digest_i
pub const DIGEST_I_LABEL: Label = Label::new(VERSION, 202);

/// LABEL for Pairwise MtA
pub const PAIRWISE_MTA_LABEL: Label = Label::new(VERSION, 203);

/// LABEL for Pairwise Randomization
pub const PAIRWISE_RANDOMIZATION_LABEL: Label = Label::new(VERSION, 204);

/// Broadcast message 1
pub const DSG_MSG_R1: MessageTag = MessageTag::tag(1);

/// P2P message 2
pub const DSG_MSG_R2: MessageTag = MessageTag::tag(2);

/// P2P message 3
pub const DSG_MSG_R3: MessageTag = MessageTag::tag(3);

/// Broadcast message 4
pub const DSG_MSG_R4: MessageTag = MessageTag::tag(4);
