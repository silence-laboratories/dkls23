//!

use crate::VERSION;
use sl_mpc_mate::{label::Label, message::MessageTag};

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


/// Broadcast message KeygenMsg1
pub const DKG_MSG_R1: MessageTag = MessageTag::tag(1);

/// Message handled by KeygenParty<R2>.
/// We send both broadcast and P2P messages wit this tag.
pub const DKG_MSG_R2: MessageTag = MessageTag::tag(2);

/// Message handled by KeygenParty<R3>
pub const DKG_MSG_R3: MessageTag = MessageTag::tag(3);

/// Message handled by KeygenParty<R4>
pub const DKG_MSG_R4: MessageTag = MessageTag::tag(4);
