///!

use sl_mpc_mate::message::MessageTag;

/// LABEL for the keygen protocol
pub const DKG_LABEL: &[u8] = b"SilenceLaboratories-DKG-DKLS";

/// LABEL for the DLOG proof 1
pub const DLOG_PROOF1_LABEL: &[u8] = b"SilenceLaboratories-DKG-DLOG-PROOF1";

/// LABEL for the DLOG proof 2
pub const DLOG_PROOF2_LABEL: &[u8] = b"SilenceLaboratories-DKG-DLOG-PROOF2";

///
pub const DKG_MSG_R1: MessageTag = MessageTag::tag(1);

///
pub const DKG_MSG_R2: MessageTag = MessageTag::tag(2);

///
pub const DKG_MSG_R3: MessageTag = MessageTag::tag(3);

///
pub const DKG_MSG_R4: MessageTag = MessageTag::tag(4);

///
pub const DKG_MSG_R5: MessageTag = MessageTag::tag(5);

///
pub const DKG_MSG_R6: MessageTag = MessageTag::tag(6);
