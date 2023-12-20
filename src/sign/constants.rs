//!

use sl_mpc_mate::message::MessageTag;

/// LABEL for the signature protocol
pub const DSG_LABEL: &[u8] = b"SilenceLaboratories-DSG-DKLS-v1.0";

/// LABEL for the commitment
pub const COMMITMENT_LABEL: &[u8] = b"SilenceLaboratories-DSG-COMMITMENT";

/// LABEL for the digest_i
pub const DIGEST_I_LABEL: &[u8] = b"SilenceLaboratories-DSG-DIGEST-I";

/// LABEL for Pairwise MtA
pub const PAIRWISE_MTA_LABEL: &[u8] = b"SilenceLaboratories-DSG-PAIRWISE-MTA";

/// LABEL for Pairwise Randomization
pub const PAIRWISE_RANDOMIZATION_LABEL: &[u8] = b"SilenceLaboratories-DSG-RANDOMIZATION-MTA";

/// Broadcast message 1
pub const DSG_MSG_R1: MessageTag = MessageTag::tag(1);

/// P2P message 2
pub const DSG_MSG_R2: MessageTag = MessageTag::tag(2);

/// P2P message 3
pub const DSG_MSG_R3: MessageTag = MessageTag::tag(3);

/// Broadcast message 4
pub const DSG_MSG_R4: MessageTag = MessageTag::tag(4);
