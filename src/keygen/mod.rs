// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

mod dkg;
mod types;

/// Misc reusable code
pub mod utils;

pub use dkg::*;
pub use types::*;

/// Key refresh protocol
pub mod key_refresh;

/// Keygen protocol messages
mod messages;

/// Keyshare and related definitions
pub mod keyshare;

/// Various contants
pub mod constants;

/// Migrate shares from GG20
pub mod migration;

/// Quorum change protocol
pub mod quorum_change;

pub use keyshare::Keyshare;

use sl_mpc_mate::message::MsgId;

use crate::setup::{ProtocolParticipant, ABORT_MESSAGE_TAG};

/// Generate message receiver map.
///
/// Call the passed closure for each pair (msg_id, receiver)
///
pub fn message_receivers<S, F>(setup: &S, mut msg_receiver: F)
where
    S: ProtocolParticipant,
    F: FnMut(MsgId, &S::MessageVerifier),
{
    setup.all_other_parties().for_each(|p| {
        let vk = setup.verifier(p);

        msg_receiver(setup.msg_id(None, ABORT_MESSAGE_TAG), vk);
        msg_receiver(setup.msg_id(None, constants::DKG_MSG_R1), vk);
        msg_receiver(setup.msg_id(None, constants::DKG_MSG_R2), vk);
        msg_receiver(setup.msg_id(Some(p), constants::DKG_MSG_OT1), vk);
        msg_receiver(setup.msg_id(Some(p), constants::DKG_MSG_R3), vk);
        msg_receiver(setup.msg_id(None, constants::DKG_MSG_R4), vk);
    })
}
