// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! Distributed Key Generation (DKG) Protocol Module
//!
//! This module implements a distributed key generation protocol that allows multiple parties
//! to collaboratively generate a shared secret key without any single party learning the
//! complete secret. The protocol includes several sub-protocols for key refresh, quorum
//! changes, and migration from other protocols.
//!
//! # Submodules
//! * `dkg` - Core distributed key generation protocol
//! * `types` - Common types used across the protocol
//! * `utils` - Utility functions and helpers
//! * `key_refresh` - Protocol for refreshing existing keys
//! * `keyshare` - Key share management and related definitions
//! * `constants` - Protocol constants and configuration
//! * `migration` - Migration utilities to DKLS23 protocol
//! * `quorum_change` - Protocol for changing the quorum of participants

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

/// Migrate shares to DKLS23
pub mod migration;

/// Quorum change protocol
pub mod quorum_change;

pub use keyshare::Keyshare;

use sl_mpc_mate::message::MsgId;

use crate::setup::{ProtocolParticipant, ABORT_MESSAGE_TAG};

/// Generates a map of message receivers for the DKG protocol.
///
/// This function iterates through all other parties in the protocol and calls the provided
/// closure for each message ID and corresponding verifier key. It handles all message types
/// used in the DKG protocol, including abort messages and messages for each round.
///
/// # Arguments
/// * `setup` - The protocol participant setup containing party information
/// * `msg_receiver` - A closure that will be called for each (message_id, verifier) pair
///
/// # Message Types
/// The function handles the following message types:
/// * `ABORT_MESSAGE_TAG` - Protocol abort messages
/// * `DKG_MSG_R1` - Round 1 messages
/// * `DKG_MSG_R2` - Round 2 messages
/// * `DKG_MSG_OT1` - Oblivious transfer messages
/// * `DKG_MSG_R3` - Round 3 messages
/// * `DKG_MSG_R4` - Round 4 messages
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
