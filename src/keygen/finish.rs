// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! Module for handling the finalization phase of the distributed key generation protocol.


use sl_mpc_mate::message::MsgId;

use crate::{
    keygen::constants, proto::SignedMessage, setup::ProtocolParticipant,
};

/// Constructs a final message for a given protocol participant.
///
/// This function creates a signed message that indicates the completion or termination
/// of the protocol process. The message includes a status code and optional details
/// that provide additional context about the protocol outcome.
///
/// # Type Parameters
///
/// * `S` - A type implementing the `ProtocolParticipant` trait, providing necessary
///   protocol context and signing capabilities.
///
/// # Arguments
///
/// * `setup` - A reference to the protocol participant setup, providing context and
///   signing capabilities.
/// * `code` - A status code indicating the final state of the protocol (e.g., success,
///   failure, or specific error conditions).
/// * `details` - Optional additional information about the protocol outcome, provided
///   as a byte slice.
///
/// # Returns
///
/// A vector of bytes containing the serialized and signed final message.
///
/// # Examples
///
/// ```rust
/// # use crate::setup::ProtocolParticipant;
/// # use crate::keygen::finish::create_final_message;
/// # let setup = unimplemented!();
/// let success_code = 0;
/// let message = create_final_message(&setup, success_code, None);
/// ```
pub fn create_final_message<S: ProtocolParticipant>(
    setup: &S,
    code: u16,
    details: Option<&[u8]>,
) -> Vec<u8> {
    let details = details.unwrap_or(&[]);

    SignedMessage::<u16, S::MessageSignature>::build(
        &setup.msg_id(None, constants::DKG_RECONCILE),
        setup.message_ttl().as_secs() as _,
        details.len(),
        setup.signer(),
        |msg, trailer| {
            *msg = code;
            trailer.copy_from_slice(details);
        },
    )
}

/// Verifies if a message matches the expected final message identifier for a sender.
///
/// This function checks whether a given message corresponds to the final message
/// type expected from a specific protocol participant.
///
/// # Arguments
///
/// * `setup` - A reference to the protocol participant setup.
/// * `sender_id` - The identifier of the message sender.
/// * `message` - The message to verify.
///
/// # Returns
///
/// `true` if the message matches the expected final message identifier, `false` otherwise.
///
/// # Examples
///
/// ```rust
/// # use crate::setup::ProtocolParticipant;
/// # use crate::keygen::finish::is_final_message;
/// # let setup = unimplemented!();
/// # let message = unimplemented!();
/// let is_final = is_final_message(&setup, 0, &message);
/// ```
pub fn is_final_message<S: ProtocolParticipant>(
    setup: &S,
    sender_id: usize,
    message: &[u8],
) -> bool {
    <&MsgId>::try_from(message)
        .map_or(None, |id| {
            setup
                .msg_id_from(sender_id, None, constants::DKG_RECONCILE)
                .eq(id)
                .then_some(id)
        })
        .is_some()
}

/// Parses and verifies a final message from a protocol participant.
///
/// This function decodes a final message, verifies its authenticity using the sender's
/// verification key, and extracts the status code and optional details.
///
/// # Type Parameters
///
/// * `S` - A type implementing the `ProtocolParticipant` trait.
/// * `E` - The error type returned when message parsing or verification fails.
///
/// # Arguments
///
/// * `setup` - A reference to the protocol participant setup.
/// * `msg` - The message to parse and verify.
/// * `party_id` - The identifier of the message sender.
/// * `err` - A closure that creates an error when message verification fails.
///
/// # Returns
///
/// * `Ok((u16, Option<&[u8]>))` - On success, returns a tuple containing:
///   - The status code
///   - Optional details as a byte slice
/// * `Err(E)` - If message parsing or verification fails
///
/// # Examples
///
/// ```rust
/// # use crate::setup::ProtocolParticipant;
/// # use crate::keygen::finish::parse_final_message;
/// # let setup = unimplemented!();
/// # let message = unimplemented!();
/// let result = parse_final_message(&setup, &message, 0, |id| format!("Invalid message from party {}", id));
/// ```
pub fn parse_final_message<'a, S: ProtocolParticipant, E>(
    setup: &S,
    msg: &'a [u8],
    party_id: usize,
    err: impl FnOnce(usize) -> E,
) -> Result<(u16, Option<&'a [u8]>), E> {
    type Msg<S> =
        SignedMessage<u16, <S as ProtocolParticipant>::MessageSignature>;

    msg.len()
        .checked_sub(Msg::<S>::size(0))
        .and_then(|trailer| {
            Msg::<S>::verify_with_trailer(
                msg,
                trailer,
                setup.verifier(party_id),
            )
        })
        .map(|(&code, reason)| (code, reason.is_empty().then_some(reason)))
        .ok_or_else(|| err(party_id))
}


