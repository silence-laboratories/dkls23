// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use sl_mpc_mate::message::MsgId;

use crate::{
    keygen::constants, proto::SignedMessage, setup::ProtocolParticipant,
};

/// Constructs a final message for a given protocol participant,
/// encoding a status code and an optional details.
///
/// This function is used to create a message that signifies the end
/// or completion of a protocol process between participants. It
/// incorporates a status code and an optional reason, which are
/// signed and marshaled into a format specified by the
/// `SignedMessage` structure.
///
/// # Type Parameters
///
/// - `S`: A type that implements the `ProtocolParticipant`
///   trait. This trait provides necessary methods and types for
///   facilitating the message creation process.
///
/// # Parameters
///
/// - `setup`: A reference to an instance of a type `S` that
///   implements the `ProtocolParticipant` trait. It provides context
///   and utilities needed for message creation, such as message
///   identifiers and signature information.
///
/// - `code`: A `u16` status code that indicates the final status or
///   outcome of the protocol. This code could represent success,
///   failure, or any other relevant state.
///
/// - `details`: An optional byte slice that provides additional
///   information or context for the status code.
///
/// # Returns
///
/// - `Vec<u8>`: A vector of bytes representing the serialized and
///   signed final message.
///
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

/// Determines whether a given message matches the expected final
/// message identifier for a specified sender.
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

/// Parses and verifies a final message, extracting the status code
/// and optional details.
///
/// This function is responsible for interpreting a message received
/// from a protocol participant, verifying its authenticity, and
/// extracting status code and an optional details.
///
/// # Type Parameters
///
/// - `S`: A type that implements the `ProtocolParticipant`
///   trait. This type provides the necessary verification capabilities
///   and signature types required for message interpretation and
///   validation.
///
/// - `E`: The error type returned by the function if message parsing
///   or verification fails.
///
/// # Parameters
///
/// - `setup`: A reference to an instance of a type `S` that
///   implements the `ProtocolParticipant` trait. This setup instance is
///   used to obtain the verifier for the corresponding protocol
///   participant.
///
/// - `msg`: A byte slice representing the message to be parsed and
///   verified. This message contains serialized data, including a
///   status code and an optional reason string.
///
/// - `party_id`: The identifier for the party whose message is being
///   verified. This identifier is used to obtain verification criteria
///   specific to the party from the `setup`.
///
/// - `err`: A closure that takes a `usize` (representing the
///   `party_id`) and returns an error of type `E`.  This closure is
///   invoked if the function encounters issues with the message (e.g.,
///   verification failure).
///
/// # Returns
///
/// - `Result<(u16, Option<&'[u8]>), E>`: On successful parsing and
///   verification, returns a tuple consisting of a `u16` status code
///   and an optional details. If any error is encountered during
///   message verification or parsing, an error of type `E` is
///   returned constructed by calling `err`.
///
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
