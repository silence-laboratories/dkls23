// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! Types and error definitions for the Distributed Signature Generation (DSG) Protocol
//!
//! This module defines the error types and other fundamental types used throughout
//! the DSG protocol implementation. These types help ensure proper error handling
//! and type safety across the protocol implementation.

use crate::proto::tags::Error;
use sl_mpc_mate::coord::MessageSendError;

/// Error types that can occur during the Distributed Signature Generation protocol
///
/// This enum represents all possible error conditions that can arise during
/// the execution of the DSG protocol. Each variant includes a descriptive
/// error message and implements the `std::error::Error` trait.
#[derive(thiserror::Error, Debug)]
#[allow(missing_docs)]
pub enum SignError {
    /// Indicates that a cryptographic commitment is invalid
    #[error("Invalid commitment")]
    InvalidCommitment,

    /// Indicates that a message digest is invalid
    #[error("Invalid digest")]
    InvalidDigest,

    /// Indicates that the final session ID is invalid
    #[error("Invalid final_session_id")]
    InvalidFinalSessionID,

    /// Indicates that a protocol check has failed
    #[error("Failed check: {0}")]
    FailedCheck(&'static str),

    /// Indicates an error from the k256 elliptic curve library
    #[error("k256 error")]
    K256Error,

    /// Indicates that a pre-signature is invalid
    #[error("invalid pre signature")]
    InvalidPreSign,

    /// Indicates that a message has an invalid format
    #[error("invalid message format")]
    InvalidMessage,

    /// Indicates that a required message is missing
    #[error("Missing message")]
    MissingMessage,

    /// Indicates that a message could not be sent
    #[error("Send message")]
    SendMessage,

    /// Indicates that a party has decided to abort the protocol
    #[error("Abort protocol by party {0}")]
    AbortProtocol(usize),

    /// Indicates that a party should be banned and the protocol aborted
    #[error("Abort the protocol and ban the party {0}")]
    AbortProtocolAndBanParty(u8),
}

/// Conversion from `MessageSendError` to `SignError`
///
/// This implementation allows `MessageSendError` to be automatically converted
/// to `SignError::SendMessage` when using the `?` operator.
impl From<MessageSendError> for SignError {
    fn from(_err: MessageSendError) -> Self {
        SignError::SendMessage
    }
}

/// Conversion from `k256::ecdsa::Error` to `SignError`
///
/// This implementation allows k256 elliptic curve errors to be automatically
/// converted to `SignError::K256Error` when using the `?` operator.
impl From<k256::ecdsa::Error> for SignError {
    fn from(_err: k256::ecdsa::Error) -> Self {
        Self::K256Error
    }
}

/// Conversion from `Error` to `SignError`
///
/// This implementation allows protocol tag errors to be automatically converted
/// to appropriate `SignError` variants when using the `?` operator.
impl From<Error> for SignError {
    fn from(err: Error) -> Self {
        match err {
            Error::Abort(p) => SignError::AbortProtocol(p as _),
            Error::Recv => SignError::MissingMessage,
            Error::Send => SignError::SendMessage,
            Error::InvalidMessage => SignError::InvalidMessage,
        }
    }
}
