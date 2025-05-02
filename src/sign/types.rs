// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use crate::proto::tags::Error;
use sl_mpc_mate::coord::MessageSendError;

/// Distributed key generation errors
#[derive(thiserror::Error, Debug)]
#[allow(missing_docs)]
pub enum SignError {
    /// Invalid commitment
    #[error("Invalid commitment")]
    InvalidCommitment,

    /// Invalid digest
    #[error("Invalid digest")]
    InvalidDigest,

    /// Invalid final_session_id
    #[error("Invalid final_session_id")]
    InvalidFinalSessionID,

    #[error("Failed check: {0}")]
    /// Failed check
    FailedCheck(&'static str),

    /// k256 error
    #[error("k256 error")]
    K256Error,

    /// Invalid PreSignature
    #[error("invalid pre signature")]
    InvalidPreSign,

    /// Invalid message format
    #[error("invalid message format")]
    InvalidMessage,

    #[error("Missing message")]
    MissingMessage,

    /// We can't a send message
    #[error("Send message")]
    SendMessage,

    /// Some party decided to not participate in the protocol.
    #[error("Abort protocol by party {0}")]
    AbortProtocol(usize),

    /// Abort the protocol and ban the party
    #[error("Abort the protocol and ban the party {0}")]
    AbortProtocolAndBanParty(u8),
}

impl From<MessageSendError> for SignError {
    fn from(_err: MessageSendError) -> Self {
        SignError::SendMessage
    }
}

impl From<k256::ecdsa::Error> for SignError {
    fn from(_err: k256::ecdsa::Error) -> Self {
        Self::K256Error
    }
}

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
