use thiserror::Error;

use sl_mpc_mate::{
    bincode::error::{DecodeError, EncodeError},
    message::InvalidMessage,
};

use crate::BadPartyIndex;

/// Distributed key generation errors
#[derive(Error, Debug)]
pub enum SignError {
    /// Mta error
    #[error("MTA error: {0}")]
    MtaError(&'static str),

    /// Invalid commitment
    #[error("Invalid commitment")]
    InvalidCommitment,

    /// Invalid digest
    #[error("Invalid digest")]
    InvalidDigest,

    #[error("Failed check: {0}")]
    /// Failed check
    FailedCheck(&'static str),

    /// k256 error
    #[error("k256 error: {0}")]
    K256Error(#[from] k256::ecdsa::Error),

    /// Invalid message format
    #[error("invalid message format")]
    InvalidMessage,

    /// Invalid party
    #[error("Bad Party")]
    BadParty,

    ///
    #[error("Missing message")]
    MissingMessage,

    /// We can't a send message
    #[error("Send message")]
    SendMessage,

    /// Some party decided to not participate in the protocol.
    #[error("Abort protocol by party {0}")]
    AbortProtocol(u8),
}

impl From<InvalidMessage> for SignError {
    fn from(_err: InvalidMessage) -> Self {
        SignError::InvalidMessage
    }
}

impl From<EncodeError> for SignError {
    fn from(_err: EncodeError) -> Self {
        SignError::InvalidMessage
    }
}

impl From<DecodeError> for SignError {
    fn from(_err: DecodeError) -> Self {
        SignError::InvalidMessage
    }
}

impl From<BadPartyIndex> for SignError {
    fn from(_err: BadPartyIndex) -> SignError {
        SignError::BadParty
    }
}
