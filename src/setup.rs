//!
//! Protocol setup message
//!

use std::ops::Deref;

use sl_mpc_mate::message::{InstanceId, MessageTag, SigningKey, VerifyingKey};

/// Tag for all setup messages
pub const SETUP_MESSAGE_TAG: MessageTag = MessageTag::tag(0);

/// Tag of a broadcast message indicating that sender
/// won't participate in the protocol. The payload of
/// the message contains error code.
pub const ABORT_MESSAGE_TAG: MessageTag = MessageTag::tag(u64::MAX);

/// Magic designates a particular MPC protocol
pub enum Magic {
    /// Distributed Key generation
    DKG = 1,

    /// Distributed Signature Generation
    DSG = 2,
}

/// How to handle message field of a DSG setup message
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HashAlgo {
    /// Message field contains hash
    HashU32 = 0,

    /// Calculate SHA256
    Sha256 = 1,

    /// Calculate SHA256D
    Sha256D = 2,
}

/// Rank of a party
pub struct Rank(u8);

impl Deref for Rank {
    type Target = u8;

    fn deref(&self) -> &u8 {
        &self.0
    }
}

/// Unique index of a participant of a MPC protocol
pub struct PartyId(u8);

impl PartyId {
    /// Max number of participants of an MPC protocol
    pub const MAX: Self = PartyId(57);
}

/// Setup for DKG
pub mod keygen;

/// Setup for DSG
pub mod sign;

///
pub trait PartyInfo {
    ///
    fn instance(&self) -> &InstanceId;

    ///
    fn party_id(&self) -> u8;

    /// Signing key for this Setup
    fn signing_key(&self) -> &SigningKey;

    /// Public key
    fn verifying_key(&self) -> VerifyingKey;
}
