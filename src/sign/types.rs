use k256::Scalar;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sl_mpc_mate::{nacl::SignPubkey, random_bytes, traits::PersistentObject, SessionId};
use thiserror::Error;

use crate::keygen::{messages::Keyshare, PartyKeys};

/// Parameters for the sign protocol. Constant across all rounds.
pub struct SignParams {
    /// The party's id
    pub party_id: usize,
    pub(crate) rand_params: SignEntropy,
    pub(crate) keyshare: Keyshare,
    pub(crate) party_keys: PartyKeys,
    /// List of all parties' public keys
    pub party_pubkeys: Vec<SignPartyPublicKeys>,
}

impl SignParams {
    /// Get the pubkeys for the given party id
    pub fn get_pubkey_for_party(&self, party_id: usize) -> Option<&SignPartyPublicKeys> {
        self.party_pubkeys.iter().find(|pk| pk.party_id == party_id)
    }
}

/// All random params needed for sign protocol
pub struct SignEntropy {
    pub(crate) session_id: SessionId,
    pub(crate) phi_i: Scalar,
    pub(crate) k_i: Scalar,
    pub(crate) blind_factor: [u8; 32],
}

impl SignEntropy {
    /// Generate all the random values used in the sign protocol
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        Self {
            session_id: SessionId::random(rng),
            phi_i: Scalar::generate_biased(rng),
            k_i: Scalar::generate_biased(rng),
            blind_factor: random_bytes(rng),
        }
    }
}

/// Datatype for all of the participants public keys (verification, encryption)
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct SignPartyPublicKeys {
    /// The party's id
    pub party_id: usize,

    /// The public key for signature verification.
    pub verify_key: SignPubkey,

    /// Public key for encryption
    pub encryption_key: sl_mpc_mate::nacl::BoxPubkey,
}

impl PersistentObject for SignPartyPublicKeys {}

/// Distributed key generation errors
#[derive(Error, Debug)]
pub enum SignError {
    /// Error in the key generation protocol
    #[error("Libsodium error: {0}")]
    LibsodiumError(#[from] sl_mpc_mate::nacl::Error),
    /// Party key not found
    #[error("Party key not found")]
    PartyKeyNotFound,
    #[error("Invalid input message count")]
    /// Invalid input message count
    InvalidMsgCount,
    #[error("Invalid party id, message from party not in id list")]
    /// Invalid party id
    UnexpectedPartyId,
    /// Received duplicate party id
    #[error("Received duplicate party id")]
    DuplicatePartyId,
    /// Invalid party ids
    #[error("Invalid party ids")]
    InvalidMsgPartyId,
    #[error("Wrong receipient, received message for party {0}, expected {1}")]
    /// Wrong receipient
    WrongReceipient(usize, usize),
    /// Already processed message from party
    #[error("Already processed message from party {0}")]
    AlreadyProcessed(usize),

    #[error("Invalid message")]
    /// Invalid message
    InvalidPlaintext,

    #[error("Already processed message from all parties, please use check_proceed to proceed to next state ")]
    /// Already processed message from all parties
    AlreadyProcessedAll,

    /// Mta error
    #[error("MTA error: {0}")]
    MtaError(String),

    /// Decryption error
    #[error("Decryption error: {0}")]
    DecryptionError(String),

    /// Invalid commitment
    #[error("Invalid commitment")]
    InvalidCommitment,

    /// Invalid digest
    #[error("Invalid digest")]
    InvalidDigest,

    #[error("Failed check: {0}")]
    /// Failed check
    FailedCheck(String),

    /// k256 error
    #[error("k256 error: {0}")]
    K256Error(#[from] k256::ecdsa::Error),

    /// Invalid message format
    #[error("invalid message format")]
    InvalidMessage
}
