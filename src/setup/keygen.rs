// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

#![allow(missing_docs)]

use std::marker::PhantomData;
use std::time::Duration;

use sha2::{Digest, Sha256};
use signature::{SignatureEncoding, Signer, Verifier};

use sl_mpc_mate::message::InstanceId;

/// Default Time-To-Live (TTL) value for messages in seconds
const DEFAULT_TTL: u64 = 100; // smaller timeout might fail tests

use crate::setup::{
    keys::{NoSignature, NoSigningKey, NoVerifyingKey},
    KeygenSetupMessage, ProtocolParticipant,
};

/// A message used for setting up key generation in a multi-party computation protocol.
///
/// This struct encapsulates all necessary information for setting up a key generation protocol,
/// including participant information, cryptographic keys, and protocol parameters.
///
/// # Type Parameters
/// * `SK` - The type of signing key used for message signatures
/// * `VK` - The type of verifying key used to verify message signatures
/// * `MS` - The type of message signature
pub struct SetupMessage<SK = NoSigningKey, VK = NoVerifyingKey, MS = NoSignature> {
    /// Total number of participants in the protocol
    n: usize,
    /// Threshold value for the protocol
    t: usize,
    /// ID of the current party
    party_id: usize,
    /// Ranks of all participants
    ranks: Vec<u8>,
    /// Signing key for the current party
    sk: SK,
    /// Verifying keys for all participants
    vk: Vec<VK>,
    /// Optional key identifier
    key_id: Option<[u8; 32]>,
    /// Instance identifier for the protocol
    inst: InstanceId,
    /// Time-to-live duration for messages
    ttl: Duration,
    /// Phantom data to hold the message signature type
    marker: PhantomData<MS>,
}

impl<SK, VK, MS> SetupMessage<SK, VK, MS> {
    /// Creates a new setup message for key generation.
    ///
    /// # Arguments
    /// * `inst` - Instance identifier for the protocol
    /// * `sk` - Signing key for the current party
    /// * `party_id` - ID of the current party
    /// * `vk` - Vector of verifying keys for all participants
    /// * `ranks` - Ranks of all participants
    /// * `t` - Threshold value for the protocol
    ///
    /// # Returns
    /// A new `SetupMessage` instance with default TTL and no key ID
    pub fn new(
        inst: InstanceId,
        sk: SK,
        party_id: usize,
        vk: Vec<VK>,
        ranks: &[u8],
        t: usize,
    ) -> Self {
        Self {
            n: vk.len(),
            t,
            party_id,
            sk,
            vk,
            inst,
            key_id: None,
            ttl: Duration::from_secs(DEFAULT_TTL),
            ranks: ranks.to_vec(),
            marker: PhantomData,
        }
    }

    /// Sets a custom time-to-live duration for messages.
    ///
    /// # Arguments
    /// * `ttl` - The new time-to-live duration
    ///
    /// # Returns
    /// The modified `SetupMessage` instance
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// Sets a custom key identifier.
    ///
    /// # Arguments
    /// * `key_id` - Optional key identifier
    ///
    /// # Returns
    /// The modified `SetupMessage` instance
    pub fn with_key_id(mut self, key_id: Option<[u8; 32]>) -> Self {
        self.key_id = key_id;
        self
    }

    /// Returns the key identifier if it exists.
    ///
    /// # Returns
    /// An optional reference to the key identifier bytes
    pub fn key_id(&self) -> Option<&[u8]> {
        self.key_id.as_ref().map(AsRef::as_ref)
    }
}

impl<SK, VK, MS> ProtocolParticipant for SetupMessage<SK, VK, MS>
where
    SK: Signer<MS>,
    MS: SignatureEncoding,
    VK: AsRef<[u8]> + Verifier<MS>,
{
    type MessageSignature = MS;
    type MessageSigner = SK;
    type MessageVerifier = VK;

    /// Returns the total number of participants in the protocol.
    fn total_participants(&self) -> usize {
        self.n
    }

    /// Returns the index of the current participant.
    fn participant_index(&self) -> usize {
        self.party_id
    }

    /// Returns the instance identifier for the protocol.
    fn instance_id(&self) -> &InstanceId {
        &self.inst
    }

    /// Returns the time-to-live duration for messages.
    fn message_ttl(&self) -> Duration {
        self.ttl
    }

    /// Returns the verifying key for a specific participant.
    ///
    /// # Arguments
    /// * `index` - The index of the participant
    ///
    /// # Returns
    /// A reference to the verifying key
    fn verifier(&self, index: usize) -> &Self::MessageVerifier {
        &self.vk[index]
    }

    /// Returns the signing key for the current participant.
    fn signer(&self) -> &Self::MessageSigner {
        &self.sk
    }
}

impl<SK, VK, MS> KeygenSetupMessage for SetupMessage<SK, VK, MS>
where
    SK: Signer<MS>,
    MS: SignatureEncoding,
    VK: AsRef<[u8]> + Verifier<MS>,
{
    /// Returns the threshold value for the protocol.
    fn threshold(&self) -> u8 {
        self.t as u8
    }

    /// Returns the rank of a specific participant.
    ///
    /// # Arguments
    /// * `index` - The index of the participant
    ///
    /// # Returns
    /// The rank of the participant
    fn participant_rank(&self, index: usize) -> u8 {
        self.ranks[index]
    }

    /// Derives a key identifier from a public key.
    ///
    /// # Arguments
    /// * `public_key` - The public key to derive the identifier from
    ///
    /// # Returns
    /// A 32-byte key identifier
    fn derive_key_id(&self, public_key: &[u8]) -> [u8; 32] {
        self.key_id
            .unwrap_or_else(|| Sha256::digest(public_key).into())
    }
}
