// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

#![allow(missing_docs)]

use core::str::FromStr;
use std::{marker::PhantomData, sync::Arc, time::Duration};

use derivation_path::DerivationPath;
use signature::{SignatureEncoding, Signer, Verifier};

use sl_mpc_mate::message::InstanceId;

use crate::{
    keygen::Keyshare,
    setup::{
        keys::{NoSignature, NoSigningKey, NoVerifyingKey},
        PreSignSetupMessage, ProtocolParticipant, SignSetupMessage,
    },
};

/// Default Time-To-Live (TTL) value for messages in seconds
const DEFAULT_TTL: u64 = 100; // smaller timeout might fail tests

/// A message used for setting up signing operations in a multi-party computation protocol.
///
/// This struct encapsulates all necessary information for signing operations,
/// including participant information, cryptographic keys, and protocol parameters.
///
/// # Type Parameters
/// * `SK` - The type of signing key used for message signatures
/// * `VK` - The type of verifying key used to verify message signatures
/// * `MS` - The type of message signature
/// * `KS` - The type of keyshare used in the protocol
pub struct SetupMessage<
    SK = NoSigningKey,
    VK = NoVerifyingKey,
    MS = NoSignature,
    KS = Keyshare,
> {
    /// Index of the current party
    party_idx: usize,
    /// Signing key for the current party
    sk: SK,
    /// Verifying keys for all participants
    vk: Vec<VK>,
    /// Instance identifier for the protocol
    instance: InstanceId,
    /// Reference to the keyshare used in signing
    keyshare: Arc<KS>,
    /// Derivation path for key derivation
    chain_path: DerivationPath,
    /// Time-to-live duration for messages
    ttl: Duration,
    /// Hash of the message to be signed
    hash: [u8; 32],
    /// Phantom data to hold the message signature type
    marker: PhantomData<MS>,
}

impl<SK, VK, MS, KS> SetupMessage<SK, VK, MS, KS> {
    /// Creates a new setup message for signing operations.
    ///
    /// # Arguments
    /// * `instance` - Instance identifier for the protocol
    /// * `sk` - Signing key for the current party
    /// * `party_idx` - Index of the current party
    /// * `vk` - Vector of verifying keys for all participants
    /// * `share` - Reference to the keyshare used in signing
    ///
    /// # Returns
    /// A new `SetupMessage` instance with default TTL, root derivation path, and zero hash
    pub fn new(
        instance: InstanceId,
        sk: SK,
        party_idx: usize,
        vk: Vec<VK>,
        share: Arc<KS>,
    ) -> Self {
        Self {
            party_idx,
            sk,
            vk,
            instance,
            keyshare: share.clone(),
            ttl: Duration::from_secs(DEFAULT_TTL),
            chain_path: DerivationPath::from_str("m").unwrap(),
            hash: [0; 32],
            marker: PhantomData,
        }
    }

    /// Sets a custom derivation path for key derivation.
    ///
    /// # Arguments
    /// * `chain_path` - The new derivation path
    ///
    /// # Returns
    /// The modified `SetupMessage` instance
    pub fn with_chain_path(mut self, chain_path: DerivationPath) -> Self {
        self.chain_path = chain_path;
        self
    }

    /// Sets the hash of the message to be signed.
    ///
    /// # Arguments
    /// * `hash` - The 32-byte hash of the message
    ///
    /// # Returns
    /// The modified `SetupMessage` instance
    pub fn with_hash(mut self, hash: [u8; 32]) -> Self {
        self.hash = hash;
        self
    }

    /// Optionally sets the hash of the message to be signed.
    ///
    /// # Arguments
    /// * `hash` - Optional 32-byte hash of the message
    ///
    /// # Returns
    /// The modified `SetupMessage` instance
    pub fn with_hash_opt(mut self, hash: Option<[u8; 32]>) -> Self {
        if let Some(hash) = hash {
            self.hash = hash;
        }
        self
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

    /// Returns a clone of the keyshare.
    pub fn clone_keyshare(&self) -> Arc<KS> {
        self.keyshare.clone()
    }

    /// Returns a reference to the derivation path.
    pub fn get_chain_path(&self) -> &DerivationPath {
        &self.chain_path
    }
}

impl<SK, VK, MS, KS> ProtocolParticipant for SetupMessage<SK, VK, MS, KS>
where
    SK: Signer<MS>,
    MS: SignatureEncoding,
    VK: AsRef<[u8]> + Verifier<MS>,
{
    type MessageSignature = MS;
    type MessageSigner = SK;
    type MessageVerifier = VK;

    /// Returns the signing key for the current participant.
    fn signer(&self) -> &Self::MessageSigner {
        &self.sk
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

    /// Returns the instance identifier for the protocol.
    fn instance_id(&self) -> &InstanceId {
        &self.instance
    }

    /// Returns the time-to-live duration for messages.
    fn message_ttl(&self) -> Duration {
        self.ttl
    }

    /// Returns the index of the current participant.
    fn participant_index(&self) -> usize {
        self.party_idx
    }

    /// Returns the total number of participants in the protocol.
    fn total_participants(&self) -> usize {
        self.vk.len()
    }
}

impl<SK, VK, MS> PreSignSetupMessage for SetupMessage<SK, VK, MS, Keyshare>
where
    SK: Signer<MS>,
    MS: SignatureEncoding,
    VK: AsRef<[u8]> + Verifier<MS>,
{
    /// Returns the derivation path for key derivation.
    fn chain_path(&self) -> &DerivationPath {
        &self.chain_path
    }

    /// Returns a reference to the keyshare.
    fn keyshare(&self) -> &Keyshare {
        &self.keyshare
    }
}

impl<SK, VK, MS> SignSetupMessage for SetupMessage<SK, VK, MS, Keyshare>
where
    SK: Signer<MS>,
    MS: SignatureEncoding,
    VK: AsRef<[u8]> + Verifier<MS>,
{
    /// Returns the hash of the message to be signed.
    fn message_hash(&self) -> [u8; 32] {
        self.hash
    }
}
