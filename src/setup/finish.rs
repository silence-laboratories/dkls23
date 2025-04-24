// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

#![allow(missing_docs)]

use std::{marker::PhantomData, time::Duration};

use signature::{SignatureEncoding, Signer, Verifier};

use sl_mpc_mate::message::InstanceId;

use crate::{
    setup::{
        keys::{NoSignature, NoSigningKey, NoVerifyingKey},
        FinalSignSetupMessage, ProtocolParticipant,
    },
    sign::PreSign,
};

/// Default Time-To-Live (TTL) value for messages in seconds
const DEFAULT_TTL: u64 = 100; // smaller timeout might fail tests

/// A message used for finalizing signing operations in a multi-party computation protocol.
///
/// This struct encapsulates all necessary information for completing a signing operation,
/// including participant information, cryptographic keys, and protocol parameters.
///
/// # Type Parameters
/// * `SK` - The type of signing key used for message signatures
/// * `VK` - The type of verifying key used to verify message signatures
/// * `MS` - The type of message signature
/// * `PS` - The type of pre-signature used in the protocol
pub struct SetupMessage<
    SK = NoSigningKey,
    VK = NoVerifyingKey,
    MS = NoSignature,
    PS = PreSign,
> {
    /// Index of the current party
    party_idx: usize,
    /// Signing key for the current party
    sk: SK,
    /// Verifying keys for all participants
    vk: Vec<VK>,
    /// Instance identifier for the protocol
    instance: InstanceId,
    /// Time-to-live duration for messages
    ttl: Duration,
    /// Hash of the message to be signed
    hash: [u8; 32],
    /// Pre-signature used in the final signing step
    pre: PS,
    /// Phantom data to hold the message signature type
    marker: PhantomData<MS>,
}

impl<SK, VK, MS, PS> SetupMessage<SK, VK, MS, PS> {
    /// Creates a new setup message for finalizing signing operations.
    ///
    /// # Arguments
    /// * `instance` - Instance identifier for the protocol
    /// * `party_idx` - Index of the current party
    /// * `sk` - Signing key for the current party
    /// * `vk` - Vector of verifying keys for all participants
    /// * `pre` - Pre-signature used in the final signing step
    ///
    /// # Returns
    /// A new `SetupMessage` instance with default TTL and zero hash
    pub fn new(
        instance: InstanceId,
        party_idx: usize,
        sk: SK,
        vk: Vec<VK>,
        pre: PS,
    ) -> Self {
        Self {
            party_idx,
            sk,
            vk,
            instance,
            pre,
            ttl: Duration::from_secs(DEFAULT_TTL),
            hash: [0; 32],
            marker: PhantomData,
        }
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

    /// Sets a custom time-to-live duration for messages.
    ///
    /// # Arguments
    /// * `ttl` - The new time-to-live duration
    ///
    /// # Returns
    /// The modified `SetupMessage` instance
    pub fn ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }
}

impl<SK, VK, MS, PS> ProtocolParticipant for SetupMessage<SK, VK, MS, PS>
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

impl<SK, VK, MS> FinalSignSetupMessage for SetupMessage<SK, VK, MS, PreSign>
where
    SK: Signer<MS>,
    MS: SignatureEncoding,
    VK: AsRef<[u8]> + Verifier<MS>,
{
    /// Returns a reference to the pre-signature.
    fn pre_signature(&self) -> &PreSign {
        &self.pre
    }

    /// Returns the hash of the message to be signed.
    fn message_hash(&self) -> [u8; 32] {
        self.hash
    }
}
