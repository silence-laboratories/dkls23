// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

#![allow(missing_docs)]

use std::{marker::PhantomData, sync::Arc, time::Duration};

use crate::{
    keygen::Keyshare,
    setup::{
        keys::{NoSignature, NoSigningKey, NoVerifyingKey},
        *,
    },
};

/// Default Time-To-Live (TTL) value for messages in seconds
const DEFAULT_TTL: u64 = 100; // smaller timeout might fail tests

/// A message used for setting up quorum changes in a multi-party computation protocol.
///
/// This struct encapsulates all necessary information for changing the quorum of participants,
/// including old and new participant information, cryptographic keys, and protocol parameters.
///
/// # Type Parameters
/// * `SK` - The type of signing key used for message signatures
/// * `VK` - The type of verifying key used to verify message signatures
/// * `MS` - The type of message signature
/// * `KS` - The type of keyshare used in the protocol
/// * `PK` - The type of public key used in the protocol
pub struct SetupMessage<
    SK = NoSigningKey,
    VK = NoVerifyingKey,
    MS = NoSignature,
    KS = Keyshare,
    PK = ProjectivePoint,
> {
    /// ID of the current party
    this_party: usize,
    /// Signing key for the current party
    sk: SK,
    /// Verifying keys for all participants
    vk: Vec<VK>,
    /// Optional reference to the current keyshare
    keyshare: Option<Arc<KS>>,
    /// Public key for the protocol
    public_key: PK,
    /// New threshold value for the protocol
    new_t: usize,
    /// New ranks for all participants
    new_ranks: Vec<u8>,
    /// Indices of new participants
    new_parties: Vec<usize>,
    /// Indices of old participants
    old_parties: Vec<usize>,
    /// Instance identifier for the protocol
    instance: InstanceId,
    /// Time-to-live duration for messages
    ttl: Duration,
    /// Phantom data to hold the message signature type
    marker: PhantomData<MS>,
}

impl<SK, VK, MS, KS, PK> SetupMessage<SK, VK, MS, KS, PK> {
    /// Creates a new setup message for quorum changes.
    ///
    /// # Arguments
    /// * `instance` - Instance identifier for the protocol
    /// * `this_party` - ID of the current party
    /// * `old_parties` - Indices of old participants
    /// * `new_parties` - Pairs of (index, rank) for new participants
    /// * `new_t` - New threshold value
    /// * `sk` - Signing key for the current party
    /// * `vk` - Vector of verifying keys for all participants
    /// * `public_key` - Public key for the protocol
    ///
    /// # Panics
    /// Panics if:
    /// * `this_party` is not less than the total number of parties
    /// * Any old party index is not less than the total number of parties
    /// * Any new party index is not less than the total number of parties
    /// * `new_t` is greater than the number of new parties
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        instance: InstanceId,
        this_party: usize,
        old_parties: &[usize],
        new_parties: &[(usize, u8)],
        new_t: usize,
        sk: SK,
        vk: Vec<VK>,
        public_key: PK,
    ) -> Self {
        let total_parties = vk.len();

        assert!(this_party < total_parties);

        assert!(
            old_parties.iter().max().unwrap_or(&usize::MAX) < &total_parties
        );

        assert!(
            new_parties
                .iter()
                .map(|&(i, _)| i)
                .max()
                .unwrap_or(usize::MAX)
                < total_parties
        );

        assert!(new_t <= new_parties.len());

        Self {
            this_party,
            sk,
            vk,
            public_key,
            new_t,
            new_ranks: new_parties.iter().map(|p| p.1).collect(),
            new_parties: new_parties.iter().map(|p| p.0).collect(),
            old_parties: old_parties.to_vec(),
            instance,
            ttl: Duration::from_secs(DEFAULT_TTL),
            keyshare: None,
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

    /// Sets an optional keyshare for the protocol.
    ///
    /// # Arguments
    /// * `keyshare` - Optional reference to the keyshare
    ///
    /// # Returns
    /// The modified `SetupMessage` instance
    pub fn with_keyshare_opt(mut self, keyshare: Option<Arc<KS>>) -> Self {
        self.keyshare = keyshare;
        self
    }

    /// Sets a keyshare for the protocol.
    ///
    /// # Arguments
    /// * `keyshare` - Reference to the keyshare
    ///
    /// # Returns
    /// The modified `SetupMessage` instance
    pub fn with_keyshare(self, keyshare: Arc<KS>) -> Self {
        self.with_keyshare_opt(Some(keyshare))
    }
}

impl<SK, VK, MS, KS, PK> ProtocolParticipant
    for SetupMessage<SK, VK, MS, KS, PK>
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
        self.this_party
    }

    /// Returns the total number of participants in the protocol.
    fn total_participants(&self) -> usize {
        self.vk.len()
    }
}

impl<SK, VK, MS, KS, PK> QuorumChangeSetupMessage<KS, PK>
    for SetupMessage<SK, VK, MS, KS, PK>
where
    SK: Signer<MS>,
    MS: SignatureEncoding,
    VK: AsRef<[u8]> + Verifier<MS>,
{
    /// Returns a reference to the old keyshare if it exists.
    fn old_keyshare(&self) -> Option<&KS> {
        self.keyshare.as_deref()
    }

    /// Returns the new threshold value for the protocol.
    fn new_threshold(&self) -> u8 {
        self.new_t as u8
    }

    /// Returns the rank of a specific participant in the new quorum.
    ///
    /// # Arguments
    /// * `party_id` - The ID of the participant
    ///
    /// # Returns
    /// The rank of the participant
    fn new_participant_rank(&self, party_id: u8) -> u8 {
        self.new_ranks[party_id as usize]
    }

    /// Returns the expected public key for the protocol.
    fn expected_public_key(&self) -> &PK {
        &self.public_key
    }

    /// Returns the indices of the old participants.
    fn old_party_indices(&self) -> &[usize] {
        &self.old_parties
    }

    /// Returns the indices of the new participants.
    fn new_party_indices(&self) -> &[usize] {
        &self.new_parties
    }

    /// Derives a key identifier from a public key.
    ///
    /// This is a trivial implementation that takes the first 32 bytes of the public key.
    ///
    /// # Arguments
    /// * `public_key` - The public key to derive the identifier from
    ///
    /// # Returns
    /// A 32-byte key identifier
    fn derive_key_id(&self, public_key: &[u8]) -> [u8; 32] {
        let mut bytes = [0; 32];

        let size = bytes.len().min(public_key.len());

        bytes[..size].copy_from_slice(&public_key[..size]);

        bytes
    }
}
