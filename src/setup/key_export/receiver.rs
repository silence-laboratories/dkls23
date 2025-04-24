// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use super::*;

/// A message used for setting up key export receiving operations in a multi-party computation protocol.
///
/// This struct encapsulates all necessary information for receiving an exported key,
/// including participant information, cryptographic keys, and protocol parameters.
///
/// # Type Parameters
/// * `SK` - The type of signing key used for message signatures
/// * `VK` - The type of verifying key used to verify message signatures
/// * `MS` - The type of message signature
pub struct KeyExportReceiver<SK = NoSigningKey, VK = NoVerifyingKey, MS = NoSignature> {
    /// ID of the current party
    party_id: usize,
    /// Signing key for the current party
    sk: SK,
    /// Verifying keys for all participants
    vk: Vec<VK>,
    /// Instance identifier for the protocol
    inst: InstanceId,
    /// Time-to-live duration for messages
    ttl: Duration,
    /// Reference to the keyshare to be received
    share: Arc<Keyshare>,
    /// Private key used for decryption
    enc_key: ReusableSecret,
    /// Phantom data to hold the message signature type
    marker: PhantomData<MS>,
}

impl<SK, VK, MS> KeyExportReceiver<SK, VK, MS> {
    /// Creates a new setup message for key export receiving operations.
    ///
    /// # Arguments
    /// * `inst` - Instance identifier for the protocol
    /// * `sk` - Signing key for the current party
    /// * `party_id` - ID of the current party
    /// * `vk` - Vector of verifying keys for all participants
    /// * `share` - Reference to the keyshare to be received
    /// * `enc_key` - Private key used for decryption
    ///
    /// # Returns
    /// A new `KeyExportReceiver` instance with default TTL
    pub fn new(
        inst: InstanceId,
        sk: SK,
        party_id: usize,
        vk: Vec<VK>,
        share: Arc<Keyshare>,
        enc_key: ReusableSecret,
    ) -> Self {
        Self {
            party_id,
            sk,
            vk,
            inst,
            ttl: Duration::from_secs(DEFAULT_TTL),
            marker: PhantomData,
            share,
            enc_key,
        }
    }

    /// Sets a custom time-to-live duration for messages.
    ///
    /// # Arguments
    /// * `ttl` - The new time-to-live duration
    ///
    /// # Returns
    /// The modified `KeyExportReceiver` instance
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }
}

impl<SK, VK, MS> ProtocolParticipant for KeyExportReceiver<SK, VK, MS>
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
        self.vk.len()
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

impl<SK, VK, MS> setup::KeyExportReceiverSetupMessage<ReusableSecret>
    for KeyExportReceiver<SK, VK, MS>
where
    SK: Signer<MS>,
    MS: SignatureEncoding,
    VK: AsRef<[u8]> + Verifier<MS>,
{
    /// Returns a reference to the keyshare to be received.
    fn keyshare(&self) -> &Keyshare {
        &self.share
    }

    /// Returns the private key used for decryption.
    fn receiver_private_key(&self) -> &ReusableSecret {
        &self.enc_key
    }
}
