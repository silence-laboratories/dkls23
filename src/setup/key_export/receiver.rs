// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use super::*;

/// Setup message for a key receiver in a key export protocol.
pub struct KeyExportReceiver<SK = NoSigningKey, VK = NoVerifyingKey, MS = NoSignature> {
    party_id: usize,
    sk: SK,
    vk: Vec<VK>,
    inst: InstanceId,
    ttl: Duration,
    share: Arc<Keyshare>,
    enc_key: ReusableSecret,
    marker: PhantomData<MS>,
}

impl<SK, VK, MS> KeyExportReceiver<SK, VK, MS> {
    /// Create new setup message
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

    /// Update TTL
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

    fn total_participants(&self) -> usize {
        self.vk.len()
    }

    fn participant_index(&self) -> usize {
        self.party_id
    }

    fn instance_id(&self) -> &InstanceId {
        &self.inst
    }

    fn message_ttl(&self) -> Duration {
        self.ttl
    }

    fn verifier(&self, index: usize) -> &Self::MessageVerifier {
        &self.vk[index]
    }

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
    fn keyshare(&self) -> &Keyshare {
        &self.share
    }

    fn receiver_private_key(&self) -> &ReusableSecret {
        &self.enc_key
    }
}
