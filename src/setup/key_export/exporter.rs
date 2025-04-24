// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use super::*;

/// Setup message for a key export .
pub struct KeyExporter<SK = NoSigningKey, VK = NoVerifyingKey, MS = NoSignature, KS = Keyshare> {
    party_id: usize,
    sk: SK,
    vk: Vec<VK>,
    inst: InstanceId,
    ttl: Duration,
    pub_key: PublicKey,
    share: Arc<KS>,
    marker: PhantomData<MS>,
}

impl<SK, VK, MS, KS> KeyExporter<SK, VK, MS, KS> {
    /// Create new setup message
    pub fn new(
        inst: InstanceId,
        sk: SK,
        party_id: usize,
        vk: Vec<VK>,
        share: Arc<KS>,
        enc_pub_key: PublicKey,
    ) -> Self {
        Self {
            party_id,
            sk,
            vk,
            inst,
            ttl: Duration::from_secs(DEFAULT_TTL),
            marker: PhantomData,
            pub_key: enc_pub_key,
            share,
        }
    }

    /// Keyshare
    pub fn keyshare(&self) -> &KS {
        &self.share
    }

    /// Update TTL
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }
}

impl<SK, VK, MS, KS> ProtocolParticipant for KeyExporter<SK, VK, MS, KS>
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

impl<SK, VK, MS, KS> setup::KeyExporterSetupMessage<PublicKey, KS> for KeyExporter<SK, VK, MS, KS>
where
    SK: Signer<MS>,
    MS: SignatureEncoding,
    VK: AsRef<[u8]> + Verifier<MS>,
{
    fn receiver_public_key(&self) -> &PublicKey {
        &self.pub_key
    }

    fn keyshare(&self) -> &KS {
        &self.share
    }
}
