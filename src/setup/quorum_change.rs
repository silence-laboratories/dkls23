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

const DEFAULT_TTL: u64 = 100; // smaller timeout might fail tests

pub struct SetupMessage<
    SK = NoSigningKey,
    VK = NoVerifyingKey,
    MS = NoSignature,
    KS = Keyshare,
    PK = ProjectivePoint,
> {
    this_party: usize,
    sk: SK,
    vk: Vec<VK>,
    keyshare: Option<Arc<KS>>,
    public_key: PK,
    new_t: usize,
    new_ranks: Vec<u8>,
    new_parties: Vec<usize>,
    old_parties: Vec<usize>,
    instance: InstanceId,
    ttl: Duration,
    marker: PhantomData<MS>,
}

impl<SK, VK, MS, KS, PK> SetupMessage<SK, VK, MS, KS, PK> {
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

    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    pub fn with_keyshare_opt(mut self, keyshare: Option<Arc<KS>>) -> Self {
        self.keyshare = keyshare;
        self
    }

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

    fn signer(&self) -> &Self::MessageSigner {
        &self.sk
    }

    fn verifier(&self, index: usize) -> &Self::MessageVerifier {
        &self.vk[index]
    }

    fn instance_id(&self) -> &InstanceId {
        &self.instance
    }

    fn message_ttl(&self) -> Duration {
        self.ttl
    }

    fn participant_index(&self) -> usize {
        self.this_party
    }

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
    fn old_keyshare(&self) -> Option<&KS> {
        self.keyshare.as_deref()
    }

    fn new_threshold(&self) -> u8 {
        self.new_t as u8
    }

    fn new_participant_rank(&self, party_id: u8) -> u8 {
        self.new_ranks[party_id as usize]
    }

    fn expected_public_key(&self) -> &PK {
        &self.public_key
    }

    fn old_party_indices(&self) -> &[usize] {
        &self.old_parties
    }

    fn new_party_indices(&self) -> &[usize] {
        &self.new_parties
    }

    // A trivial implementation, just take first 32 bytes of passed
    // slice.
    fn derive_key_id(&self, public_key: &[u8]) -> [u8; 32] {
        let mut bytes = [0; 32];

        let size = bytes.len().min(public_key.len());

        bytes[..size].copy_from_slice(&public_key[..size]);

        bytes
    }
}
