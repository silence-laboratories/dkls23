// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

#![allow(missing_docs)]

use std::marker::PhantomData;
use std::time::Duration;

use sha2::{Digest, Sha256};
use signature::{SignatureEncoding, Signer, Verifier};

use sl_mpc_mate::message::InstanceId;

const DEFAULT_TTL: u64 = 100; // smaller timeout might fail tests

use crate::setup::{
    keys::{NoSignature, NoSigningKey, NoVerifyingKey},
    KeygenSetupMessage, ProtocolParticipant,
};

pub struct SetupMessage<SK = NoSigningKey, VK = NoVerifyingKey, MS = NoSignature> {
    n: usize,
    t: usize,
    party_id: usize,
    ranks: Vec<u8>,
    sk: SK,
    vk: Vec<VK>,
    key_id: Option<[u8; 32]>,
    inst: InstanceId,
    ttl: Duration,
    marker: PhantomData<MS>,
}

impl<SK, VK, MS> SetupMessage<SK, VK, MS> {
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

    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    pub fn with_key_id(mut self, key_id: Option<[u8; 32]>) -> Self {
        self.key_id = key_id;
        self
    }

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

    fn total_participants(&self) -> usize {
        self.n
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

impl<SK, VK, MS> KeygenSetupMessage for SetupMessage<SK, VK, MS>
where
    SK: Signer<MS>,
    MS: SignatureEncoding,
    VK: AsRef<[u8]> + Verifier<MS>,
{
    fn threshold(&self) -> u8 {
        self.t as u8
    }

    fn participant_rank(&self, index: usize) -> u8 {
        self.ranks[index]
    }

    fn derive_key_id(&self, public_key: &[u8]) -> [u8; 32] {
        self.key_id
            .unwrap_or_else(|| Sha256::digest(public_key).into())
    }
}
