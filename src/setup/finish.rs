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

const DEFAULT_TTL: u64 = 100; // smaller timeout might fail tests

pub struct SetupMessage<SK = NoSigningKey, VK = NoVerifyingKey, MS = NoSignature, PS = PreSign> {
    party_idx: usize,
    sk: SK,
    vk: Vec<VK>,
    instance: InstanceId,
    ttl: Duration,
    hash: [u8; 32],
    pre: PS,
    marker: PhantomData<MS>,
}

impl<SK, VK, MS, PS> SetupMessage<SK, VK, MS, PS> {
    pub fn new(instance: InstanceId, party_idx: usize, sk: SK, vk: Vec<VK>, pre: PS) -> Self {
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

    pub fn with_hash(mut self, hash: [u8; 32]) -> Self {
        self.hash = hash;
        self
    }

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
        self.party_idx
    }

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
    fn pre_signature(&self) -> &PreSign {
        &self.pre
    }

    fn message_hash(&self) -> [u8; 32] {
        self.hash
    }
}
