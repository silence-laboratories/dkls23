// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

mod constants;
mod dsg;
mod messages;
mod types;

pub use dsg::*;
pub use types::*;

pub use messages::PreSign;

pub use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

use crate::setup::{ProtocolParticipant, ABORT_MESSAGE_TAG};
use sl_mpc_mate::message::MsgId;

/// DSG variant
pub enum DsgVariant {
    /// SignPre + Finish
    Full,
    /// PreSign only
    PreSign,
    /// Finish only
    Finish,
}

/// Generate message receiver map.
///
/// Call the passed closure for each pair (msg_id, receiver)
///
pub fn message_receivers<S, F>(
    setup: &S,
    variant: DsgVariant,
    mut msg_receiver: F,
) where
    S: ProtocolParticipant,
    F: FnMut(MsgId, &S::MessageVerifier),
{
    setup.all_other_parties().for_each(|p| {
        let vk = setup.verifier(p);

        msg_receiver(setup.msg_id(None, ABORT_MESSAGE_TAG), vk);

        if matches!(variant, DsgVariant::Full | DsgVariant::PreSign) {
            msg_receiver(setup.msg_id(None, constants::DSG_MSG_R1), vk);
            msg_receiver(setup.msg_id(Some(p), constants::DSG_MSG_R2), vk);
            msg_receiver(setup.msg_id(Some(p), constants::DSG_MSG_R3), vk);
        }

        if matches!(variant, DsgVariant::Finish | DsgVariant::Full) {
            msg_receiver(setup.msg_id(None, constants::DSG_MSG_R4), vk);
        }
    })
}

#[cfg(any(test, feature = "test-support"))]
pub use support::*;

#[cfg(any(test, feature = "test-support"))]
mod support {
    use std::{str::FromStr, sync::Arc, time::Duration};

    use derivation_path::DerivationPath;
    use rand::prelude::*;
    use sha2::{Digest, Sha256};

    use sl_mpc_mate::message::*;

    use crate::{
        keygen::Keyshare,
        setup::ProtocolParticipant,
        setup::{
            finish::SetupMessage as FinishSetupMsg, sign::SetupMessage,
            NoSigningKey, NoVerifyingKey,
        },
        sign::PreSign,
        Seed,
    };

    /// Test helper
    pub fn setup_dsg(
        instance: Option<[u8; 32]>,
        shares: &[Arc<Keyshare>],
        chain_path: &str,
    ) -> Vec<(SetupMessage, Seed)> {
        let instance = instance.unwrap_or_else(rand::random);

        let chain_path = DerivationPath::from_str(chain_path).unwrap();

        let t = shares[0].threshold as usize;
        assert!(shares.len() >= t);

        // make sure that first share has rank 0
        assert_eq!(shares[0].get_rank(0), 0);

        let party_vk: Vec<NoVerifyingKey> = shares
            .iter()
            .map(|share| NoVerifyingKey::new(share.party_id as _))
            .collect();

        shares
            .iter()
            .enumerate()
            .map(|(party_idx, share)| {
                SetupMessage::new(
                    InstanceId::new(instance),
                    NoSigningKey,
                    party_idx,
                    party_vk.clone(),
                    share.clone(),
                )
                .with_chain_path(chain_path.clone())
                .with_hash([1; 32])
                .with_ttl(Duration::from_secs(1000))
            })
            .map(|setup| {
                let mixin = [setup.participant_index() as u8 + 1];

                (
                    setup,
                    Sha256::new()
                        .chain_update(instance)
                        .chain_update(b"dsg-party-seed")
                        .chain_update(mixin)
                        .finalize()
                        .into(),
                )
            })
            .collect::<Vec<_>>()
    }

    /// The same as
    pub fn setup_finish_sign(pre_signs: Vec<PreSign>) -> Vec<FinishSetupMsg> {
        let mut rng = rand::thread_rng();

        let instance = InstanceId::from(rng.gen::<[u8; 32]>());

        let party_vk: Vec<NoVerifyingKey> = pre_signs
            .iter()
            .map(|pre| NoVerifyingKey::new(pre.party_id as _))
            .collect();

        pre_signs
            .into_iter()
            .enumerate()
            .map(|(party_idx, pre)| {
                crate::setup::finish::SetupMessage::new(
                    instance,
                    party_idx,
                    NoSigningKey,
                    party_vk.clone(),
                    pre,
                )
            })
            .collect()
    }
}
