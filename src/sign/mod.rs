use k256::AffinePoint;
use rand::prelude::*;

use sl_mpc_mate::{message::*, HashBytes};

use crate::{
    keygen::Keyshare,
    setup::{sign::SetupBuilder, SETUP_MESSAGE_TAG},
    Seed,
};
use derivation_path::DerivationPath;

pub use crate::setup::sign::ValidatedSetup;

/// Pairwise MTA
pub mod pairwise_mta;

mod constants;
mod dsg;
mod messages;
mod types;

pub use dsg::*;
pub use types::*;

/// Test helper
pub fn setup_dsg(
    pk: &AffinePoint,
    shares: &[Keyshare],
    chain_path: &DerivationPath,
) -> Vec<(ValidatedSetup, Seed)> {
    let mut rng = rand::thread_rng();

    let instance = InstanceId::from(rng.gen::<[u8; 32]>());

    // signing key to sing the setup message
    let setup_sk = SigningKey::from_bytes(&rng.gen());
    let setup_vk = setup_sk.verifying_key();
    let setup_pk = setup_vk.to_bytes();

    let setup_msg_id = MsgId::new(&instance, &setup_pk, None, SETUP_MESSAGE_TAG);

    // a signing key for each party.
    let party_sk: Vec<SigningKey> = (0..shares.len())
        .map(|_| SigningKey::from_bytes(&rng.gen()))
        .collect();

    let mut setup = party_sk
        .iter()
        .fold(
            SetupBuilder::new(pk).chain_path(Some(chain_path)),
            |setup, sk| {
                let vk = sk.verifying_key();
                setup.add_party(vk)
            },
        )
        .with_hash(HashBytes::new([1; 32]))
        .build(&setup_msg_id, 100, &setup_sk)
        .unwrap();

    party_sk
        .into_iter()
        .enumerate()
        .map(|(idx, party_sk)| {
            ValidatedSetup::decode(&mut setup, &instance, &setup_vk, party_sk, |_| {
                Some(shares[idx].clone())
            })
            .unwrap()
        })
        .map(|setup| (setup, rng.gen()))
        .collect::<Vec<_>>()
}
