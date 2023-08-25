use std::array;

use k256::AffinePoint;
use rand::prelude::*;

use sl_mpc_mate::{message::*, HashBytes};

use crate::{
    Seed,
    keygen::Keyshare,
    setup::{
        sign::{SetupBuilder, ValidatedSetup},
        SETUP_MESSAGE_TAG,
    },
};

/// Pairwise MTA
pub mod pairwise_mta;

mod dsg;
mod messages;
mod types;

pub use dsg::*;
pub use messages::*;
pub use types::*;

/// Test helper
pub fn setup_dsg(pk: &AffinePoint, shares: &[Keyshare]) -> Vec<(ValidatedSetup, Seed)> {
    let mut rng = rand::thread_rng();

    let instance = InstanceId::from(rng.gen::<[u8; 32]>());

    // signing key to sing the setup message
    let setup_sk = SigningKey::from_bytes(&rng.gen());
    let setup_vk = setup_sk.verifying_key();
    let setup_pk = setup_vk.to_bytes();

    let setup_msg_id = MsgId::new(&instance, &setup_pk, None, SETUP_MESSAGE_TAG);

    const T: usize = 2;

    // a signing key for each party.
    let party_sk: [SigningKey; T] = array::from_fn(|_| SigningKey::from_bytes(&rng.gen()));

    let mut setup = (0..T)
        .fold(SetupBuilder::new(pk), |setup, p| {
            let vk = party_sk[p].verifying_key();
            setup.add_party(vk)
        })
        .with_hash(HashBytes::new([1; 32]))
        .build(&setup_msg_id, 100, &setup_sk)
        .unwrap();

    party_sk
        .into_iter()
        .enumerate()
        .map(|(idx, party_sk)| {
            ValidatedSetup::decode(&mut setup, &instance, &setup_vk, party_sk, |_, _| {
                Some(shares[idx].clone())
            })
            .unwrap()
        })
        .map(|setup| (setup, rng.gen()))
        .collect::<Vec<_>>()
}
