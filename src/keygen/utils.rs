#![allow(unused_imports)]

use std::array;

use k256::{NonZeroScalar, ProjectivePoint};
use rand::prelude::*;
// use rayon::prelude::*;
use sl_mpc_mate::{math::birkhoff_coeffs, message::*, state::Env, state::*};

#[cfg(test)]
use sl_oblivious::{
    soft_spoken::{ReceiverOTSeed, SenderOTSeed},
    soft_spoken_mod::{KAPPA_DIV_SOFT_SPOKEN_K, SOFT_SPOKEN_Q},
};

use crate::{
    setup::keygen::{SetupBuilder, ValidatedSetup},
    setup::SETUP_MESSAGE_TAG,
    utils::Init,
};

use super::{messages::Keyshare, KeygenError};

/// Get the index of the message for the given party id.
///
/// This is indexing is when a party wants to get message
/// from id list, it's own id is not included in the list.
///
/// # Note
/// For e.g if party id is 1 and there are 3 parties, then
/// the id list will be `[0, 2]` and the index of the vsot
/// message for party 0 will be 0, and for party 2 will be 1.
///
pub(crate) fn get_idx_from_id(current_party_id: u8, for_party_id: u8) -> u8 {
    if for_party_id > current_party_id {
        for_party_id - 1
    } else {
        for_party_id
    }
}

#[allow(dead_code)]
pub(crate) fn check_secret_recovery(
    x_i_list: &[NonZeroScalar],
    rank_list: &[u8],
    big_s_list: &[ProjectivePoint],
    public_key: &ProjectivePoint,
) -> Result<(), KeygenError> {
    // Checking if secret recovery works
    let mut party_params_list = x_i_list
        .iter()
        .zip(rank_list)
        .zip(big_s_list)
        .collect::<Vec<((&NonZeroScalar, &u8), &ProjectivePoint)>>();

    party_params_list.sort_by_key(|((_, n_i), _)| *n_i);

    let params = party_params_list
        .iter()
        .map(|((x_i, n_i), _)| (**x_i, **n_i as usize))
        .collect::<Vec<_>>();

    let sorted_big_s_list = party_params_list
        .iter()
        .map(|((_, _), big_s_i)| *big_s_i)
        .collect::<Vec<_>>();

    let betta_vector = birkhoff_coeffs(params.as_slice());
    let public_key_point = sorted_big_s_list
        .iter()
        .zip(betta_vector.iter())
        .fold(ProjectivePoint::IDENTITY, |acc, (point, betta_i)| {
            acc + *point * betta_i
        });

    println!("Checking public key!");
    (public_key == &public_key_point)
        .then_some(())
        .ok_or(KeygenError::PublicKeyMismatch)
}

// #[cfg(test)]
// pub(crate) fn check_all_but_one_seeds(
//     seed_ot_sender: &SenderOTSeed,
//     seed_ot_receiver: &ReceiverOTSeed,
// ) {
//     for i in 0..KAPPA_DIV_SOFT_SPOKEN_K {
//         let sender_pad = &seed_ot_sender.one_time_pad_enc_keys[i];
//         let receiver_pad = &seed_ot_receiver.one_time_pad_dec_keys[i];
//         let choice = seed_ot_receiver.random_choices[i];

//         println!("sender pad len:{}", sender_pad.len());
//         println!("receiver pad len:{}", receiver_pad.len());

//         for j in 0..SOFT_SPOKEN_Q {
//             if j as u8 == choice {
//                 continue;
//             }
//             assert_eq!(sender_pad[j], receiver_pad[j]);
//         }
//     }
// }

#[cfg(test)]
pub(crate) fn setup_keygen<const T: usize, const N: usize>(
    n_i_list: Option<[usize; N]>,
) -> Vec<(ValidatedSetup, [u8; 32])> {
    let mut rng = rand::thread_rng();

    let instance = InstanceId::from(rng.gen::<[u8; 32]>());

    // signing key to sing the setup message
    let setup_sk = SigningKey::from_bytes(&rng.gen());
    let setup_vk = setup_sk.verifying_key();
    let setup_pk = setup_vk.to_bytes();

    let setup_msg_id = MsgId::new(&instance, &setup_pk, None, SETUP_MESSAGE_TAG);

    // a signing key for each party.
    let party_sk: [SigningKey; N] = array::from_fn(|_| SigningKey::from_bytes(&rng.gen()));

    // Create a setup message. In a real world,
    // this part will be created by an intiator.
    // The setup message contail public keys of
    // all parties that will participate in this
    // protocol execution.
    let mut setup = n_i_list
        .unwrap_or([0; N])
        .into_iter()
        .enumerate()
        .fold(SetupBuilder::new(), |setup, p| {
            let vk = party_sk[p.0].verifying_key();
            setup.add_party(p.1 as u8, &vk)
        })
        .build(&setup_msg_id, 100, T as u8, &setup_sk)
        .unwrap();

    party_sk
        .into_iter()
        .map(|party_sk| {
            ValidatedSetup::decode(&mut setup, &instance, &setup_vk, party_sk, |_, _, _| true)
                .unwrap()
        })
        .map(|setup| (setup, rng.gen()))
        .collect::<Vec<_>>()
}

#[cfg(test)]
pub(crate) async fn gen_keyshares(n_i_list: Option<[usize; 3]>) -> Vec<Keyshare> {
    let coord = sl_mpc_mate::coord::SimpleMessageRelay::new();

    let mut parties = tokio::task::JoinSet::new();
    for (setup, seed) in setup_keygen::<2, 3>(n_i_list).into_iter() {
        parties.spawn(crate::keygen::run(setup, seed, coord.connect()));
    }

    let mut shares = vec![];

    while let Some(fini) = parties.join_next().await {
        if let Err(ref err) = fini {
            println!("error {err:?}");
        } else {
            match fini.unwrap() {
                Err(err) => panic!("err {:?}", err),
                Ok(share) => shares.push(share),
            }
        }
    }

    shares.sort_by_key(|share| share.party_id);

    shares
}
