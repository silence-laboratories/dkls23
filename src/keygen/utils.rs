#![allow(unused_imports)]

use std::array;

use k256::{NonZeroScalar, ProjectivePoint};
use rand::prelude::*;
// use rayon::prelude::{IntoParallelIterator, ParallelIterator};
use sl_mpc_mate::{
    cooridinator::Coordinator,
    math::birkhoff_coeffs,
    message::*,
    nacl::EncryptedData,
    recv_broadcast,
    state::Env,
    state::*,
    traits::{HasFromParty, PersistentObject, Round},
};

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

use super::{messages::Keyshare, KeygenError, KeygenParty};

// pub fn make_env() -> impl Env {
//     todo!()
// }

///
// pub fn setup_keygen<const T: usize, const N: usize>(
//     n_i_list: Option<[usize; N]>,
// ) -> Result<(Vec<KeygenParty<R1>>, Coordinator), KeygenError> {
//     let mut rng = rand::thread_rng();

//     let instance = InstanceId::new(rng.gen());

//     // signing key to sing the setup message
//     let setup_sk = SigningKey::from_bytes(&rng.gen());
//     let setup_pk = setup_sk.verifying_key().to_bytes();

//     let setup_msg_id = MsgId::new(&instance, &setup_pk, None, SETUP_MESSAGE_TAG);

//     // a signing key for each party.
//     let party_sk: [SigningKey; N] = array::from_fn(|_| SigningKey::from_bytes(&rng.gen()));

//     // Create a setup message. In a real world,
//     // this part will be created by an intiator.
//     // The setup message contail public keys of
//     // all parties that will participate in this
//     // protocol execution.
//     let mut setup = n_i_list
//         .unwrap_or([0; N])
//         .into_iter()
//         .enumerate()
//         .fold(SetupBuilder::new(), |setup, p| {
//             let vk = party_sk[p.0].verifying_key();
//             let pk = vk.as_bytes();
//             setup.add_party(p.1 as u8, pk)
//         })
//         .build(&setup_msg_id, 100, T as u8, &setup_sk)
//         .unwrap();

//     // validate the setup message and create ValidatedSetup object. It contains
//     // decoded and validated protocol parameters and signing key pair of the party.
//     let validated_setup: [ValidatedSetup; N] = array::from_fn(|i| {
//         ValidatedSetup::decode(&mut setup, &instance, party_sk[i], |_, _, _| true).unwrap()
//     });

//     let mut coord = Coordinator::new(N, 4 + 4);

//     let mut env = make_env();

//     // Initializing the keygen for each party.
//     let actors = n_i_list
//         .unwrap_or([0; N])
//         .into_iter()
//         .map(|n_i| {
//             // // Generate or load from persistent storage
//             // // set of party's keys
//             // let party_keys = PartyKeys::new(&mut rng);

//             // // extract public keys
//             // let actor_pubkeys = party_keys.public_keys();

//             // // and send them to the coordinator and get
//             // // assigned pid in range 0..N
//             // let pid = coord.send(0, actor_pubkeys.to_bytes().unwrap()).unwrap();

//             let seed = rng.gen();

//             KeygenParty::new(validated_setup.clone(), &mut env, seed).unwrap()
//         })
//         .collect();

//     Ok((actors, coord))
// }

/// Execute one round of DKG protocol, execute parties in parallel
#[inline(never)]
pub fn run_round<I, N, R, M, E>(coord: &mut Coordinator, actors: Vec<R>, round: usize) -> Vec<N>
where
    R: Round<Input = Vec<I>, Output = std::result::Result<(N, M), E>>,
    I: PersistentObject + Clone + Sync,
    M: PersistentObject,
    E: std::fmt::Debug,
    //    Vec<R>: IntoParallelIterator<Item = R>,
    N: Send,
{
    let msgs = recv_broadcast(coord, round);

    let (actors, msgs): (Vec<N>, Vec<M>) = actors
        .into_iter()
        .map(|actor| actor.process(msgs.clone()).unwrap())
        .unzip();

    if round < coord.max_round() {
        msgs.iter().for_each(|msg| {
            coord.send(round + 1, msg.to_bytes().unwrap()).unwrap();
        })
    }

    actors
}

pub(crate) trait HasVsotMsg: HasFromParty {
    fn get_vsot_msg(&self, party_id: usize) -> &EncryptedData;
}

/// Get the index of the message for the given party id.
/// This is indexing is when a party wants to get message from id list, it's own id is not included in the list.
/// # Note
/// For e.g if party id is 1 and there are 3 parties, then the id list will be `[0, 2]` and the index of the vsot message
/// for party 0 will be 0, and for party 2 will be 1.
pub fn get_idx_from_id(current_party_id: usize, for_party_id: usize) -> usize {
    if for_party_id > current_party_id {
        for_party_id - 1
    } else {
        for_party_id
    }
}

// /// Utility function to process all rounds of keygen
// pub fn process_keygen<const T: usize, const N: usize>(
//     n_i_list: Option<[usize; N]>,
// ) -> [Keyshare; N] {
//     let (parties, mut coord) = setup_keygen::<T, N>(n_i_list).unwrap();
//     let parties1 = run_round(&mut coord, parties, 0);
//     let parties2 = run_round(&mut coord, parties1, 1);
//     let parties3 = run_round(&mut coord, parties2, 2);
//     let parties4 = run_round(&mut coord, parties3, 3);
//     let parties5 = run_round(&mut coord, parties4, 4);
//     let parties6 = run_round(&mut coord, parties5, 5);

//     let keyshares = run_round(&mut coord, parties6, 6);

//     keyshares
//         .try_into()
//         .map_err(|_| "Failed to convert keyshares to array")
//         .unwrap()
// }

// pub(crate) fn check_secret_recovery(
//     x_i_list: &[NonZeroScalar],
//     rank_list: &[usize],
//     big_s_list: &[ProjectivePoint],
//     public_key: &ProjectivePoint,
// ) -> Result<(), KeygenError> {
//     // Checking if secret recovery works
//     let mut party_params_list = x_i_list
//         .iter()
//         .zip(rank_list)
//         .zip(big_s_list)
//         .collect::<Vec<((&NonZeroScalar, &usize), &ProjectivePoint)>>();

//     party_params_list.sort_by_key(|((_, n_i), _)| *n_i);

//     let params = party_params_list
//         .iter()
//         .map(|((x_i, n_i), _)| (**x_i, **n_i))
//         .collect::<Vec<_>>();

//     let sorted_big_s_list = party_params_list
//         .iter()
//         .map(|((_, _), big_s_i)| *big_s_i)
//         .collect::<Vec<_>>();

//     let betta_vector = birkhoff_coeffs(params.as_slice());
//     let public_key_point = sorted_big_s_list
//         .iter()
//         .zip(betta_vector.iter())
//         .fold(ProjectivePoint::IDENTITY, |acc, (point, betta_i)| {
//             acc + *point * betta_i
//         });

//     (public_key == &public_key_point)
//         .then_some(())
//         .ok_or(KeygenError::PublicKeyMismatch)
// }

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
