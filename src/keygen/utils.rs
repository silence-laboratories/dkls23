use k256::{NonZeroScalar, ProjectivePoint};
use rayon::prelude::{IntoParallelIterator, ParallelIterator};
use sl_mpc_mate::{
    cooridinator::Coordinator,
    math::birkhoff_coeffs,
    nacl::EncryptedData,
    recv_broadcast,
    traits::{HasFromParty, PersistentObject, Round},
};
use sl_oblivious::soft_spoken::{self, ReceiverOTSeed, SenderOTSeed};

use crate::{
    soft_spoken_ot_mod::{KAPPA, SOFT_SPOKEN_K, SOFT_SPOKEN_Q},
    utils::Init,
};

use super::{messages::Keyshare, KeygenError, KeygenParty, KeygenPartyKeys, R6};
///
pub fn setup_keygen<const T: usize, const N: usize>(
    n_i_list: Option<[usize; N]>,
    soft_spoken_k: u8,
) -> Result<(Vec<KeygenParty<Init>>, Coordinator), KeygenError> {
    let mut coord = Coordinator::new(N, 4 + 4);
    let mut rng = rand::thread_rng();

    // Initializing the keygen for each party.
    let actors = n_i_list
        .unwrap_or([0; N])
        .into_iter()
        .map(|n_i| {
            // Generate or load from persistent storage
            // set of party's keys
            let party_keys = KeygenPartyKeys::new(&mut rng);

            // extract public keys
            let actor_pubkeys = party_keys.public_keys();

            // and send them to the coordinator and get
            // assigned pid in range 0..N
            let pid = coord.send(0, actor_pubkeys.to_bytes().unwrap()).unwrap();

            KeygenParty::new(T, N, pid, n_i, &party_keys, soft_spoken_k, &mut rng).unwrap()
        })
        .collect();

    Ok((actors, coord))
}

/// Execute one round of DKG protocol, execute parties in parallel
pub fn run_round<I, N, R, M, E>(coord: &mut Coordinator, actors: Vec<R>, round: usize) -> Vec<N>
where
    R: Round<Input = Vec<I>, Output = std::result::Result<(N, M), E>>,
    I: PersistentObject + Clone + Sync,
    M: PersistentObject,
    E: std::fmt::Debug,
    Vec<R>: IntoParallelIterator<Item = R>,
    N: Send,
{
    let msgs = recv_broadcast(coord, round);

    let (actors, msgs): (Vec<N>, Vec<M>) = actors
        .into_par_iter()
        .map(|actor| {
            let (actor, msg) = actor.process(msgs.clone()).unwrap();

            (actor, msg)
        })
        .unzip();

    if round < coord.max_round() {
        msgs.iter().for_each(|msg| {
            coord.send(round + 1, msg.to_bytes().unwrap()).unwrap();
        })
    }
    actors
}

pub(crate) trait HasVsotMsg: HasFromParty {
    /// Get the index of the vsot message for the given party id.
    fn get_idx_from_id(&self, party_id: usize) -> usize {
        if party_id > self.get_pid() {
            party_id - 1
        } else {
            party_id
        }
    }
    fn get_vsot_msg(&self, party_id: usize) -> &EncryptedData;
}

/// Utility function to process all rounds of keygen
pub fn process_keygen<const T: usize, const N: usize>(
    n_i_list: Option<[usize; N]>,
) -> ([KeygenParty<R6>; N], [Keyshare; N]) {
    let (parties, mut coord) = setup_keygen::<T, N>(n_i_list, SOFT_SPOKEN_K as u8).unwrap();
    let parties1 = run_round(&mut coord, parties, 0);
    let parties2 = run_round(&mut coord, parties1, 1);
    let parties3 = run_round(&mut coord, parties2, 2);
    let parties4 = run_round(&mut coord, parties3, 3);
    let parties5 = run_round(&mut coord, parties4, 4);
    let parties6 = run_round(&mut coord, parties5, 5);
    let keyshares = run_round(&mut coord, parties6.clone(), 6);

    (
        parties6
            .try_into()
            .map_err(|_| "Failed to convert parties to array")
            .unwrap(),
        keyshares
            .try_into()
            .map_err(|_| "Failed to convert keyshares to array")
            .unwrap(),
    )
}

pub(crate) fn check_secret_recovery(
    x_i_list: &[NonZeroScalar],
    rank_list: &[usize],
    big_s_list: &[ProjectivePoint],
    public_key: &ProjectivePoint,
) -> Result<(), KeygenError> {
    // Checking if secret recovery works
    let mut party_params_list = x_i_list
        .iter()
        .zip(rank_list)
        .zip(big_s_list)
        .collect::<Vec<((&NonZeroScalar, &usize), &ProjectivePoint)>>();

    party_params_list.sort_by_key(|((_, n_i), _)| *n_i);

    let params = party_params_list
        .iter()
        .map(|((x_i, n_i), _)| (**x_i, **n_i))
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

    (public_key == &public_key_point)
        .then_some(())
        .ok_or(KeygenError::PublicKeyMismatch)
}

// def check_all_but_one_seeds(seed_ot_sender: SenderOTSeed, seed_ot_receiver: ReceiverOTSeed):
//     for i in range(KAPPA//SOFT_SPOKEN_K):
//         sender_pad = seed_ot_sender.one_time_pad_encryption_keys[i]
//         receiver_pad = seed_ot_receiver.one_time_pad_decryption_keys[i]
//         choice = seed_ot_receiver.random_choices[i]

//         for j in range(SOFT_SPOKEN_Q):
//             if j == choice:
//                 continue
//             assert sender_pad[j] == receiver_pad[j]

pub(crate) fn check_all_but_one_seeds(
    seed_ot_sender: &SenderOTSeed,
    seed_ot_receiver: &ReceiverOTSeed,
) {
    for i in 0..KAPPA / SOFT_SPOKEN_K {
        let sender_pad = &seed_ot_sender.one_time_pad_enc_keys[i];
        let receiver_pad = &seed_ot_receiver.one_time_pad_dec_keys[i];
        let choice = seed_ot_receiver.random_choices[i];

        println!("sender pad len:{}", sender_pad.len());
        println!("receiver pad len:{}", receiver_pad.len());

        for j in 0..SOFT_SPOKEN_Q {
            if j as u8 == choice {
                continue;
            }
            assert_eq!(sender_pad[j], receiver_pad[j]);
        }
    }
}
