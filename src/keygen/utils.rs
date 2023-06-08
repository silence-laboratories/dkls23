use sl_mpc_mate::{
    cooridinator::Coordinator,
    nacl::EncryptedData,
    recv_broadcast,
    traits::{HasFromParty, PersistentObject, Round},
};

use crate::utils::Init;

use super::{KeygenError, KeygenParty, KeygenPartyKeys};
///
pub fn setup_keygen<const T: usize, const N: usize>(
    n_i_list: Option<[usize; N]>,
) -> Result<(Vec<KeygenParty<Init>>, Coordinator), KeygenError> {
    let mut coord = Coordinator::new(N, 4 + 4);
    let mut rng = rand::thread_rng();
    let soft_spoken_k = 2;

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

/// Execute one round of DKG protocol
pub fn run_round<I, N, R, M, E>(coord: &mut Coordinator, actors: Vec<R>, round: usize) -> Vec<N>
where
    R: Round<Input = Vec<I>, Output = std::result::Result<(N, M), E>>,
    I: PersistentObject + Clone,
    M: PersistentObject,
    E: std::fmt::Debug,
{
    let msgs = recv_broadcast(coord, round);

    actors
        .into_iter()
        .map(|actor| {
            let (actor, msg) = actor.process(msgs.clone()).unwrap();

            if round < coord.max_round() {
                coord.send(round + 1, msg.to_bytes().unwrap()).unwrap();
            }

            actor
        })
        .collect()
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

// Utility function to process all rounds of keygen, given initialized participants and public keys list.
// fn process_keygen<const N: usize>(
//     actors0: Vec<KeygenParty<Init>>,
//     mut coord: Coordinator,
// ) -> ([KeygenParty<R4>; N], [Keyshare; N]) {
//     let actors1 = run_round(&mut coord, actors0, 0);
//     let actors2 = run_round(&mut coord, actors1, 1);
//     let actors3 = run_round(&mut coord, actors2, 2);
//     let actors4 = run_round(&mut coord, actors3, 3);

//     let keyshares = run_round(&mut coord, actors4.clone(), 4);

//     (actors4.try_into().unwrap(), keyshares.try_into().unwrap())
// }
