#![allow(dead_code, unused_imports)]
//! Distributed sign generation protocol.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use k256::{
    ecdsa::Signature,
    elliptic_curve::{
        group::GroupEncoding, ops::Reduce, point::AffineCoordinates, subtle::ConstantTimeEq,
        PrimeField,
    },
    sha2::{Digest, Sha256},
    ProjectivePoint, Scalar, Secp256k1, U256,
};
use rand::{rngs::StdRng, CryptoRng, Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use tokio::task::{JoinError, JoinSet};

use sl_mpc_mate::{coord::MessageRelay, math::birkhoff_coeffs, message::*, HashBytes, SessionId};

use sl_oblivious::soft_spoken_mod::Round1Output;

use crate::{
    keygen::{get_idx_from_id, messages::Keyshare},
    setup::sign::ValidatedSetup,
    sign::{
        pairwise_mta::{MtaRecR1, MtaRound2Output, PairwiseMtaRec, PairwiseMtaSender},
        SignMsg1, SignMsg3, SignMsg4,
    },
    utils::{
        // calculate_final_session_id,
        // decrypt_point,
        parse_raw_sign,
        verify_final_signature,
    },
    BadPartyIndex, Pairs, Seed,
};

use super::{pairwise_mta::MtaSendR0, SignError};

const DSG_MSG_R1: MessageTag = MessageTag::tag(1);
const DSG_MSG_R2: MessageTag = MessageTag::tag(2);
const DSG_MSG_R3: MessageTag = MessageTag::tag(3);

fn find_pair<K: Eq, T>(pairs: &[(K, T)], party_id: K) -> Result<&T, BadPartyIndex> {
    pairs
        .iter()
        .find(|(p, _)| *p == party_id)
        .map(|(_, v)| v)
        .ok_or(BadPartyIndex)
}

fn pop_pair<K: Eq, T>(pairs: &mut Vec<(K, T)>, party_id: K) -> Result<T, BadPartyIndex> {
    let pos = pairs
        .iter()
        .position(|(p, _)| *p == party_id)
        .ok_or(BadPartyIndex)?;

    Ok(pairs.remove(pos).1)
}

// /// Distributed Signer Party
// pub struct SignerParty<T> {
//     params: SignParams,
//     state: T,
//     times: Vec<(u32, Duration)>,
// }

/// Initial state of Signer party
pub struct Init;

/// Round 1 state of Signer party
pub struct R1 {
    commitments: HashMap<usize, (SessionId, HashBytes)>,
    big_r_i: ProjectivePoint,
    party_id_list: Vec<usize>,
}

/// Round 2 state of Signer party
/// State before processing all SignMsg2 messages
pub struct R2 {
    final_session_id: SessionId,
    mta_receivers: HashMap<usize, PairwiseMtaRec<MtaRecR1>>,
    mta_senders: HashMap<usize, PairwiseMtaSender<MtaSendR0>>,
    digest_i: HashBytes,
    x_i: Scalar,
    big_x_i: ProjectivePoint,
    remaining_parties: HashSet<usize>,
    big_r_i: ProjectivePoint,
    commitments: HashMap<usize, (SessionId, HashBytes)>,
    sender_additive_shares: Vec<[Scalar; 2]>,
}

/// State of Signer party after processing all SignMsg2 messages
/// and before sending SignMsg3 messages
pub struct R3 {
    final_session_id: SessionId,
    mta_receivers: HashMap<usize, PairwiseMtaRec<MtaRecR1>>,
    digest_i: HashBytes,
    x_i: Scalar,
    big_x_i: ProjectivePoint,
    big_r_i: ProjectivePoint,
    commitments: HashMap<usize, (SessionId, HashBytes)>,
    sender_additive_shares: Vec<[Scalar; 2]>,
}

/// State of Signer party after processing all SignMsg3 messages
pub struct R4 {
    final_session_id: SessionId,
    big_r: ProjectivePoint,
    sender_additive_shares: Vec<[Scalar; 2]>,
    receiver_additive_shares: Vec<[Scalar; 2]>,
    x_i: Scalar,
}

/// State of Signer party after generating partial signatures.
pub struct R5 {
    final_session_id: SessionId,
    big_r: ProjectivePoint,
    //    recid: u8,
    s_0: Scalar,
    s_1: Scalar,
    msg_hash: [u8; 32],
}

fn recv_p2p_messages(
    setup: &ValidatedSetup,
    tag: MessageTag,
    relay: &MessageRelay,
) -> JoinSet<Result<(Vec<u8>, usize), SignError>> {
    let mut js = JoinSet::new();
    let me = Some(setup.party_idx());
    setup.other_parties_iter().for_each(|(p, vk)| {
        // P2P message from party VK (p) to me
        let msg_id = setup.msg_id_from(vk, me, tag);
        let relay = relay.clone();

        js.spawn(async move {
            let msg = relay
                .recv(msg_id, 10)
                .await
                .ok_or(SignError::InvalidMessage)?;
            Ok::<_, SignError>((msg, p))
        });
    });

    js
}

fn recv_broadcast_messages(
    setup: &ValidatedSetup,
    tag: MessageTag,
    relay: &MessageRelay,
) -> JoinSet<Result<(Vec<u8>, usize), SignError>> {
    let mut js = JoinSet::new();
    setup.other_parties_iter().for_each(|(party_idx, vk)| {
        // broadcast message from party `p'
        let msg_id = setup.msg_id_from(vk, None, tag);
        let relay = relay.clone();

        js.spawn(async move {
            let msg = relay
                .recv(msg_id, 10)
                .await
                .ok_or(SignError::InvalidMessage)?;
            Ok::<_, SignError>((msg, party_idx))
        });
    });

    js
}

fn decode_signed_message<T: bincode::Decode>(
    msg: Result<Result<(Vec<u8>, usize), SignError>, JoinError>,
    setup: &ValidatedSetup,
) -> Result<(T, usize), SignError> {
    let (mut msg, party_idx) = msg.map_err(|_| SignError::InvalidMessage)??; // it's ugly, I know

    let msg = Message::from_buffer(&mut msg)?;
    let msg = msg.verify_and_decode(&setup.party_verifying_key(party_idx).unwrap())?;

    Ok((msg, party_idx))
}

fn decode_encrypted_message<T: bincode::Decode>(
    msg: Result<Result<(Vec<u8>, usize), SignError>, JoinError>,
    secret: &ReusableSecret,
    enc_pub_keys: &[(usize, PublicKey)],
) -> Result<(T, usize), SignError> {
    let (mut msg, party_id) = msg.map_err(|_| SignError::InvalidMessage)??; // it's ugly, I know

    let mut msg = Message::from_buffer(&mut msg)?;
    let msg = msg.decrypt_and_decode(
        MESSAGE_HEADER_SIZE,
        secret,
        find_pair(enc_pub_keys, party_id)?,
    )?;

    Ok((msg, party_id))
}

///
pub async fn run(setup: ValidatedSetup, seed: Seed, relay: MessageRelay) -> Result<(), SignError> {
    let mut rng = ChaCha20Rng::from_seed(seed);

    // For DKG part_id == part_idx.
    //
    // For DSG: party_idx is an index of the party in the setup messages.
    //
    // In the first message a party sends its part_id from Keyshare and
    // its encryption public key
    //
    let my_party_id = setup.keyshare().party_id;
    let my_party_idx = setup.party_idx();

    let mut commitments = vec![];
    let mut enc_pub_keys = vec![];

    let session_id: SessionId = SessionId::random(&mut rng);
    let phi_i: Scalar = Scalar::generate_biased(&mut rng);
    let k_i: Scalar = Scalar::generate_biased(&mut rng);
    let blind_factor: [u8; 32] = rng.gen();

    let enc_keys = ReusableSecret::random_from_rng(&mut rng);

    let big_r_i = ProjectivePoint::GENERATOR * k_i;
    let commitment_r_i = hash_commitment_r_i(&session_id, &big_r_i, &blind_factor);

    commitments.push((setup.party_idx(), (session_id, commitment_r_i)));

    relay.send(Builder::<Signed>::encode(
        &setup.msg_id(None, DSG_MSG_R1),
        10,
        setup.signing_key(),
        &SignMsg1 {
            session_id: Opaque::from(session_id),
            commitment_r_i: Opaque::from(commitment_r_i),
            party_id: setup.keyshare().party_id,
            enc_pk: Opaque::from(PublicKey::from(&enc_keys).to_bytes()),
        },
    )?);

    // vector of pairs (party_idx, party_id)
    let mut party_idx_to_id_map = vec![(my_party_idx, my_party_id)];

    let mut js = recv_broadcast_messages(&setup, DSG_MSG_R1, &relay);
    while let Some(msg) = js.join_next().await {
        let (msg, party_idx) = decode_signed_message::<SignMsg1>(msg, &setup)?;

        party_idx_to_id_map.push((party_idx, msg.party_id));
        commitments.push((party_idx, (*msg.session_id, *msg.commitment_r_i)));
        enc_pub_keys.push((party_idx, PublicKey::from(*msg.enc_pk)));
    }

    party_idx_to_id_map.sort_by_key(|(_, pid)| *pid);

    let find_party_id = |idx: usize| {
        party_idx_to_id_map
            .iter()
            .find(|(i, _)| *i == idx)
            .map(|(_, p)| *p)
    };

    commitments.sort_by_key(|(idx, _)| *idx);

    let final_session_id = SessionId::new(
        commitments
            .iter()
            .fold(Sha256::new(), |hash, (_, (sid, _))| hash.chain_update(sid))
            .finalize()
            .into(),
    );

    let mut mta_receivers = setup
        .other_parties_iter()
        .map(|(party_idx, _vk)| {
            let sender_id = find_party_id(party_idx).unwrap();

            let sid = mta_session_id(&final_session_id, sender_id, my_party_id);

            let sender_ot_results =
                &setup.keyshare().seed_ot_senders[get_idx_from_id(my_party_id, sender_id) as usize];

            let mta_receiver = PairwiseMtaRec::new(sid, sender_ot_results, &mut rng);

            let (mta_receiver, mta_msg_1) = mta_receiver.process(&phi_i);

            relay.send(Builder::<Encrypted>::encode(
                &setup.msg_id(Some(party_idx), DSG_MSG_R2),
                100,
                &enc_keys,
                find_pair(&enc_pub_keys, party_idx)?,
                &mta_msg_1,
            )?);

            Ok((party_idx as u8, mta_receiver))
        })
        .collect::<Result<Vec<_>, SignError>>()?;

    let mut mta_senders = setup
        .other_parties_iter()
        .map(|(party_idx, _vk)| {
            let receiver_id = find_party_id(party_idx).unwrap();

            let sid = mta_session_id(&final_session_id, my_party_id, receiver_id);

            let seed_ot_results = &setup.keyshare().seed_ot_receivers
                [get_idx_from_id(my_party_id, receiver_id) as usize];

            let sender = PairwiseMtaSender::new(sid, seed_ot_results, &mut rng);

            Ok((party_idx as u8, sender))
        })
        .collect::<Result<Vec<_>, SignError>>()?;

    let digest_i = {
        let mut h = Sha256::new();
        for (key, (sid_i, commitment_i)) in &commitments {
            h.update((*key as u32).to_be_bytes());
            h.update(sid_i);
            h.update(commitment_i);
        }

        HashBytes::new(h.finalize().into())
    };

    let mu_i = get_mu_i(setup.keyshare(), &party_idx_to_id_map, digest_i);

    let coeff = if setup.keyshare().rank_list.iter().all(|&r| r == 0) {
        get_lagrange_coeff(&setup.keyshare(), &party_idx_to_id_map)
    } else {
        let betta_coeffs = get_birkhoff_coefficients(setup.keyshare(), &party_idx_to_id_map);

        *betta_coeffs
            .get(&(my_party_id as usize))
            .expect("betta_i not found")
    };

    let x_i = coeff * *setup.keyshare().s_i + mu_i;
    let big_x_i = ProjectivePoint::GENERATOR * x_i;

    let mut sender_additive_shares = vec![];

    let mut js = recv_p2p_messages(&setup, DSG_MSG_R2, &relay);
    while let Some(msg) = js.join_next().await {
        let (msg1, party_idx) =
            decode_encrypted_message::<Round1Output>(msg, &enc_keys, &enc_pub_keys)?;

        let mta_sender = pop_pair(&mut mta_senders, party_idx as u8)?;

        let (additive_shares, mta_msg2) = mta_sender.process((x_i, k_i, msg1));

        let gamma0 = ProjectivePoint::GENERATOR * additive_shares[0];
        let gamma1 = ProjectivePoint::GENERATOR * additive_shares[1];

        let msg3 = SignMsg3 {
            session_id: Opaque::from(final_session_id),
            mta_msg2,
            digest_i: Opaque::from(digest_i),
            big_x_i: Opaque::from(big_x_i),
            big_r_i: Opaque::from(big_r_i),
            blind_factor: Opaque::from(blind_factor),
            gamma0: Opaque::from(gamma0),
            gamma1: Opaque::from(gamma1),
        };

        relay.send(Builder::<Encrypted>::encode(
            &setup.msg_id(Some(party_idx), DSG_MSG_R3),
            100,
            &enc_keys,
            find_pair(&enc_pub_keys, party_idx)?,
            &msg3,
        )?);

        sender_additive_shares.push(additive_shares);
    }

    let mut big_r_star = ProjectivePoint::IDENTITY;
    let mut sum_x_j = ProjectivePoint::IDENTITY;
    let mut sum_gamma_0 = ProjectivePoint::IDENTITY;
    let mut sum_gamma_1 = ProjectivePoint::IDENTITY;
    let mut sum_big_t_0 = Scalar::ZERO;
    let mut sum_big_t_1 = Scalar::ZERO;

    let mut receiver_additive_shares = vec![];

    let mut js = recv_p2p_messages(&setup, DSG_MSG_R3, &relay);
    while let Some(msg) = js.join_next().await {
        let (msg3, party_idx) =
            decode_encrypted_message::<SignMsg3>(msg, &enc_keys, &enc_pub_keys)?;

        let mta_receiver = pop_pair(&mut mta_receivers, party_idx as u8)?;

        let receiver_additive_shares_i = mta_receiver
            .process(msg3.mta_msg2)
            .map_err(SignError::MtaError)?;

        receiver_additive_shares.push(receiver_additive_shares_i);

        let (sid_i, commitment) = find_pair(&commitments, party_idx)?;

        if !verify_commitment_r_i(sid_i, &msg3.big_r_i, &msg3.blind_factor, commitment) {
            return Err(SignError::InvalidCommitment);
        }

        if digest_i.ct_eq(&msg3.digest_i).unwrap_u8() != 1 {
            return Err(SignError::InvalidDigest);
        }

        big_r_star += &*msg3.big_r_i;
        sum_x_j += &*msg3.big_x_i;
        sum_gamma_0 += &*msg3.gamma0;
        sum_gamma_1 += &*msg3.gamma1;
        sum_big_t_0 += &receiver_additive_shares_i[0];
        sum_big_t_1 += &receiver_additive_shares_i[1];
    }

    let big_t_0 = &ProjectivePoint::GENERATOR * &sum_big_t_0;
    let big_t_1 = &ProjectivePoint::GENERATOR * &sum_big_t_1;
    let big_x_star_i = setup.keyshare().public_key + (-big_x_i);
    // new var
    let big_r = big_r_star + big_r_i;

    // Checks
    if sum_x_j != big_x_star_i {
        return Err(SignError::FailedCheck("sum_x_j != big_x_star_i"));
    }

    if sum_gamma_0 != (&big_x_star_i * &phi_i + (-&big_t_0)) {
        return Err(SignError::FailedCheck(
            "sum_gamma_0 != (self.phi_i * big_x_star_i + (-big_t))",
        ));
    }

    if sum_gamma_1 != (&big_r_star * &phi_i + (-big_t_1)) {
        return Err(SignError::FailedCheck(
            "sum_gamma_1 != (self.phi_i * big_r_star + (-big_t_1)",
        ));
    }

    Ok(())
}

// impl Round for SignerParty<R1> {
//     type Input = Vec<SignMsg1>;

//     type Output = Result<(SignerParty<R2>, Vec<SignMsg2>), SignError>;

//     fn process(self, msgs1: Self::Input) -> Self::Output {
//         let start_time = Instant::now();

//         let msgs1 = validate_input_messages(
//             msgs1,
//             self.params.keyshare.threshold,
//             &self.state.party_id_list,
//         )?;

//         let mut commitments = self.state.commitments;

//         for msg in msgs1.iter() {
//             let pubkey = self
//                 .params
//                 .get_pubkey_for_party(msg.from_party)
//                 .ok_or(SignError::InvalidMsgPartyId)?;

//             let msg_hash = hash_msg_1(&msg.session_id, msg.get_pid(), &msg.commitment_r_i);
//             verify_signature(&msg_hash, &msg.signature, &pubkey.verify_key)?;
//             commitments.insert(msg.get_pid(), (msg.session_id, msg.commitment_r_i));
//         }

//         let sids = msgs1.iter().map(|msg| msg.session_id).collect::<Vec<_>>();

//         let final_session_id = calculate_final_session_id(&self.state.party_id_list, &sids);
//         let other_parties = self
//             .state
//             .party_id_list
//             .iter()
//             .copied()
//             .filter(|pid| pid != &self.params.party_id)
//             .collect::<Vec<_>>();

//         let current_pid = self.params.party_id;

//         // TODO: Accept this as input
//         let mut rng = rand::rngs::OsRng;

//         // Seeds for deterministic generation of VSOT receivers.
//         // Used to create test vectors.
//         let rec_seeds: Vec<_> = other_parties
//             .iter()
//             .map(|_| rng.gen::<<StdRng as SeedableRng>::Seed>())
//             .collect();

//         let send_seeds: Vec<_> = other_parties
//             .iter()
//             .map(|_| rng.gen::<<StdRng as SeedableRng>::Seed>())
//             .collect();

//         let (mta_receivers, sign_msgs2): (HashMap<usize, PairwiseMtaRec<MtaRecR1>>, Vec<SignMsg2>) =
//             other_parties
//                 .iter()
//                 .enumerate()
//                 .map(|(idx, sender_id)| {
//                     // TODO: REMOVE this clone later
//                     // Use vec of options and .take() instead
//                     let sender_ot_results = &self.params.keyshare.seed_ot_senders
//                         [get_idx_from_id(current_pid, *sender_id)];

//                     let mut h = Sha256::new();
//                     h.update(b"SL-DKLS-PAIRWISE-MTA");
//                     h.update(&final_session_id.0);
//                     h.update(b"sender");
//                     h.update((*sender_id as u32).to_be_bytes());
//                     h.update(b"receiver");
//                     h.update((current_pid as u32).to_be_bytes());
//                     let mta_session_id = SessionId::new(h.finalize().into());

//                     let mut seed_rng = StdRng::from_seed(rec_seeds[idx]);

//                     let mta_receiver =
//                         PairwiseMtaRec::new(mta_session_id, sender_ot_results, &mut seed_rng);

//                     let (mta_receivers, mta_msg_1) =
//                         mta_receiver.process(&self.params.rand_params.phi_i);

//                     let sender_pubkeys = self
//                         .params
//                         .get_pubkey_for_party(*sender_id)
//                         .ok_or(SignError::InvalidMsgPartyId)?;

//                     let enc_mta_msg1 = encrypt_data(
//                         mta_msg_1.to_bytes().unwrap(),
//                         &sender_pubkeys.encryption_key,
//                         &self.params.party_keys.encryption_keypair.secret_key,
//                         *sender_id,
//                         current_pid,
//                     )?;

//                     let msg_2_hash =
//                         hash_msg_2(&final_session_id, current_pid, *sender_id, &enc_mta_msg1);

//                     let signature = sign_message(&self.params.party_keys.signing_key, &msg_2_hash)?;

//                     let msg1 = SignMsg2 {
//                         session_id: final_session_id,
//                         from_party: current_pid,
//                         to_party: *sender_id,
//                         enc_mta_msg1,
//                         signature,
//                     };

//                     // Collect as hashmap for easier lookup later
//                     Ok(((*sender_id, mta_receivers), msg1))
//                 })
//                 .collect::<Result<Vec<_>, SignError>>()?
//                 .into_iter()
//                 .unzip();

//         let mta_senders = other_parties
//             .iter()
//             .enumerate()
//             .map(|(idx, receiver_id)| {
//                 let seed_ot_results = &self.params.keyshare.seed_ot_receivers
//                     [get_idx_from_id(current_pid, *receiver_id)];

//                 let mut h = Sha256::new();
//                 h.update(b"SL-DKLS-PAIRWISE-MTA");
//                 h.update(final_session_id.as_ref());
//                 h.update(b"sender");
//                 h.update((current_pid as u32).to_be_bytes());
//                 h.update(b"receiver");
//                 h.update((*receiver_id as u32).to_be_bytes());
//                 let mta_session_id = SessionId::new(h.finalize().into());

//                 let mut seed_rng = StdRng::from_seed(send_seeds[idx]);

//                 (
//                     *receiver_id,
//                     PairwiseMtaSender::new(mta_session_id, seed_ot_results, &mut seed_rng),
//                 )
//             })
//             .collect::<HashMap<usize, PairwiseMtaSender<MtaSendR0>>>();

//         let mut h = Sha256::new();
//         let mut keys = commitments.keys().collect::<Vec<_>>();
//         keys.sort();
//         for key in keys {
//             let (sid_i, commitment_i) = &commitments[key];
//             h.update((*key as u32).to_be_bytes());
//             h.update(sid_i);
//             h.update(commitment_i);
//         }

//         let digest_i = HashBytes::new(h.finalize().into());
//         let mu_i = get_mu_i(&self.params.keyshare, &self.state.party_id_list, digest_i);

//         let coeff = match is_zero_vec(&self.params.keyshare.rank_list) {
//             true => get_lagrange_coeff(&self.params.keyshare, &self.state.party_id_list),
//             false => {
//                 let betta_coeffs =
//                     get_birkhoff_coefficients(&self.params.keyshare, &self.state.party_id_list);
//                 *betta_coeffs
//                     .get(&self.params.party_id)
//                     .expect("betta_i not found")
//             }
//         };
//         let x_i = coeff * &self.params.keyshare.s_i + mu_i;
//         let big_x_i = ProjectivePoint::GENERATOR * x_i;

//         let next_round = R2 {
//             final_session_id,
//             big_x_i,
//             x_i,
//             digest_i,
//             mta_receivers,
//             mta_senders,
//             remaining_parties: other_parties.iter().copied().collect(),
//             big_r_i: self.state.big_r_i,
//             commitments,
//             sender_additive_shares: vec![],
//         };

//         let next_state = SignerParty {
//             params: self.params,
//             state: next_round,
//             times: vec_append(self.times, (2, start_time.elapsed())),
//         };

//         Ok((next_state, sign_msgs2))
//     }
// }

// impl SignerParty<R2> {
//     /// Process sign message 2 from other parties where msg.to_party is the current party
//     // TODO: Should we consume self and return a new state?
//     pub fn process_p2p(&mut self, sign_msg2: SignMsg2) -> Result<SignMsg3, SignError> {
//         let start_time = Instant::now();

//         if sign_msg2.to_party != self.params.party_id {
//             return Err(SignError::WrongReceipient(
//                 sign_msg2.to_party,
//                 self.params.party_id,
//             ));
//         }

//         if !self.state.remaining_parties.contains(&sign_msg2.from_party) {
//             return Err(SignError::AlreadyProcessed(sign_msg2.from_party));
//         }

//         if self.state.remaining_parties.is_empty() {
//             return Err(SignError::AlreadyProcessedAll);
//         }

//         let receiver_id = sign_msg2.from_party;
//         let sender_id = sign_msg2.to_party;

//         let receiver_keys = self
//             .params
//             .get_pubkey_for_party(receiver_id)
//             .ok_or(SignError::InvalidMsgPartyId)?;

//         let sender_keys = &self.params.party_keys;

//         let msg_2_hash = hash_msg_2(
//             &self.state.final_session_id,
//             receiver_id,
//             sender_id,
//             &sign_msg2.enc_mta_msg1,
//         );

//         verify_signature(&msg_2_hash, &sign_msg2.signature, &receiver_keys.verify_key)?;

//         // We are sure that mta instance is Some(), because we checked that the party is in remaining_parties
//         let mta_sender = self.state.mta_senders.remove(&receiver_id).unwrap();

//         let msg_bytes = sign_msg2.enc_mta_msg1.enc_data.decrypt_to_vec(
//             &sign_msg2.enc_mta_msg1.nonce,
//             &receiver_keys.encryption_key,
//             &self.params.party_keys.encryption_keypair.secret_key,
//         )?;

//         let msg1 = Round1Output::from_bytes(&msg_bytes).ok_or(SignError::InvalidPlaintext)?;

//         let (additive_shares, mta_msg_2) =
//             mta_sender.process((self.state.x_i, self.params.rand_params.k_i, msg1));

//         // TODO: Change this to encrypt muliple messages at once
//         let enc_mta_msg2 = encrypt_data(
//             mta_msg_2.to_bytes().unwrap(),
//             &receiver_keys.encryption_key,
//             &sender_keys.encryption_keypair.secret_key,
//             receiver_id,
//             sender_id,
//         )?;

//         let enc_digest_i = encrypt_data(
//             self.state.digest_i.as_ref(),
//             &receiver_keys.encryption_key,
//             &sender_keys.encryption_keypair.secret_key,
//             receiver_id,
//             sender_id,
//         )?;

//         let enc_big_x_i = encrypt_data(
//             self.state.big_x_i.to_bytes(),
//             &receiver_keys.encryption_key,
//             &sender_keys.encryption_keypair.secret_key,
//             receiver_id,
//             sender_id,
//         )?;

//         let enc_blind_factor = encrypt_data(
//             self.params.rand_params.blind_factor.as_ref(),
//             &receiver_keys.encryption_key,
//             &sender_keys.encryption_keypair.secret_key,
//             receiver_id,
//             sender_id,
//         )?;

//         let enc_big_r_i = encrypt_data(
//             self.state.big_r_i.to_bytes(),
//             &receiver_keys.encryption_key,
//             &sender_keys.encryption_keypair.secret_key,
//             receiver_id,
//             sender_id,
//         )?;

//         let gamma0 = ProjectivePoint::GENERATOR * additive_shares[0];
//         let gamma1 = ProjectivePoint::GENERATOR * additive_shares[1];

//         let enc_gamma0 = encrypt_data(
//             gamma0.to_bytes(),
//             &receiver_keys.encryption_key,
//             &sender_keys.encryption_keypair.secret_key,
//             receiver_id,
//             sender_id,
//         )?;

//         let enc_gamma1 = encrypt_data(
//             gamma1.to_bytes(),
//             &receiver_keys.encryption_key,
//             &sender_keys.encryption_keypair.secret_key,
//             receiver_id,
//             sender_id,
//         )?;

//         let msg3_hash = hash_msg_3(
//             &self.state.final_session_id,
//             sender_id,
//             receiver_id,
//             &enc_mta_msg2,
//             &enc_digest_i,
//             &enc_big_x_i,
//             &enc_big_r_i,
//             &enc_blind_factor,
//             &enc_gamma0,
//             &enc_gamma1,
//         );

//         let signature = sign_message(&sender_keys.signing_key, &msg3_hash)?;
//         let sign_msg3 = SignMsg3 {
//             session_id: self.state.final_session_id,
//             to_party: receiver_id,
//             from_party: sender_id,
//             enc_mta_msg2,
//             enc_digest_i,
//             enc_big_x_i,
//             enc_big_r_i,
//             enc_blind_factor,
//             enc_gamma0,
//             enc_gamma1,
//             signature,
//         };

//         self.state.remaining_parties.remove(&sign_msg2.from_party);
//         self.state.sender_additive_shares.push(additive_shares);

//         self.times.push((3, start_time.elapsed()));

//         Ok(sign_msg3)
//     }

//     /// Get the number of remaining party to process
//     pub fn get_remaining(&self) -> usize {
//         self.state.remaining_parties.len()
//     }

//     /// Get the party id of the signer
//     pub fn get_pid(&self) -> usize {
//         self.params.party_id
//     }

//     /// Check if all parties' messages have been processed
//     // TODO: Check with artem, bit difficult to use, but prevents wrong state transition
//     pub fn check_proceed(self) -> R2State {
//         if self.state.remaining_parties.is_empty() {
//             let next_state = R3 {
//                 final_session_id: self.state.final_session_id,
//                 big_x_i: self.state.big_x_i,
//                 x_i: self.state.x_i,
//                 digest_i: self.state.digest_i,
//                 mta_receivers: self.state.mta_receivers,
//                 commitments: self.state.commitments,
//                 big_r_i: self.state.big_r_i,
//                 sender_additive_shares: self.state.sender_additive_shares,
//             };

//             let next_state = SignerParty {
//                 params: self.params,
//                 state: next_state,
//                 times: self.times,
//             };
//             R2State::R2Complete(next_state)
//         } else {
//             R2State::R2(self)
//         }
//     }
// }

// impl Round for SignerParty<R3> {
//     type Input = Vec<SignMsg3>;

//     type Output = Result<SignerParty<R4>, SignError>;

//     /// `SignMsg3` messages from other parties for the current party,
//     /// will have `t-1` messages
//     fn process(self, messages: Self::Input) -> Self::Output {
//         let start_time = Instant::now();

//         // TODO: Add some validation for messages

//         let mut big_r_star = ProjectivePoint::IDENTITY;
//         let mut sum_x_j = ProjectivePoint::IDENTITY;
//         let mut sum_gamma_0 = ProjectivePoint::IDENTITY;
//         let mut sum_gamma_1 = ProjectivePoint::IDENTITY;
//         let mut sum_big_t_0 = Scalar::ZERO;
//         let mut sum_big_t_1 = Scalar::ZERO;

//         // TODO: with capacity
//         let mut receiver_additive_shares = Vec::new();

//         let mut mta_receivers = self.state.mta_receivers;

//         for msg3 in &messages {
//             if msg3.to_party != self.params.party_id {
//                 continue;
//             }

//             let sender_id = msg3.from_party;
//             let receiver_id = msg3.to_party;

//             let sender_keys = get_pubkey_for_party(sender_id, &self.params.party_pubkeys)?;
//             let receiver_keys = &self.params.party_keys;

//             let msg3_hash = hash_msg_3(
//                 &self.state.final_session_id,
//                 sender_id,
//                 receiver_id,
//                 &msg3.enc_mta_msg2,
//                 &msg3.enc_digest_i,
//                 &msg3.enc_big_x_i,
//                 &msg3.enc_big_r_i,
//                 &msg3.enc_blind_factor,
//                 &msg3.enc_gamma0,
//                 &msg3.enc_gamma1,
//             );

//             verify_signature(&msg3_hash, &msg3.signature, &sender_keys.verify_key)?;

//             let mta_receiver = mta_receivers
//                 .remove(&sender_id)
//                 .ok_or(SignError::InvalidMsgPartyId)?;

//             let msg_bytes = msg3.enc_mta_msg2.enc_data.decrypt_to_vec(
//                 &msg3.enc_mta_msg2.nonce,
//                 &sender_keys.encryption_key,
//                 &receiver_keys.encryption_keypair.secret_key,
//             )?;

//             let mta_msg2 =
//                 MtaRound2Output::from_bytes(&msg_bytes).ok_or(SignError::InvalidPlaintext)?;

//             let receiver_additive_shares_i = mta_receiver
//                 .process(mta_msg2)
//                 .map_err(SignError::MtaError)?;

//             receiver_additive_shares.push(receiver_additive_shares_i);

//             let digest_j: [u8; 32] = msg3
//                 .enc_digest_i
//                 .enc_data
//                 .decrypt_to_vec(
//                     &msg3.enc_digest_i.nonce,
//                     &sender_keys.encryption_key,
//                     &receiver_keys.encryption_keypair.secret_key,
//                 )?
//                 .try_into()
//                 .unwrap();

//             let big_x_j = decrypt_point(
//                 &msg3.enc_big_x_i,
//                 &sender_keys.encryption_key,
//                 &receiver_keys.encryption_keypair.secret_key,
//             )
//             .map_err(SignError::DecryptionError)?;

//             let big_r_j = decrypt_point(
//                 &msg3.enc_big_r_i,
//                 &sender_keys.encryption_key,
//                 &receiver_keys.encryption_keypair.secret_key,
//             )
//             .map_err(SignError::DecryptionError)?;

//             let blind_factor: [u8; 32] = msg3
//                 .enc_blind_factor
//                 .enc_data
//                 .decrypt_to_vec(
//                     &msg3.enc_blind_factor.nonce,
//                     &sender_keys.encryption_key,
//                     &receiver_keys.encryption_keypair.secret_key,
//                 )?
//                 .try_into()
//                 .map_err(|_| SignError::InvalidPlaintext)?;

//             let gamma0 = decrypt_point(
//                 &msg3.enc_gamma0,
//                 &sender_keys.encryption_key,
//                 &receiver_keys.encryption_keypair.secret_key,
//             )
//             .map_err(SignError::DecryptionError)?;

//             let gamma1 = decrypt_point(
//                 &msg3.enc_gamma1,
//                 &sender_keys.encryption_key,
//                 &receiver_keys.encryption_keypair.secret_key,
//             )
//             .map_err(SignError::DecryptionError)?;

//             let (sid_i, commitment) = self
//                 .state
//                 .commitments
//                 .get(&sender_id)
//                 .ok_or(SignError::InvalidMsgPartyId)?;

//             if !verify_commitment_r_i(sid_i, &big_r_j, &blind_factor, commitment.0) {
//                 return Err(SignError::InvalidCommitment);
//             }

//             if self.state.digest_i.ct_eq(&digest_j).unwrap_u8() != 1 {
//                 return Err(SignError::InvalidDigest);
//             }

//             big_r_star += &big_r_j;
//             sum_x_j += &big_x_j;
//             sum_gamma_0 += &gamma0;
//             sum_gamma_1 += &gamma1;
//             sum_big_t_0 += &receiver_additive_shares_i[0];
//             sum_big_t_1 += &receiver_additive_shares_i[1];
//         }

//         let big_t_0 = &ProjectivePoint::GENERATOR * &sum_big_t_0;
//         let big_t_1 = &ProjectivePoint::GENERATOR * &sum_big_t_1;
//         let big_x_star_i = self.params.keyshare.public_key + (-self.state.big_x_i);
//         // new var
//         let big_r = big_r_star + self.state.big_r_i;

//         // Checks
//         if sum_x_j != big_x_star_i {
//             return Err(SignError::FailedCheck(
//                 "sum_x_j != big_x_star_i".to_string(),
//             ));
//         }

//         if sum_gamma_0 != (&big_x_star_i * &self.params.rand_params.phi_i + (-&big_t_0)) {
//             return Err(SignError::FailedCheck(
//                 "sum_gamma_0 != (self.phi_i * big_x_star_i + (-big_t))".to_string(),
//             ));
//         }

//         if sum_gamma_1 != (&big_r_star * &self.params.rand_params.phi_i + (-big_t_1)) {
//             return Err(SignError::FailedCheck(
//                 "sum_gamma_1 != (self.phi_i * big_r_star + (-big_t_1)".to_string(),
//             ));
//         }

//         let next = SignerParty {
//             params: self.params,
//             state: R4 {
//                 final_session_id: self.state.final_session_id,
//                 big_r,
//                 sender_additive_shares: self.state.sender_additive_shares,
//                 receiver_additive_shares,
//                 x_i: self.state.x_i,
//             },
//             times: vec_append(self.times, (4, start_time.elapsed())),
//         };

//         Ok(next)
//     }
// }

// impl SignerParty<R3> {
//     /// Get party id of the signer party
//     pub fn get_pid(&self) -> usize {
//         self.params.keyshare.party_id
//     }
// }

// impl Round for SignerParty<R4> {
//     type Input = [u8; 32];

//     type Output = Result<(SignerParty<R5>, SignMsg4), SignError>;

//     /// Generates partial signature
//     fn process(self, msg_hash: Self::Input) -> Self::Output {
//         let start_time = Instant::now();

//         let mut sum0 = Scalar::ZERO;
//         let mut sum1 = Scalar::ZERO;

//         for i in 0..self.params.keyshare.threshold - 1 {
//             let sender_shares = &self.state.sender_additive_shares[i];
//             let receiver_shares = &self.state.receiver_additive_shares[i];
//             sum0 += &sender_shares[0] + &receiver_shares[0];
//             sum1 += &sender_shares[1] + &receiver_shares[1];
//         }

//         let r_point = self.state.big_r.to_affine();
//         let r_x = Scalar::from_repr(r_point.x()).unwrap();
//         //        let recid = r_point.y_is_odd().unwrap_u8();
//         let mut s_0 = r_x * (&self.state.x_i * &self.params.rand_params.phi_i + &sum0);
//         let s_1 = &self.params.rand_params.k_i * &self.params.rand_params.phi_i + &sum1;

//         let m = U256::from_be_slice(&msg_hash).to_scalar::<Secp256k1>();
//         s_0 = m * &self.params.rand_params.phi_i + &s_0;

//         let msg4_hash = hash_msg_4(
//             &self.state.final_session_id,
//             self.params.party_id,
//             &s_0,
//             &s_1,
//         );

//         let signature = sign_message(&self.params.party_keys.signing_key, &msg4_hash)?;

//         let sign_msg4 = SignMsg4 {
//             session_id: self.state.final_session_id,
//             from_party: self.params.party_id,
//             s_0,
//             s_1,
//             signature,
//         };

//         let next = SignerParty {
//             params: self.params,
//             state: R5 {
//                 final_session_id: self.state.final_session_id,
//                 big_r: self.state.big_r,
//                 //                recid,
//                 s_0,
//                 s_1,
//                 msg_hash,
//             },
//             times: vec_append(self.times, (5, start_time.elapsed())),
//         };

//         Ok((next, sign_msg4))
//     }
// }

// impl Round for SignerParty<R5> {
//     type Input = Vec<SignMsg4>;

//     type Output = Result<Signature, SignError>;

//     fn process(self, messages: Self::Input) -> Self::Output {
//         // let startTime = Instant::now();

//         let mut sum_s_0 = self.state.s_0;
//         let mut sum_s_1 = self.state.s_1;

//         for msg in &messages {
//             if msg.from_party == self.params.party_id {
//                 continue;
//             }

//             let verify_key =
//                 get_pubkey_for_party(msg.from_party, &self.params.party_pubkeys)?.verify_key;

//             let msg4_hash = hash_msg_4(
//                 &self.state.final_session_id,
//                 msg.from_party,
//                 &msg.s_0,
//                 &msg.s_1,
//             );

//             verify_signature(&msg4_hash, &msg.signature, &verify_key)?;
//             sum_s_0 += &msg.s_0;
//             sum_s_1 += &msg.s_1;
//         }

//         let r = self.state.big_r.to_affine().x();
//         let sum_s_1_inv = sum_s_1.invert().unwrap();
//         let sig = sum_s_0 * sum_s_1_inv;

//         let sign = parse_raw_sign(&r, &sig.to_bytes())?;

//         verify_final_signature(
//             &self.state.msg_hash,
//             &sign,
//             &self.params.keyshare.public_key.to_affine().to_bytes(),
//         )?;

//         Ok(sign)
//     }
// }

// /// State of the signer party in the R2 round
// pub enum R2State {
//     /// The signer party is still in the R2 round, hasn't processed
//     /// all `SignMsg2` messages from other parties
//     R2(SignerParty<R2>),
//     /// The signer party has processed all `SignMsg2` messages from other parties
//     R2Complete(SignerParty<R3>),
// }

// fn get_pubkey_for_party(
//     pid: usize,
//     pubkey_list: &[SignPartyPublicKeys],
// ) -> Result<&SignPartyPublicKeys, SignError> {
//     pubkey_list
//         .iter()
//         .find(|&key| key.party_id == pid)
//         .ok_or(SignError::PartyKeyNotFound)
// }

fn hash_commitment_r_i(
    session_id: &SessionId,
    big_r_i: &ProjectivePoint,
    blind_factor: &[u8; 32],
) -> HashBytes {
    let mut hasher = Sha256::new();
    hasher.update(session_id.as_ref());
    hasher.update(big_r_i.to_bytes());
    hasher.update(blind_factor);
    HashBytes::new(hasher.finalize().into())
}

// #[inline(never)]
// fn validate_input_messages<M: HasFromParty>(
//     mut msgs: Vec<M>,
//     threshold: usize,
//     party_id_list: &[usize],
// ) -> Result<Vec<M>, SignError> {
//     if msgs.len() != threshold {
//         return Err(SignError::InvalidMsgCount);
//     }

//     let party_ids = msgs
//         .iter()
//         .map(|msg| msg.get_pid())
//         .collect::<HashSet<usize>>();

//     if party_ids.len() != threshold {
//         return Err(SignError::DuplicatePartyId);
//     }

//     for pid in party_id_list {
//         if !party_ids.contains(pid) {
//             return Err(SignError::InvalidMsgPartyId);
//         }
//     }

//     msgs.sort_by_key(HasFromParty::get_pid);

//     Ok(msgs)
// }

// fn validate_pubkeys(
//     mut pubkeys: Vec<SignPartyPublicKeys>,
//     t: usize,
//     n: usize,
// ) -> Result<(Vec<SignPartyPublicKeys>, HashMap<usize, usize>, Vec<usize>), SignError> {
//     let party_id_set = pubkeys
//         .iter()
//         .map(|key| key.party_id)
//         .collect::<HashSet<usize>>();

//     if party_id_set.len() != pubkeys.len() {
//         return Err(SignError::DuplicatePartyId);
//     }

//     if party_id_set.len() != t {
//         return Err(SignError::InvalidMsgCount);
//     }

//     for pid in &party_id_set {
//         if pid >= &n {
//             return Err(SignError::InvalidMsgPartyId);
//         }
//     }

//     // Get party ids and sort them
//     let mut party_id_list = party_id_set.iter().copied().collect::<Vec<_>>();
//     party_id_list.sort();

//     // Map from party id to index in all vecs
//     let party_id_map = party_id_list
//         .iter()
//         .enumerate()
//         .map(|(idx, pid)| (*pid, idx))
//         .collect::<HashMap<_, _>>();

//     pubkeys.sort_by_key(|key| key.party_id);

//     Ok((pubkeys, party_id_map, party_id_list))
// }

fn get_mu_i(keyshare: &Keyshare, party_id_list: &[(usize, u8)], sig_id: HashBytes) -> Scalar {
    let mut p_0_list = Vec::new();
    let mut p_1_list = Vec::new();

    for (_, party_id) in party_id_list {
        if party_id < &keyshare.party_id {
            p_0_list.push(*party_id);
        }
        if party_id > &keyshare.party_id {
            p_1_list.push(*party_id);
        }
    }

    let mut sum_p_0 = Scalar::ZERO;
    for p_0_party in &p_0_list {
        let seed_j_i = keyshare.rec_seed_list[*p_0_party as usize];
        let mut hasher = Sha256::new();
        hasher.update(seed_j_i);
        hasher.update(sig_id);
        let value = Scalar::reduce(U256::from_be_slice(&hasher.finalize()));
        sum_p_0 += value;
    }

    let mut sum_p_1 = Scalar::ZERO;
    for p_1_party in &p_1_list {
        let seed_i_j =
            keyshare.sent_seed_list[*p_1_party as usize - keyshare.party_id as usize - 1];
        let mut hasher = Sha256::new();
        hasher.update(seed_i_j);
        hasher.update(sig_id.as_ref());
        let value = Scalar::reduce(U256::from_be_slice(&hasher.finalize()));
        sum_p_1 += value;
    }

    sum_p_0 - sum_p_1
}

fn get_birkhoff_coefficients(
    keyshare: &Keyshare,
    sign_party_ids: &[(usize, u8)],
) -> HashMap<usize, Scalar> {
    let params = sign_party_ids
        .iter()
        .map(|(_, pid)| {
            (
                keyshare.x_i_list[*pid as usize],
                keyshare.rank_list[*pid as usize] as usize,
            )
        })
        .collect::<Vec<_>>();

    let betta_vec = birkhoff_coeffs::<Secp256k1>(&params);

    sign_party_ids
        .iter()
        .zip(betta_vec.iter())
        .map(|((_, pid), w_i)| (*pid as usize, *w_i))
        .collect::<HashMap<_, _>>()
}

fn get_lagrange_coeff(keyshare: &Keyshare, sign_party_ids: &[(usize, u8)]) -> Scalar {
    let mut coeff = Scalar::from(1u64);
    let pid = keyshare.party_id;
    let x_i = &keyshare.x_i_list[pid as usize] as &Scalar;
    for (_, index) in sign_party_ids {
        let x_j = &keyshare.x_i_list[*index as usize] as &Scalar;
        if x_i.ct_ne(&x_j).into() {
            let sub = x_j - x_i;
            coeff *= *x_j * sub.invert().unwrap();
        }
    }
    coeff
}

fn verify_commitment_r_i(
    sid: &SessionId,
    big_r_i: &ProjectivePoint,
    blind_factor: &[u8; 32],
    commitment: &HashBytes,
) -> bool {
    let compare_commitment = hash_commitment_r_i(sid, big_r_i, blind_factor);

    commitment.ct_eq(&compare_commitment).into()
}

fn mta_session_id(final_session_id: &SessionId, sender_id: u8, receiver_id: u8) -> SessionId {
    let mut h = Sha256::new();
    h.update(b"SL-DKLS-PAIRWISE-MTA");
    h.update(&final_session_id);
    h.update(b"sender");
    h.update(&[sender_id]);
    h.update(b"receiver");
    h.update(&[receiver_id]);

    SessionId::new(h.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::AffinePoint;
    use std::array;

    use sl_mpc_mate::coord::SimpleMessageRelay;

    use crate::keygen::gen_keyshares;
    use crate::setup::{sign::*, SETUP_MESSAGE_TAG};

    fn setup_dsg(pk: &AffinePoint, shares: &[Keyshare]) -> Vec<(ValidatedSetup, Seed)> {
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

    #[test]
    fn s0() {
        assert!(true);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn s1() {
        let coord = SimpleMessageRelay::new();

        let shares = gen_keyshares(Some([0, 1, 1])).await;

        let pk = shares[0].public_key.to_affine();

        let mut parties = JoinSet::new();
        for (setup, seed) in setup_dsg(&pk, &shares).into_iter() {
            parties.spawn(run(setup, seed, coord.connect()));
        }

        while let Some(fini) = parties.join_next().await {
            let fini = fini.unwrap();

            if let Err(ref err) = fini {
                println!("error {err:?}");
            }

            let fini = fini.unwrap();
        }
    }
}
