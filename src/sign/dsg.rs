//! Distributed sign generation protocol.

use std::collections::HashMap;

use k256::{
    ecdsa::Signature,
    elliptic_curve::{
        group::GroupEncoding, ops::Reduce, point::AffineCoordinates, subtle::ConstantTimeEq,
        PrimeField,
    },
    sha2::{Digest, Sha256},
    ProjectivePoint, Scalar, Secp256k1, U256,
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use tokio::task::{JoinError, JoinSet};

use sl_mpc_mate::{coord::MessageRelay, math::birkhoff_coeffs, message::*, HashBytes, SessionId};

use sl_oblivious::soft_spoken_mod::Round1Output;

use crate::{
    keygen::{get_idx_from_id, messages::Keyshare},
    setup::sign::ValidatedSetup,
    sign::{
        pairwise_mta::{PairwiseMtaRec, PairwiseMtaSender},
        SignMsg1, SignMsg3, SignMsg4,
    },
    utils::{parse_raw_sign, verify_final_signature},
    BadPartyIndex, Seed,
};

use super::SignError;

const DSG_MSG_R1: MessageTag = MessageTag::tag(1);
const DSG_MSG_R2: MessageTag = MessageTag::tag(2);
const DSG_MSG_R3: MessageTag = MessageTag::tag(3);
const DSG_MSG_R4: MessageTag = MessageTag::tag(4);

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
                .recv(&msg_id, 10)
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
                .recv(&msg_id, 10)
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
    let msg = msg.verify_and_decode(setup.party_verifying_key(party_idx).unwrap())?;

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
pub async fn run(
    setup: ValidatedSetup,
    seed: Seed,
    relay: MessageRelay,
) -> Result<Signature, SignError> {
    let mut rng = ChaCha20Rng::from_seed(seed);
    let mut nonce_counter = NonceCounter::new();

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
                nonce_counter.next_nonce()
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
        get_lagrange_coeff(setup.keyshare(), &party_idx_to_id_map)
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
            nonce_counter.next_nonce()
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

    let big_t_0 = ProjectivePoint::GENERATOR * sum_big_t_0;
    let big_t_1 = ProjectivePoint::GENERATOR * sum_big_t_1;
    let big_x_star_i = setup.keyshare().public_key + (-big_x_i);
    // new var
    let big_r = big_r_star + big_r_i;

    // Checks
    if sum_x_j != big_x_star_i {
        return Err(SignError::FailedCheck("sum_x_j != big_x_star_i"));
    }

    if sum_gamma_0 != (big_x_star_i * phi_i + (-&big_t_0)) {
        return Err(SignError::FailedCheck(
            "sum_gamma_0 != (self.phi_i * big_x_star_i + (-big_t))",
        ));
    }

    if sum_gamma_1 != (big_r_star * phi_i + (-big_t_1)) {
        return Err(SignError::FailedCheck(
            "sum_gamma_1 != (self.phi_i * big_r_star + (-big_t_1)",
        ));
    }

    let msg_hash = setup.hash();

    let mut sum0 = Scalar::ZERO;
    let mut sum1 = Scalar::ZERO;

    for i in 0..setup.keyshare().threshold as usize - 1 {
        let sender_shares = &sender_additive_shares[i];
        let receiver_shares = &receiver_additive_shares[i];
        sum0 += sender_shares[0] + receiver_shares[0];
        sum1 += sender_shares[1] + receiver_shares[1];
    }

    let r_point = big_r.to_affine();
    let r_x = Scalar::from_repr(r_point.x()).unwrap();
    //        let recid = r_point.y_is_odd().unwrap_u8();
    let mut s_0 = r_x * (x_i * phi_i + sum0);
    let s_1 = k_i * phi_i + sum1;

    let m = Scalar::reduce(U256::from_be_slice(&msg_hash));

    s_0 = m * phi_i + s_0;

    relay.send(Builder::<Signed>::encode(
        &setup.msg_id(None, DSG_MSG_R4),
        10,
        setup.signing_key(),
        &SignMsg4 {
            session_id: Opaque::from(final_session_id),
            s_0: Opaque::from(s_0),
            s_1: Opaque::from(s_1),
        },
    )?);

    let mut sum_s_0 = s_0;
    let mut sum_s_1 = s_1;

    let mut js = recv_broadcast_messages(&setup, DSG_MSG_R4, &relay);
    while let Some(msg) = js.join_next().await {
        let (msg, _party_idx) = decode_signed_message::<SignMsg4>(msg, &setup)?;

        sum_s_0 += &*msg.s_0;
        sum_s_1 += &*msg.s_1;
    }

    let r = big_r.to_affine().x();
    let sum_s_1_inv = sum_s_1.invert().unwrap();
    let sig = sum_s_0 * sum_s_1_inv;

    let sign = parse_raw_sign(&r, &sig.to_bytes())?;

    verify_final_signature(
        &setup.hash(),
        &sign,
        &setup.keyshare().public_key.to_affine().to_bytes(),
    )?;

    Ok(sign)
}

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
        if x_i.ct_ne(x_j).into() {
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
    h.update(final_session_id);
    h.update(b"sender");
    h.update([sender_id]);
    h.update(b"receiver");
    h.update([receiver_id]);

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
            .with_hash(HashBytes::new([1; 32]))
            .build(&setup_msg_id, 100, &setup_sk)
            .unwrap();

        let list = party_sk
            .into_iter()
            .enumerate()
            .map(|(idx, party_sk)| {
                ValidatedSetup::decode(&mut setup, &instance, &setup_vk, party_sk, |_, _| {
                    Some(shares[idx].clone())
                })
                .unwrap()
            })
            .map(|setup| (setup, rng.gen()))
            .collect::<Vec<_>>();

        list
    }

    #[test]
    fn s0() {
        assert!(true);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn s1() {
        let coord = SimpleMessageRelay::new();

        let shares = gen_keyshares::<2, 3>(Some([0, 1, 1])).await;

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

            let _fini = fini.unwrap();
        }
    }
}
