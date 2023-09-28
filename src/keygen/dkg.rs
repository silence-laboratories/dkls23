//! Distributed key generation protocol.
//

use digest::{generic_array::GenericArray, Digest};
use k256::{
    elliptic_curve::{group::GroupEncoding, subtle::ConstantTimeEq, PrimeField},
    FieldBytes, NonZeroScalar, ProjectivePoint, Scalar, Secp256k1,
};
use merlin::Transcript;
use rand::prelude::*;
use rand_chacha::ChaCha20Rng;
use rayon::prelude::*;
use sha2::Sha256;
use tokio::task::{JoinError, JoinSet};

use sl_oblivious::{
    soft_spoken::{build_pprf, eval_pprf, PPRFOutput, SenderOTSeed},
    soft_spoken_mod::SOFT_SPOKEN_K,
    utils::TranscriptProtocol,
    vsot::{VSOTError, VSOTMsg3, VSOTReceiver, VSOTSender},
    zkproofs::DLogProof,
};

use sl_mpc_mate::{
    coord::*,
    math::{feldman_verify, polynomial_coeff_multipliers, GroupPolynomial, Polynomial},
    message::*,
    HashBytes, SessionId,
};

use crate::{
    keygen::{check_secret_recovery, constants::*, messages::*, KeygenError},
    setup::{keygen::ValidatedSetup, PartyInfo},
};

/// Seed for our RNG
pub type Seed = <ChaCha20Rng as SeedableRng>::Seed;

type Pairs<T> = Vec<(u8, T)>;

fn find_pair<T>(pairs: &[(u8, T)], party_id: u8) -> Result<&T, KeygenError> {
    pairs
        .iter()
        .find(|(p, _)| *p == party_id)
        .map(|(_, v)| v)
        .ok_or(KeygenError::InvalidParty(party_id))
}

fn pop_pair<T>(pairs: &mut Pairs<T>, party_id: u8) -> Result<T, KeygenError> {
    let pos = pairs
        .iter()
        .position(|(p, _)| *p == party_id)
        .ok_or(KeygenError::InvalidParty(party_id))?;

    Ok(pairs.remove(pos).1)
}

fn remove_ids<T>(mut pairs: Vec<(u8, T)>) -> Vec<T> {
    pairs.sort_by_key(|(p, _)| *p);
    pairs.into_iter().map(|(_, v)| v).collect()
}

fn remove_ids_and_wrap<T, K>(mut pairs: Vec<(u8, T)>) -> Vec<Opaque<T, K>> {
    pairs.sort_by_key(|(p, _)| *p);
    pairs.into_iter().map(|(_, v)| Opaque::from(v)).collect()
}

fn pop_tag<T>(msg_map: &mut Vec<(MsgId, T)>, id: &MsgId) -> Option<T> {
    if let Some(idx) = msg_map.iter().position(|prev| prev.0.eq(id)) {
        let (_, tag) = msg_map.swap_remove(idx);
        return Some(tag);
    }

    println!("unexpected message {:X}", id);

    None
}

async fn request_messages<R: Relay>(
    setup: &ValidatedSetup,
    tag: MessageTag,
    relay: &mut R,
    p2p: bool,
) -> Result<Vec<(MsgId, u8)>, InvalidMessage> {
    let mut tags = vec![];
    let me = if p2p { Some(setup.party_id()) } else { None };

    for (p, vk) in setup.other_parties_iter() {
        // A message from party VK (p) to me.
        let msg_id = setup.msg_id_from(vk, me, tag);

        tracing::info!("ask msg {:X} tag {:?} {} p2p {}", msg_id, tag, setup.party_id(), p2p);

        let msg = AskMsg::allocate(&msg_id, setup.ttl().as_secs() as _);

        tags.push((msg_id, p));

        relay.send(msg).await?;
    }

    Ok(tags)
}

fn decode_signed_message<T: bincode::Decode>(
    tags: &mut Vec<(MsgId, u8)>,
    mut msg: Vec<u8>,
    setup: &ValidatedSetup,
) -> Result<(T, u8), InvalidMessage> {
    let msg = Message::from_buffer(&mut msg)?;
    let mid = msg.id();

    let party_id = pop_tag(tags, &mid).unwrap(); // ok_or(InvalidMessage::RecvError)?;

    let msg = msg.verify_and_decode(setup.party_verifying_key(party_id).unwrap())?;

    tracing::info!("got msg {:X} {}", mid, setup.party_id());

    Ok((msg, party_id))
}

fn decode_encrypted_message<T: bincode::Decode>(
    tags: &mut Vec<(MsgId, u8)>,
    mut msg: Vec<u8>,
    secret: &ReusableSecret,
    enc_pub_keys: &[(u8, PublicKey)],
) -> Result<(T, u8), InvalidMessage> {
    let mut msg = Message::from_buffer(&mut msg)?;
    let mid = msg.id();

    let party_id = pop_tag(tags, &mid).unwrap(); // .ok_or(InvalidMessage::RecvError)?;

    let msg = msg.decrypt_and_decode(
        MESSAGE_HEADER_SIZE,
        secret,
        find_pair(enc_pub_keys, party_id).map_err(|_| InvalidMessage::RecvError)?,
    )?;

    tracing::info!("got msg {:X} p2p", mid);

    Ok((msg, party_id))
}

///
pub async fn run<R>(
    setup: ValidatedSetup,
    seed: Seed,
    relay: R,
) -> Result<Keyshare, KeygenError>
where
    R: Relay,
{
    let mut relay = BufferedMsgRelay::new(relay);

    let mut rng = ChaCha20Rng::from_seed(seed);
    let mut nonce_counter = NonceCounter::new();

    let t = setup.threshold();
    let my_party_id = setup.party_id();
    let session_id = SessionId::new(rng.gen());
    let r_i = rng.gen();
    let polynomial = Polynomial::random(&mut rng, t as usize - 1); // u_i_k
    let x_i = NonZeroScalar::random(&mut rng);

    let enc_keys = ReusableSecret::random_from_rng(&mut rng);

    let big_f_i_vec = polynomial.commit(); // big_f_i_vector in dkg.py

    let commitment = hash_commitment(
        &session_id,
        setup.party_id() as usize,
        setup.rank() as usize,
        &x_i,
        &big_f_i_vec,
        &r_i,
    );

    let d_i = polynomial.derivative_at(setup.rank() as usize, &x_i);

    let mut commitment_list = vec![(my_party_id, commitment)];
    let mut sid_i_list = vec![(my_party_id, session_id)];
    let mut x_i_list = vec![(my_party_id, x_i)];
    let mut d_i_list = vec![(my_party_id, d_i)];
    let mut enc_pub_key = vec![];
    let mut big_f_i_vecs = vec![(my_party_id, big_f_i_vec.clone())];

    // send out first message
    relay
        .send(Builder::<Signed>::encode(
            &setup.msg_id(None, DKG_MSG_R1),
            setup.ttl(),
            setup.signing_key(),
            &KeygenMsg1 {
                session_id: Opaque::from(session_id),
                commitment: Opaque::from(commitment),
                x_i: Opaque::from(*x_i),
                enc_pk: Opaque::from(PublicKey::from(&enc_keys).to_bytes()),
            },
        )?)
        .await?;

    let mut r1_tags = request_messages(&setup, DKG_MSG_R1, &mut relay, false).await?;
    while !r1_tags.is_empty() {
        let msg = relay.next().await.ok_or(KeygenError::MissingMessage)?;

        let (
            KeygenMsg1 {
                session_id,
                x_i,
                commitment,
                enc_pk,
            },
            party_id,
        ) = decode_signed_message(&mut r1_tags, msg, &setup)?;

        sid_i_list.push((party_id, *session_id));
        commitment_list.push((party_id, *commitment));
        x_i_list.push((party_id, NonZeroScalar::new(*x_i).unwrap())); // FIXME handle unwrap()!
        enc_pub_key.push((party_id, PublicKey::from(*enc_pk)));
    }

    tracing::info!("R1 done {}", setup.party_id());

    // Create a common session ID from pieces od random data that we received
    // from other parties.
    //
    // Sort party's session-id by party id
    sid_i_list.sort_by_key(|(p, _)| *p);
    x_i_list.sort_by_key(|(p, _)| *p);
    commitment_list.sort_by_key(|(p, _)| *p);

    // TODO: Should parties be initialized with rank_list and x_i_list? Ask Vlad.
    let final_session_id = SessionId::new(
        sid_i_list
            .iter()
            .fold(Sha256::new(), |hash, (_, sid)| hash.chain_update(sid))
            .finalize()
            .into(),
    );

    // Setup transcript for DLog proofs.
    let mut dlog_transcript = Transcript::new_dlog_proof(
        &final_session_id,
        setup.party_id() as usize,
        DLOG_PROOF1_LABEL,
        DKG_LABEL,
    );

    let dlog_proofs = polynomial
        .iter()
        .map(|f_i| {
            DLogProof::prove(
                f_i,
                &ProjectivePoint::GENERATOR,
                &mut dlog_transcript,
                &mut rng,
            )
        })
        .collect::<Vec<_>>();

    let mut vsot_receivers = setup
        .other_parties_iter()
        .map(|(p, _)| {
            (
                p,
                VSOTReceiver::new(
                    get_vsot_session_id(p as usize, my_party_id as usize, &final_session_id),
                    &mut rng,
                ),
            )
        })
        .collect::<Vec<_>>();

    let mut to_send = vec![];

    let mut vsot_senders = setup
        .other_parties_iter()
        .map(|(p, _vk)| {
            (
                p,
                setup.msg_id_from(&setup.verifying_key(), Some(p), DKG_MSG_R2),
                rng.gen(),
                find_pair(&enc_pub_key, p).unwrap(),
                nonce_counter.next_nonce(),
            )
        })
        // .par_bridge()
        .map(|(p, msg_id, seed, enc_pk, nonce)| {
            let mut rng = ChaCha20Rng::from_seed(seed); // TODO check!!!

            let vsot_session_id =
                get_vsot_session_id(my_party_id as usize, p as usize, &final_session_id);

            let (sender, msg1) = VSOTSender::new(vsot_session_id, &mut rng);

            to_send.push(Builder::<Encrypted>::encode(
                &msg_id,
                setup.ttl(),
                &enc_keys,
                enc_pk,
                &msg1,
                nonce,
            )?);

            Ok((p, sender))
        })
        .collect::<Result<Vec<_>, KeygenError>>()?;

    // send out R2 P2P messages
    for msg in to_send.into_iter() {
        relay.send(msg).await?;
    }

    // send out our R2 broadcast message
    relay
        .send(Builder::<Signed>::encode(
            &setup.msg_id(None, DKG_MSG_R2),
            setup.ttl(),
            setup.signing_key(),
            &KeygenMsg2 {
                session_id: Opaque::from(final_session_id),
                big_f_i_vector: big_f_i_vec,
                r_i: Opaque::from(r_i),
                dlog_proofs_i: dlog_proofs,
            },
        )?)
        .await?;

    // ... and while we are receiving P2P messages,
    // receive and process broadcast messages from parties.
    let mut r2_msgs = request_messages(&setup, DKG_MSG_R2, &mut relay, false).await?;
    while !r2_msgs.is_empty() {
        tracing::info!("r2_msgs {} {:?}", setup.party_id(), r2_msgs);

        let msg = relay.next().await.ok_or(KeygenError::MissingMessage)?;
        let (msg, party_id) = decode_signed_message::<KeygenMsg2>(&mut r2_msgs, msg, &setup)?;

        // Verify commitments.
        let rank = setup.party_rank(party_id).unwrap();
        let x_i = find_pair(&x_i_list, party_id)?;
        let sid = find_pair(&sid_i_list, party_id)?;
        let commitment = find_pair(&commitment_list, party_id)?;

        let commit_hash = hash_commitment(
            sid,
            party_id as usize,
            rank as usize,
            x_i,
            &msg.big_f_i_vector,
            &msg.r_i,
        );

        bool::from(commit_hash.ct_eq(commitment))
            .then_some(())
            .ok_or(KeygenError::InvalidCommitmentHash)?;

        // Verify DLog proofs.
        let mut dlog_transcript = Transcript::new_dlog_proof(
            &final_session_id,
            party_id as usize,
            DLOG_PROOF1_LABEL,
            DKG_LABEL,
        );

        verfiy_dlog_proofs(
            &msg.dlog_proofs_i,
            msg.big_f_i_vector.points(),
            &mut dlog_transcript,
        )?;

        big_f_i_vecs.push((party_id, msg.big_f_i_vector));
    }
    drop(r2_msgs);

    tracing::info!("R2 broadcast done {}", setup.party_id());

    drop(commitment_list);

    // 6.d
    let mut big_f_vec = GroupPolynomial::new(
        (0..setup.threshold())
            .map(|_| ProjectivePoint::IDENTITY.into())
            .collect(),
    );
    for (_, v) in &big_f_i_vecs {
        big_f_vec.add_mut(v);
    }

    // start receiving P2P messages
    let mut r2_p2p = request_messages(&setup, DKG_MSG_R2, &mut relay, true).await?;

    let mut vsot_next_receivers = vec![];
    while !r2_p2p.is_empty() {
        tracing::info!("r2_p2p {} {:?}", setup.party_id(), r2_p2p);

        let msg = relay.next().await.ok_or(KeygenError::MissingMessage)?;
        let (vsot_msg1, party_id) =
            decode_encrypted_message(&mut r2_p2p, msg, &enc_keys, &enc_pub_key)?;

        let rank = setup.party_rank(party_id).unwrap();

        let receiver = pop_pair(&mut vsot_receivers, party_id)?;

        let (receiver, vsot_msg2) = receiver.process(vsot_msg1)?;

        vsot_next_receivers.push((party_id, receiver));

        let x_i = find_pair(&x_i_list, party_id)?;
        let d_i = polynomial.derivative_at(rank as usize, x_i);

        let msg3 = KeygenMsg3 {
            vsot_msg2,
            d_i: Opaque::from(d_i),
            session_id: Opaque::from(final_session_id),
            big_f_vec: big_f_vec.clone(),
        };

        relay
            .send(Builder::<Encrypted>::encode(
                &setup.msg_id(Some(party_id), DKG_MSG_R3),
                setup.ttl(),
                &enc_keys,
                find_pair(&enc_pub_key, party_id)?,
                &msg3,
                nonce_counter.next_nonce(),
            )?)
            .await?;
    }
    drop(r2_p2p);

    tracing::info!("R2 P2P done {}", setup.party_id());

    let mut vsot_receivers = vsot_next_receivers;

    let mut vsot_next_senders = vec![];
    let mut r3_msgs = request_messages(&setup, DKG_MSG_R3, &mut relay, true).await?;
    while !r3_msgs.is_empty() {

        tracing::info!("r3_msgs {} {:?}", setup.party_id(), r3_msgs);

        let msg = relay.next().await.ok_or(KeygenError::MissingMessage)?;
        let (msg3, party_id) =
            decode_encrypted_message::<KeygenMsg3>(&mut r3_msgs, msg, &enc_keys, &enc_pub_key)?;

        (msg3.big_f_vec == big_f_vec)
            .then_some(())
            .ok_or(KeygenError::BigFVecMismatch)?;

        d_i_list.push((party_id, *msg3.d_i));

        let sender = pop_pair(&mut vsot_senders, party_id)?;

        let (sender, vsot_msg3) = sender.process(msg3.vsot_msg2)?;

        vsot_next_senders.push((party_id, sender));

        relay
            .send(Builder::<Encrypted>::encode(
                &setup.msg_id(Some(party_id), DKG_MSG_R4),
                setup.ttl(),
                &enc_keys,
                find_pair(&enc_pub_key, party_id)?,
                &vsot_msg3,
                nonce_counter.next_nonce(),
            )?)
            .await?;
    }

    tracing::info!("R3 P2P done {}", setup.party_id());

    let mut vsot_senders = vsot_next_senders;

    d_i_list.sort_by_key(|(p, _)| *p);
    big_f_i_vecs.sort_by_key(|(p, _)| *p);

    for ((_, big_f_i_vec), (_, f_i_val)) in big_f_i_vecs.iter().zip(&d_i_list) {
        let coeffs = big_f_i_vec.derivative_coeffs(setup.rank() as usize);

        let valid = feldman_verify(
            &coeffs,
            find_pair(&x_i_list, setup.party_id())?,
            f_i_val,
            &ProjectivePoint::GENERATOR,
        )
        .expect("u_i_k cannot be empty");

        if !valid {
            return Err(KeygenError::FailedFelmanVerify);
        }
    }

    let public_key = *big_f_vec.get(0).unwrap(); // FIXME dup data
    let s_i: Scalar = d_i_list.iter().map(|(_, p)| p).sum();
    let big_s_i = ProjectivePoint::GENERATOR * s_i;

    let mut transcript = Transcript::new_dlog_proof(
        &final_session_id,
        setup.party_id() as usize,
        DLOG_PROOF2_LABEL,
        DKG_LABEL,
    );

    let proof = DLogProof::prove(&s_i, &ProjectivePoint::GENERATOR, &mut transcript, &mut rng);

    let msg4 = KeygenMsg4 {
        session_id: Opaque::from(final_session_id),
        public_key: Opaque::from(public_key),
        big_s_i: Opaque::from(big_s_i),
        dlog_proof: proof,
    };

    relay
        .send(Builder::<Signed>::encode(
            &setup.msg_id(None, DKG_MSG_R4),
            setup.ttl(),
            setup.signing_key(),
            &msg4,
        )?)
        .await?;

    let mut big_s_list = vec![(my_party_id, big_s_i)];

    let mut r4_msgs = request_messages(&setup, DKG_MSG_R4, &mut relay, false).await?;
    while !r4_msgs.is_empty() {
        let msg = relay.next().await.ok_or(KeygenError::MissingMessage)?;
        let (msg, party_id) = decode_signed_message::<KeygenMsg4>(&mut r4_msgs, msg, &setup)?;

        if public_key != *msg.public_key {
            return Err(KeygenError::PublicKeyMismatch);
        }

        let big_s_i = &*msg.big_s_i;
        let dlog_proof = &msg.dlog_proof;

        let mut transcript = Transcript::new_dlog_proof(
            &final_session_id,
            party_id as usize,
            DLOG_PROOF2_LABEL,
            DKG_LABEL,
        );

        dlog_proof
            .verify(big_s_i, &ProjectivePoint::GENERATOR, &mut transcript)
            .then_some(())
            .ok_or(KeygenError::InvalidDLogProof)?;

        let x_i = find_pair(&x_i_list, party_id)?;
        // TODO: Handle unwrap
        let party_rank = setup.party_rank(party_id).unwrap();
        let coeff_multipliers =
            polynomial_coeff_multipliers(x_i, party_rank as usize, setup.participants() as usize);
        let mut expected_point = ProjectivePoint::IDENTITY;
        for (point, coeff) in big_f_vec.points().zip(coeff_multipliers) {
            expected_point += point * &coeff;
        }

        (expected_point == *msg.big_s_i)
            .then_some(())
            .ok_or(KeygenError::BigSMismatch)?;

        big_s_list.push((party_id, *msg.big_s_i));
    }

    big_s_list.sort_by_key(|(p, _)| *p);

    // TODO:(sushi) Only for birkhoff now (with ranks), support lagrange later.
    let rank_list = setup.all_party_ranks();

    // TODO: Remove clone later, just for testing
    check_secret_recovery(
        &remove_ids(x_i_list.clone()),
        &remove_ids(rank_list),
        &remove_ids(big_s_list.clone()),
        &public_key,
    )?;

    let mut vsot_next_receivers = vec![];
    let mut js = request_messages(&setup, DKG_MSG_R4, &mut relay, true).await?;
    while !js.is_empty() {
        let msg = relay.next().await.ok_or(KeygenError::MissingMessage)?;
        let (msg, party_id) =
            decode_encrypted_message::<VSOTMsg3>(&mut js, msg, &enc_keys, &enc_pub_key)?;
        let receiver = pop_pair(&mut vsot_receivers, party_id)?;

        let (receiver, vsot_msg4) = receiver.process(msg)?;
        vsot_next_receivers.push((party_id, receiver));

        relay
            .send(Builder::<Encrypted>::encode(
                &setup.msg_id(Some(party_id), DKG_MSG_R5),
                setup.ttl(),
                &enc_keys,
                find_pair(&enc_pub_key, party_id)?,
                &vsot_msg4,
                nonce_counter.next_nonce(),
            )?)
            .await?;
    }
    let mut vsot_receivers = vsot_next_receivers;

    let mut seed_ot_senders = vec![];
    let mut seed_i_j_list = vec![];

    let mut js = request_messages(&setup, DKG_MSG_R5, &mut relay, true).await?;
    while !js.is_empty() {
        let msg = relay.next().await.ok_or(KeygenError::MissingMessage)?;
        let (msg, party_id) = decode_encrypted_message(&mut js, msg, &enc_keys, &enc_pub_key)?;
        let sender = pop_pair(&mut vsot_senders, party_id)?;

        let (sender_output, vsot_msg5) = sender.process(msg)?;

        let (all_but_one_sender_seed, pprf_output) =
            build_pprf(&final_session_id, &sender_output, 256, SOFT_SPOKEN_K as u8);

        seed_ot_senders.push((party_id, all_but_one_sender_seed));

        let seed_i_j = if party_id > my_party_id {
            let seed_i_j = rng.gen();
            seed_i_j_list.push((party_id, seed_i_j));
            Some(seed_i_j)
        } else {
            None
        };

        let msg6 = KeygenMsg6 {
            session_id: Opaque::from(final_session_id),
            vsot_msg5,
            pprf_output,
            seed_i_j,
        };

        relay
            .send(Builder::<Encrypted>::encode(
                &setup.msg_id(Some(party_id), DKG_MSG_R6),
                setup.ttl(),
                &enc_keys,
                find_pair(&enc_pub_key, party_id)?,
                &msg6,
                nonce_counter.next_nonce(),
            )?)
            .await?;
    }

    let mut seed_ot_receivers = vec![];
    let mut rec_seed_list = vec![];

    let mut js = request_messages(&setup, DKG_MSG_R6, &mut relay, true).await?;
    while !js.is_empty() {
        let msg = relay.next().await.ok_or(KeygenError::MissingMessage)?;
        let (msg, party_id) =
            decode_encrypted_message::<KeygenMsg6>(&mut js, msg, &enc_keys, &enc_pub_key)?;

        let receiver = pop_pair(&mut vsot_receivers, party_id)?;

        let receiver_output = receiver.process(msg.vsot_msg5)?;

        let all_but_one_receiver_seed = eval_pprf(
            &final_session_id,
            &receiver_output,
            256,
            SOFT_SPOKEN_K as u8,
            msg.pprf_output,
        )
        .map_err(KeygenError::PPRFError)?;

        seed_ot_receivers.push((party_id, all_but_one_receiver_seed));
        if let Some(seed_j_i) = msg.seed_i_j {
            rec_seed_list.push((party_id, seed_j_i));
        }
    }

    // Sorting to ensure that the list is in the same order for all parties
    // As we can get messages in any order
    // TODO: Verify that this is actually necessary

    let share = Keyshare {
        magic: Keyshare::MAGIC, // marker of current version Keyshare

        total_parties: setup.participants(),
        threshold: setup.threshold(),
        party_id: my_party_id,
        rank_list: remove_ids(setup.all_party_ranks()),
        public_key: Opaque::from(public_key),
        x_i_list: remove_ids_and_wrap(x_i_list),
        big_s_list: remove_ids_and_wrap(big_s_list),
        s_i: Opaque::from(s_i),
        sent_seed_list: remove_ids(seed_i_j_list),
        seed_ot_receivers: remove_ids(seed_ot_receivers),
        seed_ot_senders: remove_ids(seed_ot_senders),
        rec_seed_list: remove_ids(rec_seed_list),
    };

    Ok(share)
}

fn hash_commitment(
    session_id: &SessionId,
    party_id: usize,
    rank: usize,
    x_i: &NonZeroScalar,
    big_f_i_vec: &GroupPolynomial<Secp256k1>,
    r_i: &[u8; 32],
) -> HashBytes {
    let mut hasher = Sha256::new();

    hasher.update(b"SL-Keygen-Commitment");
    hasher.update(session_id);
    hasher.update((party_id as u64).to_be_bytes());
    hasher.update((rank as u64).to_be_bytes());
    hasher.update(x_i.to_bytes());

    for point in &big_f_i_vec.coeffs {
        hasher.update(point.to_bytes());
    }

    hasher.update(r_i);

    HashBytes::new(hasher.finalize().into())
}

fn get_vsot_session_id(sender_id: usize, receiver_id: usize, session_id: &SessionId) -> SessionId {
    SessionId::new(
        Sha256::new()
            .chain_update(DKG_LABEL)
            .chain_update(session_id)
            .chain_update(b"sender_id")
            .chain_update((sender_id as u64).to_be_bytes())
            .chain_update(b"receiver_id")
            .chain_update((receiver_id as u64).to_be_bytes())
            .chain_update(b"vsot_session_id")
            .finalize()
            .into(),
    )
}

fn verfiy_dlog_proofs<'a>(
    proofs: &[DLogProof],
    points: impl Iterator<Item = &'a ProjectivePoint>,
    transcript: &mut Transcript,
) -> Result<(), KeygenError> {
    for (proof, point) in proofs.iter().zip(points) {
        proof
            .verify(point, &ProjectivePoint::GENERATOR, transcript)
            .then_some(())
            .ok_or(KeygenError::InvalidDLogProof)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::array;

    use sl_mpc_mate::coord::SimpleMessageRelay;

    use crate::setup::{keygen::*, SETUP_MESSAGE_TAG};

    use crate::keygen::utils::setup_keygen;

    #[test]
    fn r0() {
        assert!(true);
    }

    // (flavor = "multi_thread")
    #[tokio::test(flavor = "multi_thread")]
    async fn r1() {
        let coord = SimpleMessageRelay::new();

        let mut parties = JoinSet::new();
        for (setup, seed) in setup_keygen(2, 3, Some(&[0, 1, 1])).into_iter() {
            parties.spawn(run(setup, seed, coord.connect()));
        }

        while let Some(fini) = parties.join_next().await {
            let fini = fini.unwrap();

            if let Err(ref err) = fini {
                println!("error {}", err);
            }

            assert!(fini.is_ok());

            let share = fini.unwrap();

            println!(
                "PK {}",
                share
                    .public_key
                    .to_bytes()
                    .iter()
                    .map(|v| format!("{:02X}", v))
                    .collect::<Vec<_>>()
                    .join(".")
            );
        }
    }
}
