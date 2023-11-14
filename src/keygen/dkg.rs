//! Distributed key generation protocol.
//
use std::collections::HashSet;

use digest::Digest;
use k256::{
    elliptic_curve::{group::GroupEncoding, subtle::ConstantTimeEq, Group},
    FieldBytes, NonZeroScalar, ProjectivePoint, Scalar, Secp256k1,
};
use merlin::Transcript;
use rand::prelude::*;
use rand_chacha::ChaCha20Rng;
use sha2::Sha256;

#[cfg(feature = "milti-thread")]
use tokio::task::{block_in_place, JoinHandle};

#[cfg(not(feature = "milti-thread"))]
fn block_in_place<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    f()
}

use sl_oblivious::{
    endemic_ot::{EndemicOTReceiver, EndemicOTSender, RecR1, BATCH_SIZE},
    soft_spoken::{build_pprf, eval_pprf},
    soft_spoken_mod::SOFT_SPOKEN_K,
    utils::TranscriptProtocol,
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
    proto::{create_abort_message, Wrap},
    setup::{keygen::ValidatedSetup, PartyInfo, ABORT_MESSAGE_TAG},
};

/// Seed for our RNG
pub type Seed = <ChaCha20Rng as SeedableRng>::Seed;

type Pairs<T> = crate::pairs::Pairs<T>;

fn pop_tag<T>(msg_map: &mut Vec<(MsgId, T)>, id: &MsgId) -> Option<T> {
    if let Some(idx) = msg_map.iter().position(|prev| prev.0.eq(id)) {
        let (_, tag) = msg_map.swap_remove(idx);
        return Some(tag);
    }

    println!("unexpected message {:X}", id);

    None
}

// Request broadcast or P2P message from other parties.
//
// We do not request messages directly from other parties; instead, we
// inform a message relay to send us a message with the given message
// ID when it get one.
//
// Return a vector of pairs (MsgId, party_id) so that when a message
// arrives, we can process it appropriately.
async fn request_messages<R: Relay>(
    setup: &ValidatedSetup,
    tag: MessageTag,
    relay: &mut R,
    p2p: bool,
) -> Result<Vec<(MsgId, u8)>, KeygenError> {
    let mut tags = Vec::with_capacity(setup.participants() as usize - 1);
    let me = if p2p { Some(setup.party_id()) } else { None };

    for (p, vk) in setup.other_parties_iter() {
        // A message from party VK (p) to me.
        let msg_id = setup.msg_id_from(vk, me, tag);

        tracing::debug!(
            "ask msg {:X} tag {:?} {} p2p {}",
            msg_id,
            tag,
            setup.party_id(),
            p2p
        );

        let msg = AskMsg::allocate(&msg_id, setup.ttl().as_secs() as _);

        tags.push((msg_id, p));

        relay
            .feed(msg)
            .await
            .map_err(|_| KeygenError::SendMessage)?;
    }

    relay.flush().await.map_err(|_| KeygenError::SendMessage)?;

    Ok(tags)
}

fn decode_signed_message<T: bincode::Decode>(
    tags: &mut Vec<(MsgId, u8)>,
    mut msg: Vec<u8>,
    setup: &ValidatedSetup,
) -> Result<(T, u8), InvalidMessage> {
    let msg = Message::from_buffer(&mut msg)?;
    let mid = msg.id();

    let party_id = pop_tag(tags, &mid).ok_or(InvalidMessage::RecvError)?;

    let msg = msg.verify_and_decode(setup.party_verifying_key(party_id).unwrap())?;

    tracing::debug!("got msg {:X} {}", mid, setup.party_id());

    Ok((msg, party_id))
}

fn decode_encrypted_message<T: bincode::Decode>(
    tags: &mut Vec<(MsgId, u8)>,
    mut msg: Vec<u8>,
    secret: &ReusableSecret,
    enc_pub_keys: &[PublicKey],
) -> Result<(T, u8), InvalidMessage> {
    let mut msg = Message::from_buffer(&mut msg)?;
    let mid = msg.id();

    let party_id = pop_tag(tags, &mid).ok_or(InvalidMessage::RecvError)?;

    let msg = msg.decrypt_and_decode(
        MESSAGE_HEADER_SIZE,
        secret,
        &enc_pub_keys[party_id as usize],
    )?;

    tracing::debug!("got msg {:X} p2p", mid);

    Ok((msg, party_id))
}

fn check_abort_message(tags: &[(MsgId, u8)], msg: &[u8]) -> Result<(), KeygenError> {
    let hdr = MsgHdr::from(msg).ok_or(KeygenError::InvalidMessage)?;

    match tags.iter().find(|(id, _)| *id == hdr.id).map(|(_, p)| p) {
        None => Ok(()),
        Some(p) => Err(KeygenError::AbortProtocol(*p)),
    }
}

async fn handle_encrypted_messages<T, R, F>(
    setup: &ValidatedSetup,
    enc_key: &ReusableSecret,
    enc_pub_key: &[PublicKey],
    abort_tags: &[(MsgId, u8)],
    relay: &mut R,
    tag: MessageTag,
    mut handler: F,
) -> Result<(), KeygenError>
where
    T: bincode::Decode,
    R: Relay,
    F: FnMut(T, u8) -> Result<Option<Vec<u8>>, KeygenError>,
{
    let mut tags = request_messages(setup, tag, relay, true).await?;
    while !tags.is_empty() {
        let msg = relay.next().await.ok_or(KeygenError::MissingMessage)?;

        check_abort_message(abort_tags, &msg)?;

        let (msg, party_id) = decode_encrypted_message(&mut tags, msg, enc_key, enc_pub_key)?;

        if let Some(replay) = handler(msg, party_id)? {
            relay
                .send(replay)
                .await
                .map_err(|_| KeygenError::SendMessage)?;
        }
    }

    Ok(())
}

/// Execute DKG protocol.
pub async fn run<R>(
    setup: ValidatedSetup,
    seed: Seed,
    mut relay: R,
) -> Result<Keyshare, KeygenError>
where
    R: Relay,
{
    let abort_msg = create_abort_message(setup.instance(), setup.ttl(), setup.signing_key());

    match run_inner(setup, seed, |_| {}, &mut relay, None).await {
        Ok(share) => Ok(share),
        Err(KeygenError::AbortProtocol(p)) => Err(KeygenError::AbortProtocol(p)),
        Err(KeygenError::SendMessage) => Err(KeygenError::SendMessage),
        Err(err) => {
            tracing::debug!("sending abort message");
            relay.send(abort_msg).await?;
            Err(err)
        }
    }
}

#[cfg(feature = "milti-thread")]
/// A version of DKG that returns a public key as soon as possbile and
/// continues execution of the rest of the protocol in background.
///
/// The caller should await the handle to receive resulting keyshare.
pub async fn fast_pk<R, F>(
    setup: ValidatedSetup,
    seed: Seed,
    mut relay: R,
) -> Result<(ProjectivePoint, JoinHandle<Result<Keyshare, KeygenError>>), KeygenError>
where
    R: Relay + Send,
{
    let (tx, rx) = tokio::sync::oneshot::channel();

    let recv_pk = move |pk| {
        // Ignore error here.
        //
        // If it returns OK it doesn't mean that the value is actually received.
        // It it returns Err than the value can't be sent at all and the can not
        // handle error in any way.
        //
        let _ = tx.send(pk);
    };

    // just some x_i value not used for key generation
    let x_i = NonZeroScalar::new(Scalar::ONE).unwrap();
    let handle =
        tokio::spawn(async move { run_inner(setup, seed, recv_pk, &mut relay, x_i, false).await });

    // If rx.await returns Err, then sender was dropped without sending
    // PK. This mean that run_inner() is finished at this point.
    // Convert error and fail without return join handle.
    let pk = rx.await.map_err(|_| KeygenError::NoPublicKey)?;

    // Everything looks good, let's be optimistic
    Ok((pk, handle))
}

/// Implementation of DKG protocol.
///
/// `setup` contains all parameters, including verfication keys of all
/// parties and our own signing key.
///
/// `seed` is used to initialize instance of ChaCha20Rng random number
/// generator. This generator used to generate *ALL* random values for DKG.
///
/// `reck_pk` is a cloure that receives a newly generateed public key
/// in the middle of execution of thr DKG protocol.
///
/// And optional `x_i` is allow to reused the function for key
/// rotation protocol.
///
pub(crate) async fn run_inner<R, F>(
    setup: ValidatedSetup,
    seed: Seed,
    recv_pk: F,
    relay: &mut R,
    x_i: Option<&NonZeroScalar>,
) -> Result<Keyshare, KeygenError>
where
    R: Relay,
    F: FnOnce(ProjectivePoint),
{
    let key_refresh = x_i.is_some();

    let mut rng = ChaCha20Rng::from_seed(seed);
    let mut nonce_counter = NonceCounter::new();

    #[allow(non_snake_case)]
    let T = setup.threshold() as usize;
    #[allow(non_snake_case)]
    let N = setup.participants() as usize;

    let my_party_id = setup.party_id();

    let session_id = SessionId::new(rng.gen());
    let r_i = rng.gen();

    // u_i_k
    let mut polynomial = Polynomial::random(&mut rng, T - 1);

    if key_refresh {
        polynomial.coeffs[0] = Scalar::ZERO;
    }

    let x_i = match x_i {
        Some(x_i) => *x_i,
        None => NonZeroScalar::random(&mut rng),
    };

    let enc_key = ReusableSecret::random_from_rng(&mut rng);

    let big_f_i_vec = polynomial.commit(); // big_f_i_vector in dkg.py

    let commitment = hash_commitment(
        &session_id,
        setup.party_id() as usize,
        setup.rank() as usize,
        &x_i,
        &big_f_i_vec,
        &r_i,
    );

    let mut d_i_list = vec_init(
        N,
        my_party_id,
        block_in_place(|| polynomial.derivative_at(setup.rank() as usize, &x_i)),
    );

    let abort_tags = request_messages(&setup, ABORT_MESSAGE_TAG, relay, false).await?;

    let (sid_i_list, commitment_list, x_i_list, enc_pub_key) = broadcast_4(
        &setup,
        &abort_tags,
        relay,
        DKG_MSG_R1,
        (session_id, commitment, x_i, PublicKey::from(&enc_key)),
    )
    .await?;

    // tracing::info!("R1 done {}", setup.party_id());

    // Check that x_i_list contains unique elements
    if HashSet::<FieldBytes>::from_iter(x_i_list.iter().map(|x| x.to_bytes())).len()
        != x_i_list.len()
    {
        return Err(KeygenError::NotUniqueXiValues);
    }

    // TODO: Should parties be initialized with rank_list and x_i_list? Ask Vlad.
    let final_session_id = SessionId::new(
        sid_i_list
            .iter()
            .fold(Sha256::new(), |hash, sid| hash.chain_update(sid))
            .finalize()
            .into(),
    );

    let dlog_proofs = {
        // Setup transcript for DLog proofs.
        let mut dlog_transcript = Transcript::new_dlog_proof(
            &final_session_id,
            setup.party_id() as usize,
            DLOG_PROOF1_LABEL,
            DKG_LABEL,
        );

        polynomial
            .iter()
            .map(|f_i| {
                DLogProof::prove(
                    f_i,
                    &ProjectivePoint::GENERATOR,
                    &mut dlog_transcript,
                    &mut rng,
                )
            })
            .collect::<Vec<_>>()
    };

    let mut base_ot_senders = make_base_ot_senders(&setup, &final_session_id, &mut rng);
    let (mut base_ot_receivers, to_send) = make_base_ot_receivers(
        &setup,
        &final_session_id,
        &enc_pub_key,
        &enc_key,
        &mut nonce_counter,
        &mut rng,
    )?;

    // send out R2 P2P messages. We call feed() in the loop
    // and following send_broadcast() will call .send() that
    // implies feed() + flush()
    for msg in to_send.into_iter() {
        relay
            .feed(msg)
            .await
            .map_err(|_| KeygenError::SendMessage)?;
    }

    // generate chain_code_sid for root_chain_code
    let chain_code_sid = SessionId::new(rng.gen());
    let r_i_2 = rng.gen();

    let (big_f_i_vecs, r_i_list, commitment_list_2, dlog_proofs_i_list) = broadcast_4(
        &setup,
        &abort_tags,
        relay,
        DKG_MSG_R2,
        (
            big_f_i_vec,
            r_i,
            hash_commitment_2(&final_session_id, &chain_code_sid, &r_i_2),
            dlog_proofs,
        ),
    )
    .await?;

    for party_id in 0..N {
        let r_i = &r_i_list[party_id];
        let x_i = &x_i_list[party_id];
        let sid = &sid_i_list[party_id];
        let commitment = &commitment_list[party_id];
        let big_f_i_vector = &big_f_i_vecs[party_id];

        let commit_hash = hash_commitment(
            sid,
            party_id,
            setup.party_rank(party_id as u8).unwrap() as usize,
            x_i,
            big_f_i_vector,
            r_i,
        );

        if commit_hash.ct_ne(commitment).into() {
            return Err(KeygenError::InvalidCommitmentHash);
        }

        {
            let mut points = big_f_i_vector.points();
            if key_refresh {
                // for key refresh first point should be IDENTITY
                if points.next() != Some(&ProjectivePoint::IDENTITY) {
                    return Err(KeygenError::InvalidPolynomialPoint);
                }
            }
            if points.any(|p| p.is_identity().into()) {
                return Err(KeygenError::InvalidPolynomialPoint);
            }
        }

        verfiy_dlog_proofs(
            &final_session_id,
            party_id,
            &dlog_proofs_i_list[party_id],
            big_f_i_vector.points(),
        )?;
    }
    // tracing::info!("R2 broadcast done {}", setup.party_id());

    // 6.d
    let mut big_f_vec = GroupPolynomial::identity(T);
    for v in big_f_i_vecs.iter() {
        big_f_vec.add_mut(v); // big_f_vec += v; big_vec +
    }

    let public_key = *big_f_vec.get_constant();

    if key_refresh {
        // check that public_key == IDENTITY
        if public_key != ProjectivePoint::IDENTITY {
            return Err(KeygenError::InvalidPolynomialPoint);
        }
    }

    recv_pk(public_key);

    let mut seed_ot_senders = Pairs::new();
    let mut seed_i_j_list = Pairs::new();

    handle_encrypted_messages(
        &setup,
        &enc_key,
        &enc_pub_key,
        &abort_tags,
        relay,
        DKG_MSG_R2,
        |base_ot_msg1, party_id| {
            let rank = setup.party_rank(party_id).unwrap();
            let sender = base_ot_senders.pop_pair(party_id);

            let (sender_output, base_ot_msg2) = block_in_place(|| sender.process(base_ot_msg1));

            let (all_but_one_sender_seed, pprf_output) = build_pprf(
                &final_session_id,
                &sender_output,
                BATCH_SIZE as u32,
                SOFT_SPOKEN_K as u8,
            );

            seed_ot_senders.push(party_id, all_but_one_sender_seed);

            let seed_i_j = if party_id > my_party_id {
                let seed_i_j = rng.gen();
                seed_i_j_list.push(party_id, seed_i_j);
                Some(seed_i_j)
            } else {
                None
            };

            let x_i = &x_i_list[party_id as usize];
            let d_i = block_in_place(|| polynomial.derivative_at(rank as usize, x_i));

            let msg3 = KeygenMsg3 {
                base_ot_msg2,
                pprf_output,
                seed_i_j,
                d_i: Opaque::from(d_i),
                big_f_vec: big_f_vec.clone(),
                chain_code_sid: Opaque::from(chain_code_sid),
                r_i_2: Opaque::from(r_i_2),
            };
            Ok(Some(Builder::<Encrypted>::encode(
                &setup.msg_id(Some(party_id), DKG_MSG_R3),
                setup.ttl(),
                &enc_key,
                &enc_pub_key[party_id as usize],
                &msg3,
                nonce_counter.next_nonce(),
            )?))
        },
    )
    .await?;

    // tracing::info!("R2 P2P done {}", setup.party_id());

    let mut seed_ot_receivers = Pairs::new();
    let mut rec_seed_list = Pairs::new();
    let mut chain_code_sids = Pairs::new_with_item(my_party_id, chain_code_sid);

    handle_encrypted_messages(
        &setup,
        &enc_key,
        &enc_pub_key,
        &abort_tags,
        relay,
        DKG_MSG_R3,
        |msg3: KeygenMsg3, party_id| {
            if msg3.big_f_vec != big_f_vec {
                return Err(KeygenError::BigFVecMismatch);
            }

            d_i_list[party_id as usize] = *msg3.d_i;

            let receiver = base_ot_receivers.pop_pair(party_id);
            let receiver_output = block_in_place(|| receiver.process(msg3.base_ot_msg2));
            let all_but_one_receiver_seed = eval_pprf(
                &final_session_id,
                &receiver_output,
                256,
                SOFT_SPOKEN_K as u8,
                msg3.pprf_output,
            )
            .map_err(KeygenError::PPRFError)?;

            seed_ot_receivers.push(party_id, all_but_one_receiver_seed);
            if let Some(seed_j_i) = msg3.seed_i_j {
                rec_seed_list.push(party_id, seed_j_i);
            }

            // Verify commitments
            let commitment_2 = &commitment_list_2[party_id as usize];
            let commit_hash =
                hash_commitment_2(&final_session_id, &msg3.chain_code_sid, &msg3.r_i_2);
            bool::from(commit_hash.ct_eq(commitment_2))
                .then_some(())
                .ok_or(KeygenError::InvalidCommitmentHash)?;

            chain_code_sids.push(party_id, *msg3.chain_code_sid);

            Ok(None)
        },
    )
    .await?;

    // tracing::info!("R3 P2P done {}", setup.party_id());

    // Generate common root_chain_code from chain_code_sids
    let root_chain_code: [u8; 32] = chain_code_sids
        .iter()
        .fold(Sha256::new(), |hash, (_, sid)| hash.chain_update(sid))
        .finalize()
        .into();

    for (big_f_i_vec, f_i_val) in big_f_i_vecs.iter().zip(d_i_list.iter()) {
        let coeffs = block_in_place(|| big_f_i_vec.derivative_coeffs(setup.rank() as usize));
        let valid = feldman_verify(
            &coeffs,
            &x_i_list[my_party_id as usize],
            f_i_val,
            &ProjectivePoint::GENERATOR,
        )
        .expect("u_i_k cannot be empty");

        if !valid {
            return Err(KeygenError::FailedFelmanVerify);
        }
    }

    let s_i: Scalar = d_i_list.iter().sum();
    let big_s_i = ProjectivePoint::GENERATOR * s_i;

    let proof = {
        let mut transcript = Transcript::new_dlog_proof(
            &final_session_id,
            setup.party_id() as usize,
            DLOG_PROOF2_LABEL,
            DKG_LABEL,
        );

        DLogProof::prove(&s_i, &ProjectivePoint::GENERATOR, &mut transcript, &mut rng)
    };

    let (_, public_key_list, big_s_list, proof_list) = broadcast_4(
        &setup,
        &abort_tags,
        relay,
        DKG_MSG_R4,
        (final_session_id, public_key, big_s_i, proof),
    )
    .await?;

    if public_key_list.into_iter().any(|pk| pk != public_key) {
        return Err(KeygenError::PublicKeyMismatch);
    }

    for (party_id, (big_s_i, dlog_proof)) in
        big_s_list.iter().zip(proof_list.into_iter()).enumerate()
    {
        if party_id == my_party_id as usize {
            continue;
        }

        let mut transcript =
            Transcript::new_dlog_proof(&final_session_id, party_id, DLOG_PROOF2_LABEL, DKG_LABEL);
        if !dlog_proof.verify(big_s_i, &ProjectivePoint::GENERATOR, &mut transcript) {
            return Err(KeygenError::InvalidDLogProof);
        }
    }

    for (party_id, x_i) in x_i_list.iter().enumerate() {
        let party_rank = setup.party_rank(party_id as u8).unwrap();

        // TODO: polynomial_coeff_multipliers() should return iterator
        let coeff_multipliers = polynomial_coeff_multipliers(x_i, party_rank as usize, N);

        let expected_point: ProjectivePoint = big_f_vec
            .points()
            .zip(coeff_multipliers)
            .map(|(point, coeff)| point * &coeff)
            .sum();

        if expected_point != big_s_list[party_id] {
            return Err(KeygenError::BigSMismatch);
        }
    }

    // TODO:(sushi) Only for birkhoff now (with ranks), support lagrange later.
    let rank_list = setup.all_party_ranks();

    // FIXME: do we need this?
    check_secret_recovery(&x_i_list, &rank_list, &big_s_list, &public_key)?;

    let share = Keyshare {
        magic: Keyshare::MAGIC, // marker of current version Keyshare

        total_parties: setup.participants(),
        threshold: setup.threshold(),
        party_id: my_party_id,
        rank_list,
        public_key: Opaque::from(public_key),
        root_chain_code,
        x_i_list: x_i_list.into_iter().map(Opaque::from).collect(), // FIXME
        big_s_list: big_s_list.into_iter().map(Opaque::from).collect(),
        s_i: Opaque::from(s_i),
        sent_seed_list: seed_i_j_list.remove_ids(),
        seed_ot_receivers: seed_ot_receivers.remove_ids(),
        seed_ot_senders: seed_ot_senders.remove_ids(),
        rec_seed_list: rec_seed_list.remove_ids(),
    };

    Ok(share)
}

fn vec_init<T: Default + Clone>(size: usize, id: u8, init: T) -> Vec<T> {
    let mut v = vec![Default::default(); size];

    v[id as usize] = init;

    v
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

fn hash_commitment_2(
    session_id: &SessionId,
    chain_code_sid: &SessionId,
    r_i: &[u8; 32],
) -> HashBytes {
    let mut hasher = Sha256::new();
    hasher.update(b"SL-ChainCodeSID-Commitment");
    hasher.update(session_id);
    hasher.update(chain_code_sid);
    hasher.update(r_i);

    HashBytes::new(hasher.finalize().into())
}

async fn send_broadcast<T, R>(
    setup: &ValidatedSetup,
    relay: &mut R,
    tag: MessageTag,
    msg: T,
) -> Result<(), KeygenError>
where
    T: bincode::Encode,
    R: Relay,
{
    relay
        .send(Builder::<Signed>::encode(
            &setup.msg_id(None, tag),
            setup.ttl(),
            setup.signing_key(),
            &msg,
        )?)
        .await
        .map_err(|_| KeygenError::SendMessage)?;

    Ok(())
}

fn make_base_ot_senders<R: RngCore + CryptoRng>(
    setup: &ValidatedSetup,
    final_session_id: &SessionId,
    rng: &mut R,
) -> Pairs<EndemicOTSender> {
    setup
        .other_parties_iter()
        .map(|(p, _)| {
            (
                p,
                EndemicOTSender::new(
                    get_base_ot_session_id(p as usize, setup.party_id() as usize, final_session_id),
                    rng,
                ),
            )
        })
        .collect::<Vec<_>>()
        .into()
}

#[allow(clippy::type_complexity)]
fn make_base_ot_receivers<R: RngCore + CryptoRng>(
    setup: &ValidatedSetup,
    final_session_id: &SessionId,
    enc_pub_key: &[PublicKey],
    enc_keys: &ReusableSecret,
    nonce_counter: &mut NonceCounter,
    rng: &mut R,
) -> Result<(Pairs<EndemicOTReceiver<RecR1>>, Vec<Vec<u8>>), KeygenError> {
    let mut to_send = vec![];
    let base_ot_receivers: Pairs<EndemicOTReceiver<RecR1>> = setup
        .other_parties_iter()
        .map(|(p, _vk)| {
            (
                p,
                setup.msg_id_from(&setup.verifying_key(), Some(p), DKG_MSG_R2),
                rng.gen(),
                &enc_pub_key[p as usize],
                nonce_counter.next_nonce(),
            )
        })
        .map(|(p, msg_id, seed, enc_pk, nonce)| {
            let mut rng = ChaCha20Rng::from_seed(seed); // TODO check!!!

            let base_ot_session_id =
                get_base_ot_session_id(setup.party_id() as usize, p as usize, final_session_id);

            let (receiver, msg1) = EndemicOTReceiver::new(base_ot_session_id, &mut rng);

            to_send.push(Builder::<Encrypted>::encode(
                &msg_id,
                setup.ttl(),
                enc_keys,
                enc_pk,
                &msg1,
                nonce,
            )?);

            Ok((p, receiver))
        })
        .collect::<Result<Vec<_>, KeygenError>>()?
        .into();

    Ok((base_ot_receivers, to_send))
}

fn get_base_ot_session_id(
    sender_id: usize,
    receiver_id: usize,
    session_id: &SessionId,
) -> SessionId {
    SessionId::new(
        Sha256::new()
            .chain_update(DKG_LABEL)
            .chain_update(session_id)
            .chain_update(b"sender_id")
            .chain_update((sender_id as u64).to_be_bytes())
            .chain_update(b"receiver_id")
            .chain_update((receiver_id as u64).to_be_bytes())
            .chain_update(b"base_ot_session_id")
            .finalize()
            .into(),
    )
}

fn verfiy_dlog_proofs<'a>(
    final_session_id: &SessionId,
    party_id: usize,
    proofs: &[DLogProof],
    points: impl Iterator<Item = &'a ProjectivePoint>,
) -> Result<(), KeygenError> {
    let mut dlog_transcript =
        Transcript::new_dlog_proof(final_session_id, party_id, DLOG_PROOF1_LABEL, DKG_LABEL);

    for (proof, point) in proofs.iter().zip(points) {
        proof
            .verify(point, &ProjectivePoint::GENERATOR, &mut dlog_transcript)
            .then_some(())
            .ok_or(KeygenError::InvalidDLogProof)?;
    }

    Ok(())
}

async fn broadcast_4<R, T1, T2, T3, T4>(
    setup: &ValidatedSetup,
    abort_tags: &[(MsgId, u8)],
    relay: &mut R,
    tag: MessageTag,
    msg: (T1, T2, T3, T4),
) -> Result<(Vec<T1>, Vec<T2>, Vec<T3>, Vec<T4>), KeygenError>
where
    R: Relay,
    T1: Wrap,
    T2: Wrap,
    T3: Wrap,
    T4: Wrap,
{
    let msg = (msg.0.wrap(), msg.1.wrap(), msg.2.wrap(), msg.3.wrap());
    send_broadcast(setup, relay, tag, &msg).await?;

    fn unwrap<T: Wrap>(v: <T as Wrap>::Wrapped) -> T {
        <T as Wrap>::unwrap(v)
    }

    let mut p0 = Pairs::new_with_item(setup.party_id(), unwrap(msg.0));
    let mut p1 = Pairs::new_with_item(setup.party_id(), unwrap(msg.1));
    let mut p2 = Pairs::new_with_item(setup.party_id(), unwrap(msg.2));
    let mut p3 = Pairs::new_with_item(setup.party_id(), unwrap(msg.3));

    let mut tags = request_messages(setup, tag, relay, false).await?;
    while !tags.is_empty() {
        let msg = relay.next().await.ok_or(KeygenError::MissingMessage)?;

        check_abort_message(abort_tags, &msg)?;

        let (msg, party_id) = decode_signed_message::<(
            <T1 as Wrap>::Wrapped,
            <T2 as Wrap>::Wrapped,
            <T3 as Wrap>::Wrapped,
            <T4 as Wrap>::Wrapped,
        )>(&mut tags, msg, setup)?;

        p0.push(party_id, unwrap(msg.0));
        p1.push(party_id, unwrap(msg.1));
        p2.push(party_id, unwrap(msg.2));
        p3.push(party_id, unwrap(msg.3));
    }

    Ok((
        p0.into_removed_ids(),
        p1.into_removed_ids(),
        p2.into_removed_ids(),
        p3.into_removed_ids(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    use tokio::task::JoinSet;

    use sl_mpc_mate::coord::SimpleMessageRelay;

    use crate::keygen::utils::setup_keygen;

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
