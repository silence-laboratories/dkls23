// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! Distributed key generation protocol.
//! Based on Protocol 6.1 https://eprint.iacr.org/2022/374.pdf

use k256::{
    elliptic_curve::{
        group::GroupEncoding,
        subtle::{Choice, ConstantTimeEq},
        Group,
    },
    NonZeroScalar, ProjectivePoint, Scalar,
};
use merlin::Transcript;
use rand::prelude::*;
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};

use sl_mpc_mate::{
    coord::*,
    math::{
        feldman_verify, polynomial_coeff_multipliers, GroupPolynomial,
        Polynomial,
    },
    message::*,
    SessionId,
};

use sl_oblivious::{
    endemic_ot::{EndemicOTMsg1, EndemicOTReceiver, EndemicOTSender},
    soft_spoken::{build_pprf, eval_pprf},
    utils::TranscriptProtocol,
    zkproofs::DLogProof,
};

use crate::{
    keygen::{
        constants::*, messages::*, utils::check_secret_recovery, KeygenError,
        Keyshare,
    },
    proto::{tags::*, *},
    setup::{KeygenSetupMessage, ProtocolParticipant, ABORT_MESSAGE_TAG},
};

#[cfg(feature = "multi-thread")]
use tokio::task::block_in_place;

#[cfg(not(feature = "multi-thread"))]
fn block_in_place<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    f()
}

/// Seed for our RNG
pub type Seed = <ChaCha20Rng as SeedableRng>::Seed;

use crate::pairs::Pairs;

pub(crate) struct KeyRefreshData {
    /// Additive share of participant_i (after interpolation)
    /// \sum_{i=0}^{n-1} s_i_0 = private_key
    /// s_i_0 can be equal to Zero in case when participant lost their key_share
    /// and wants to recover it during key_refresh
    pub(crate) s_i_0: Scalar,

    /// list of participants ids who lost their key_shares
    /// should be in range [0, n-1]
    pub(crate) lost_keyshare_party_ids: Vec<u8>,

    /// expected public key for key_refresh
    pub(crate) expected_public_key: ProjectivePoint,

    /// root_chain_code
    pub(crate) root_chain_code: [u8; 32],
}

/// Execute DKG protocol.
pub async fn run<T, R>(
    setup: T,
    seed: Seed,
    relay: R,
) -> Result<Keyshare, KeygenError>
where
    T: KeygenSetupMessage,
    R: Relay,
{
    let abort_msg = create_abort_message(&setup);
    let mut relay = FilteredMsgRelay::new(relay);

    let result = match run_inner(setup, seed, &mut relay, None).await {
        Ok(share) => Ok(share),
        Err(KeygenError::AbortProtocol(p)) => {
            Err(KeygenError::AbortProtocol(p))
        }
        Err(KeygenError::SendMessage) => Err(KeygenError::SendMessage),
        Err(err) => {
            // ignore error of sending abort message
            let _ = relay.send(abort_msg).await;
            Err(err)
        }
    };

    let _ = relay.close().await;

    result
}

/// Implementation of DKG protocol.
///
/// `setup` contains all parameters, including verfication keys of all
/// parties and our own signing key.
///
/// `seed` is used to initialize instance of ChaCha20Rng random number
/// generator. This generator used to generate *ALL* random values for DKG.
///
/// And optional `key_refresh_data` is allow to reused the function for key
/// rotation protocol.
///
#[allow(non_snake_case)]
pub(crate) async fn run_inner<T, R>(
    setup: T,
    seed: Seed,
    relay: &mut FilteredMsgRelay<R>,
    key_refresh_data: Option<&KeyRefreshData>,
) -> Result<Keyshare, KeygenError>
where
    T: KeygenSetupMessage,
    R: Relay,
{
    let mut rng = ChaCha20Rng::from_seed(seed);

    let mut scheme = crate::proto::Scheme::new(&mut rng);

    let T = setup.threshold() as usize;
    let N = setup.total_participants();

    let my_party_id = setup.participant_index() as u8;
    let my_rank = setup.participant_rank(my_party_id as usize);

    if let Some(v) = key_refresh_data {
        let cond1 = v.expected_public_key == ProjectivePoint::IDENTITY;
        let cond2 = v.lost_keyshare_party_ids.len() > (N - T);
        let cond3 = (v.s_i_0 == Scalar::ZERO)
            && (!v.lost_keyshare_party_ids.contains(&my_party_id));
        if cond1 || cond2 || cond3 {
            return Err(KeygenError::InvalidKeyRefresh);
        }
    }

    let mut keyshare =
        Keyshare::new(N as u8, T as u8, my_party_id, setup.keyshare_extra());

    let session_id = SessionId::new(rng.gen());
    let r_i = rng.gen();

    // u_i_k
    let mut polynomial = Polynomial::random(&mut rng, T - 1);
    if let Some(v) = key_refresh_data {
        polynomial.set_constant(v.s_i_0);
    }

    let x_i = NonZeroScalar::random(&mut rng);

    let big_f_i_vec = polynomial.commit(); // big_f_i_vector in dkg.py

    let commitment = hash_commitment(
        &session_id,
        my_party_id as usize,
        setup.participant_rank(my_party_id as usize) as usize,
        &x_i,
        &big_f_i_vec,
        &r_i,
    );

    let mut d_i_list = vec![Scalar::ZERO; N];
    d_i_list[my_party_id as usize] =
        block_in_place(|| polynomial.derivative_at(my_rank as usize, &x_i));

    relay.ask_messages(&setup, ABORT_MESSAGE_TAG, false).await?;
    relay.ask_messages(&setup, DKG_MSG_R1, false).await?;
    relay.ask_messages(&setup, DKG_MSG_R2, false).await?;
    relay.ask_messages(&setup, DKG_MSG_OT1, true).await?;
    relay.ask_messages(&setup, DKG_MSG_R3, true).await?;
    relay.ask_messages(&setup, DKG_MSG_R4, false).await?;

    let (sid_i_list, commitment_list, x_i_list, enc_pub_key) = broadcast_4(
        &setup,
        relay,
        DKG_MSG_R1,
        (session_id, commitment, x_i, scheme.public_key().to_vec()),
    )
    .await?;

    for (receiver, pub_key) in enc_pub_key.into_iter().enumerate() {
        if receiver != setup.participant_index() {
            scheme
                .receiver_public_key(receiver, &pub_key)
                .map_err(|_| KeygenError::InvalidMessage)?;
        }
    }

    // Check that x_i_list contains unique elements.
    // N is small and following loops doesn't  allocate.
    for i in 0..x_i_list.len() - 1 {
        let x = &x_i_list[i];
        for s in &x_i_list[i + 1..] {
            if x.ct_eq(s).into() {
                return Err(KeygenError::NotUniqueXiValues);
            }
        }
    }

    // TODO: Should parties be initialized with rank_list and x_i_list? Ask Vlad.
    keyshare.info_mut().final_session_id = sid_i_list
        .iter()
        .fold(Sha256::new(), |hash, sid| hash.chain_update(sid))
        .finalize()
        .into();

    let dlog_proofs = {
        // Setup transcript for DLog proofs.
        let mut dlog_transcript = Transcript::new_dlog_proof(
            &keyshare.final_session_id,
            my_party_id as usize,
            &DLOG_PROOF1_LABEL,
            &DKG_LABEL,
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

    let mut base_ot_receivers: Pairs<EndemicOTReceiver> = Pairs::new();

    for receiver_id in setup.all_other_parties() {
        let sid = get_base_ot_session_id(
            my_party_id,
            receiver_id as u8,
            &keyshare.final_session_id,
        );

        let mut enc_msg1 = EncryptedMessage::<EndemicOTMsg1>::new(
            &setup.msg_id(Some(receiver_id), DKG_MSG_OT1),
            setup.message_ttl().as_secs() as u32,
            0,
            0,
            &scheme,
        );

        let (msg1, _) = enc_msg1.payload(&scheme);

        let receiver = EndemicOTReceiver::new(&sid, msg1, &mut rng);

        base_ot_receivers.push(receiver_id as u8, receiver);

        // send out R2 P2P message. We call feed() in the loop
        // and following send_broadcast() will call .send() that
        // implies feed() + flush()
        relay
            .feed(
                enc_msg1
                    .encrypt(&mut scheme, receiver_id)
                    .ok_or(KeygenError::SendMessage)?,
            )
            .await
            .map_err(|_| KeygenError::SendMessage)?;
    }

    #[cfg(feature = "tracing")]
    tracing::debug!("feed all OT1");

    // generate chain_code_sid for root_chain_code or use already existed from key_refresh_data
    let chain_code_sid = if let Some(v) = key_refresh_data {
        v.root_chain_code
    } else {
        SessionId::new(rng.gen()).into()
    };
    let r_i_2 = rng.gen();

    let (big_f_i_vecs, r_i_list, commitment_list_2, dlog_proofs_i_list) =
        broadcast_4(
            &setup,
            relay,
            DKG_MSG_R2,
            (
                big_f_i_vec,
                r_i,
                hash_commitment_2(
                    &keyshare.final_session_id,
                    &chain_code_sid,
                    &r_i_2,
                ),
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
        let dlog_proofs_i = &dlog_proofs_i_list[party_id];

        if big_f_i_vector.coeffs.len() != T {
            return Err(KeygenError::InvalidMessage);
        }
        if dlog_proofs_i.len() != T {
            return Err(KeygenError::InvalidMessage);
        }

        let commit_hash = hash_commitment(
            sid,
            party_id,
            setup.participant_rank(party_id) as usize,
            x_i,
            big_f_i_vector,
            r_i,
        );

        if commit_hash.ct_ne(commitment).into() {
            return Err(KeygenError::InvalidCommitmentHash);
        }

        {
            let mut points = big_f_i_vector.points();
            if let Some(v) = key_refresh_data {
                if v.lost_keyshare_party_ids.contains(&(party_id as u8)) {
                    // for participant who lost their key_share, first point should be IDENTITY
                    if points.next() != Some(&ProjectivePoint::IDENTITY) {
                        return Err(KeygenError::InvalidPolynomialPoint);
                    }
                }
            }
            if points.any(|p| p.is_identity().into()) {
                return Err(KeygenError::InvalidPolynomialPoint);
            }
        }

        verify_dlog_proofs(
            &keyshare.final_session_id,
            party_id,
            dlog_proofs_i,
            &big_f_i_vector.coeffs,
        )?;
    }

    // 6.d
    let mut big_f_vec = GroupPolynomial::identity(T);
    for v in big_f_i_vecs.iter() {
        big_f_vec.add_mut(v); // big_f_vec += v; big_vec +
    }

    let public_key = big_f_vec.get_constant();

    if let Some(v) = key_refresh_data {
        if public_key != v.expected_public_key {
            return Err(KeygenError::InvalidKeyRefresh);
        }
    }

    Round::new(setup.total_participants() - 1, DKG_MSG_OT1, relay)
        .of_encrypted_messages(
            &setup,
            &mut scheme,
            0,
            KeygenError::AbortProtocol,
            |base_ot_msg1: &EndemicOTMsg1, receiver_index, _, scheme| {
                let receiver_id = receiver_index as u8;
                let rank = setup.participant_rank(receiver_id as usize);

                let trailer = big_f_vec.external_size();

                let mut enc_buf = EncryptedMessage::<KeygenMsg3>::new(
                    &setup.msg_id(Some(receiver_id as usize), DKG_MSG_R3),
                    setup.message_ttl().as_secs() as _,
                    0,
                    trailer,
                    scheme,
                );

                let (msg3, trailer) = enc_buf.payload(scheme);

                let sender_ot_seed = {
                    let sid = get_base_ot_session_id(
                        receiver_id,
                        my_party_id,
                        &keyshare.final_session_id,
                    );

                    block_in_place(|| {
                        EndemicOTSender::process(
                            &sid,
                            base_ot_msg1,
                            &mut msg3.base_ot_msg2,
                            &mut rng,
                        )
                    })
                    .map_err(|_| KeygenError::InvalidMessage)?
                };

                let all_but_one_session_id = get_all_but_one_session_id(
                    my_party_id as usize,
                    receiver_id as usize,
                    &keyshare.final_session_id,
                );

                build_pprf(
                    &all_but_one_session_id,
                    &sender_ot_seed,
                    &mut keyshare.other_mut(receiver_id).send_ot_seed,
                    &mut msg3.pprf_output,
                );

                if receiver_id > my_party_id {
                    rng.fill_bytes(&mut msg3.seed_i_j);
                    keyshare.each_mut(receiver_id - 1).zeta_seed =
                        msg3.seed_i_j;
                };

                let x_i = &x_i_list[receiver_id as usize];
                let d_i = block_in_place(|| {
                    polynomial.derivative_at(rank as usize, x_i)
                });

                msg3.d_i = encode_scalar(&d_i);
                msg3.chain_code_sid = chain_code_sid;
                msg3.r_i_2 = r_i_2;

                big_f_vec.write(trailer);

                Ok(Some(
                    enc_buf
                        .encrypt(scheme, receiver_id as usize)
                        .ok_or(KeygenError::SendMessage)?,
                ))
            },
        )
        .await?;

    let mut chain_code_sids =
        Pairs::new_with_item(my_party_id, chain_code_sid);

    if let Some(v) = key_refresh_data {
        if v.lost_keyshare_party_ids.contains(&my_party_id) {
            chain_code_sids = Pairs::new();
        }
    }

    Round::new(setup.total_participants() - 1, DKG_MSG_R3, relay)
        .of_encrypted_messages(
            &setup,
            &mut scheme,
            big_f_vec.external_size(),
            KeygenError::AbortProtocol,
            |msg3: &KeygenMsg3, party_index, trailer, _| {
                let party_id = party_index as u8;
                let msg3_big_f_vec =
                    <GroupPolynomial<ProjectivePoint> as Wrap>::read(trailer)
                        .ok_or(KeygenError::InvalidMessage)?;

                // also checks that msg3.big_f_vec.coeffs.len() == T
                if msg3_big_f_vec != big_f_vec {
                    return Err(KeygenError::BigFVecMismatch);
                }

                d_i_list[party_id as usize] = decode_scalar(&msg3.d_i)
                    .ok_or(KeygenError::InvalidMessage)?;

                let receiver = base_ot_receivers.pop_pair(party_id);
                let receiver_output =
                    block_in_place(|| receiver.process(&msg3.base_ot_msg2))
                        .map_err(|_| KeygenError::InvalidMessage)?;
                let all_but_one_session_id = get_all_but_one_session_id(
                    party_id as usize,
                    my_party_id as usize,
                    &keyshare.final_session_id,
                );

                block_in_place(|| {
                    eval_pprf(
                        &all_but_one_session_id,
                        &receiver_output,
                        &msg3.pprf_output,
                        &mut keyshare.other_mut(party_id).recv_ot_seed,
                    )
                })
                .map_err(KeygenError::PPRFError)?;

                if party_id < my_party_id {
                    keyshare.each_mut(party_id).zeta_seed = msg3.seed_i_j;
                }

                // Verify commitments
                let commitment_2 = &commitment_list_2[party_id as usize];
                let commit_hash = hash_commitment_2(
                    &keyshare.final_session_id,
                    &msg3.chain_code_sid,
                    &msg3.r_i_2,
                );

                bool::from(commit_hash.ct_eq(commitment_2))
                    .then_some(())
                    .ok_or(KeygenError::InvalidCommitmentHash)?;

                if let Some(v) = key_refresh_data {
                    if !v.lost_keyshare_party_ids.contains(&party_id) {
                        chain_code_sids.push(party_id, msg3.chain_code_sid);
                    }
                } else {
                    chain_code_sids.push(party_id, msg3.chain_code_sid);
                }

                Ok(None)
            },
        )
        .await?;

    if key_refresh_data.is_some() {
        let chain_code_sids = chain_code_sids.remove_ids();
        if chain_code_sids.is_empty() {
            return Err(KeygenError::InvalidKeyRefresh);
        }
        let root_chain_code = chain_code_sids[0];
        if !chain_code_sids.iter().all(|&item| item == root_chain_code) {
            return Err(KeygenError::InvalidKeyRefresh);
        }
        // Use already existing root_chain_code
        keyshare.info_mut().root_chain_code = root_chain_code;
    } else {
        // Generate common root_chain_code from chain_code_sids
        keyshare.info_mut().root_chain_code = chain_code_sids
            .iter()
            .fold(Sha256::new(), |hash, (_, sid)| hash.chain_update(sid))
            .finalize()
            .into();
    }

    if big_f_i_vecs.len() != d_i_list.len() {
        return Err(KeygenError::FailedFelmanVerify);
    }

    for (big_f_i_vec, f_i_val) in big_f_i_vecs.into_iter().zip(&d_i_list) {
        let coeffs = block_in_place(|| {
            big_f_i_vec.derivative_coeffs(my_rank as usize)
        });
        let valid = feldman_verify(
            coeffs,
            &x_i_list[my_party_id as usize],
            f_i_val,
            &ProjectivePoint::GENERATOR,
        );
        if !valid {
            return Err(KeygenError::FailedFelmanVerify);
        }
    }

    let s_i: Scalar = d_i_list.iter().sum();
    let big_s_i = ProjectivePoint::GENERATOR * s_i;

    // Use the root_chain_code in the final dlog proof
    // so that all parties are sure they generated the same root_chain_code
    let final_session_id_with_root_chain_code = {
        let mut buf = [0u8; 32];
        let mut transcript = Transcript::new(&DKG_LABEL);
        transcript
            .append_message(b"final_session_id", &keyshare.final_session_id);
        transcript
            .append_message(b"root_chain_code", &keyshare.root_chain_code);
        transcript
            .challenge_bytes(&DLOG_SESSION_ID_WITH_CHAIN_CODE, &mut buf);
        SessionId::new(buf)
    };

    let proof = {
        let mut transcript = Transcript::new_dlog_proof(
            &final_session_id_with_root_chain_code,
            my_party_id as usize,
            &DLOG_PROOF2_LABEL,
            &DKG_LABEL,
        );

        DLogProof::prove(
            &s_i,
            &ProjectivePoint::GENERATOR,
            &mut transcript,
            &mut rng,
        )
    };

    let (public_key_list, big_s_list, proof_list, _) = broadcast_4(
        &setup,
        relay,
        DKG_MSG_R4,
        (public_key, big_s_i, proof, ()),
    )
    .await?;

    if public_key_list.into_iter().any(|pk| pk != public_key) {
        return Err(KeygenError::PublicKeyMismatch);
    }

    if big_s_list.len() != proof_list.len() {
        return Err(KeygenError::InvalidDLogProof);
    }

    for (party_id, (big_s_i, dlog_proof)) in
        big_s_list.iter().zip(proof_list.into_iter()).enumerate()
    {
        if party_id == my_party_id as usize {
            continue;
        }

        let mut transcript = Transcript::new_dlog_proof(
            &final_session_id_with_root_chain_code,
            party_id,
            &DLOG_PROOF2_LABEL,
            &DKG_LABEL,
        );

        if dlog_proof
            .verify(big_s_i, &ProjectivePoint::GENERATOR, &mut transcript)
            .unwrap_u8()
            == 0
        {
            return Err(KeygenError::InvalidDLogProof);
        }
    }

    for (party_id, x_i) in x_i_list.iter().enumerate() {
        let party_rank = setup.participant_rank(party_id);

        let coeff_multipliers =
            polynomial_coeff_multipliers(x_i, party_rank as usize, N);

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
    let rank_list = (0..setup.total_participants())
        .map(|p| setup.participant_rank(p))
        .collect::<Vec<_>>();

    // FIXME: do we need this?
    check_secret_recovery(&x_i_list, &rank_list, &big_s_list, &public_key)?;

    keyshare.info_mut().public_key = encode_point(&public_key);
    keyshare.info_mut().s_i = encode_scalar(&s_i);
    keyshare.info_mut().key_id = setup.derive_key_id(&public_key.to_bytes());

    for p in 0..N {
        let each = keyshare.each_mut(p as u8);

        each.x_i = encode_scalar(&x_i_list[p]);
        each.big_s = encode_point(&big_s_list[p]);
        each.rank = rank_list[p];
    }

    Ok(keyshare)
}

fn hash_commitment(
    session_id: &SessionId,
    party_id: usize,
    rank: usize,
    x_i: &NonZeroScalar,
    big_f_i_vec: &GroupPolynomial<ProjectivePoint>,
    r_i: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DKG_LABEL);
    hasher.update(session_id);
    hasher.update((party_id as u64).to_be_bytes());
    hasher.update((rank as u64).to_be_bytes());
    hasher.update(x_i.to_bytes());
    for point in big_f_i_vec.points() {
        hasher.update(point.to_bytes());
    }
    hasher.update(r_i);
    hasher.update(COMMITMENT_1_LABEL);

    hasher.finalize().into()
}

fn hash_commitment_2(
    session_id: &[u8],
    chain_code_sid: &[u8; 32],
    r_i: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DKG_LABEL);
    hasher.update(session_id);
    hasher.update(chain_code_sid);
    hasher.update(r_i);
    hasher.update(COMMITMENT_2_LABEL);

    hasher.finalize().into()
}

pub(crate) fn get_base_ot_session_id(
    sender_id: u8,
    receiver_id: u8,
    session_id: &[u8],
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

pub(crate) fn get_all_but_one_session_id(
    sender_id: usize,
    receiver_id: usize,
    session_id: &[u8],
) -> SessionId {
    SessionId::new(
        Sha256::new()
            .chain_update(DKG_LABEL)
            .chain_update(session_id)
            .chain_update(b"sender_id")
            .chain_update((sender_id as u64).to_be_bytes())
            .chain_update(b"receiver_id")
            .chain_update((receiver_id as u64).to_be_bytes())
            .chain_update(b"all_but_one_session_id")
            .finalize()
            .into(),
    )
}

fn verify_dlog_proofs(
    final_session_id: &[u8],
    party_id: usize,
    proofs: &[DLogProof],
    points: &[ProjectivePoint],
) -> Result<(), KeygenError> {
    let mut dlog_transcript = Transcript::new_dlog_proof(
        final_session_id,
        party_id,
        &DLOG_PROOF1_LABEL,
        &DKG_LABEL,
    );

    let mut ok = Choice::from(1);
    for (proof, point) in proofs.iter().zip(points) {
        ok &= proof.verify(
            point,
            &ProjectivePoint::GENERATOR,
            &mut dlog_transcript,
        );
    }

    if ok.unwrap_u8() == 0 {
        return Err(KeygenError::InvalidDLogProof);
    }

    Ok(())
}

pub(crate) async fn broadcast_4<P, R, T1, T2, T3, T4>(
    setup: &P,
    relay: &mut FilteredMsgRelay<R>,
    tag: MessageTag,
    msg: (T1, T2, T3, T4),
) -> Result<(Vec<T1>, Vec<T2>, Vec<T3>, Vec<T4>), KeygenError>
where
    P: ProtocolParticipant,
    R: Relay,
    T1: Wrap,
    T2: Wrap,
    T3: Wrap,
    T4: Wrap,
{
    let (v0, v1, v2, v3) =
        Round::new(setup.total_participants() - 1, tag, relay)
            .broadcast_4(setup, msg)
            .await?;

    Ok((v0.into(), v1.into(), v2.into(), v3.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    use tokio::task::JoinSet;

    use sl_mpc_mate::coord::{
        adversary::{EvilMessageRelay, EvilPlay},
        {MessageRelayService, SimpleMessageRelay},
    };

    use crate::{keygen::utils::setup_keygen, setup::keygen::SetupMessage};

    async fn sim<S, R>(t: u8, ranks: &[u8], coord: S) -> Vec<Keyshare>
    where
        S: MessageRelayService<MessageRelay = R>,
        R: Relay + Send + 'static,
    {
        let parties = setup_keygen(None, t, ranks.len() as u8, Some(ranks));
        sim_parties(parties, coord).await
    }

    async fn sim_parties<S, R>(
        parties: Vec<(SetupMessage, [u8; 32])>,
        coord: S,
    ) -> Vec<Keyshare>
    where
        S: MessageRelayService<MessageRelay = R>,
        R: Send + Relay + 'static,
    {
        let mut jset = JoinSet::new();
        for (setup, seed) in parties {
            let relay = coord.connect().await.unwrap();

            jset.spawn(run(setup, seed, relay));
        }

        let mut shares = vec![];

        while let Some(fini) = jset.join_next().await {
            let fini = fini.unwrap();

            if let Err(ref err) = fini {
                println!("error {}", err);
            }

            let share = fini.unwrap();

            println!(
                "PK {}",
                share
                    .public_key()
                    .to_bytes()
                    .iter()
                    .map(|v| format!("{:02X}", v))
                    .collect::<Vec<_>>()
                    .join(".")
            );

            shares.push(share);
        }

        shares
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn dkg_r1() {
        sim(2, &[0, 1, 1], SimpleMessageRelay::new()).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn keyshares() {
        let shares = sim(2, &[0, 1, 1], SimpleMessageRelay::new()).await;

        for s in &shares {
            let bytes = s.as_slice().to_vec();

            let _reloaded = Keyshare::from_vec(bytes).unwrap();
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn n1() {
        let parties = setup_keygen(None, 2, 3, None);

        let play = EvilPlay::new().drop_message(MsgId::ZERO_ID, None);

        sim_parties(parties, EvilMessageRelay::new(play)).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn inject_random_messages() {
        let parties = setup_keygen(None, 2, 3, None);

        // We could extract protocol instance ID and signing keys of
        // all parties to generate messages to inject into the
        // execution.
        let _intance = parties[0].0.instance_id();

        let mut rng = rand::thread_rng();

        let mut play = EvilPlay::new().drop_message(MsgId::ZERO_ID, None);

        for _ in 0..3 {
            let mut bytes = [0u8; 2000];
            rng.fill_bytes(&mut bytes);
            play = play.inject_message(bytes.into(), |_, _| true);
        }

        let msg_id = parties[0].0.msg_id_from(
            0, //parties[0].0.verifier(0),
            None, DKG_MSG_R1,
        );

        let mut bad_msg = vec![]; //Vec::<u8>::with_capacity(32 + 4 + 32 + 100);

        // the first 32 bytes is message ID,
        bad_msg.extend(msg_id.as_slice());
        bad_msg.extend(10u32.to_le_bytes());
        bad_msg.extend(0u64.to_le_bytes()); // payload
        bad_msg.extend([0u8; 32]); // bad signature

        let play = play.inject_message(bad_msg, |_, p| p == 1);

        sim_parties(parties, EvilMessageRelay::new(play)).await;
    }
}
