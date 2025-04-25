// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! Module for implementing the Quorum Change Protocol.
//! The protocol supports:
//! - Adding new participants
//! - Removing existing participants


use k256::{
    elliptic_curve::{group::GroupEncoding, subtle::ConstantTimeEq, Group},
    NonZeroScalar, ProjectivePoint, Scalar,
};
use rand::prelude::*;
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};

use sl_mpc_mate::{
    coord::*,
    math::{feldman_verify, polynomial_coeff_multipliers, GroupPolynomial, Polynomial},
    message::MsgId,
    SessionId,
};
use sl_oblivious::{
    endemic_ot::{EndemicOTMsg1, EndemicOTReceiver, EndemicOTSender},
    soft_spoken::{build_pprf, eval_pprf},
};

use crate::{
    keygen::{
        broadcast_4,
        constants::*,
        get_all_but_one_session_id, get_base_ot_session_id,
        messages::*,
        utils::{check_secret_recovery, get_birkhoff_coefficients, get_lagrange_coeff},
        KeygenError, Keyshare,
    },
    pairs::Pairs,
    proto::{tags::*, *},
    setup::{QuorumChangeSetupMessage, ABORT_MESSAGE_TAG},
    Seed,
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

/// Executes the Quorum Change Protocol.
///
/// This function orchestrates the quorum change process, allowing participants to:
/// - Add new participants to the quorum
/// - Remove existing participants
/// - Change the threshold value
/// - Modify participant ranks
///
/// # Type Parameters
///
/// * `T` - A type implementing the `QuorumChangeSetupMessage` trait
/// * `R` - A type implementing the `Relay` trait for message communication
///
/// # Arguments
///
/// * `setup` - The protocol setup configuration containing participant information
/// * `seed` - The random seed for cryptographic operations
/// * `relay` - The message relay for communication between parties
///
/// # Returns
///
/// * `Ok(Some(Keyshare))` - The new key share if the protocol succeeds
/// * `Ok(None)` - If the participant is not part of the new quorum
/// * `Err(KeygenError)` - If the protocol fails
///
/// # Errors
///
/// This function may return the following errors:
/// * `KeygenError::AbortProtocol` - If the protocol is aborted by a participant
/// * `KeygenError::SendMessage` - If there's an error sending messages
/// * Other `KeygenError` variants for various protocol failures
pub async fn run<T, R>(setup: T, seed: Seed, relay: R) -> Result<Option<Keyshare>, KeygenError>
where
    T: QuorumChangeSetupMessage<Keyshare, ProjectivePoint>,
    R: Relay,
{
    let abort_msg = create_abort_message(&setup);
    let mut relay = FilteredMsgRelay::new(relay);

    let result = match run_inner(setup, seed, &mut relay).await {
        Ok(share) => Ok(share),
        Err(KeygenError::AbortProtocol(p)) => Err(KeygenError::AbortProtocol(p)),
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

/// Internal implementation of the Quorum Change Protocol.
///
/// This function contains the core logic for the quorum change protocol,
/// handling the cryptographic operations and message exchanges between participants.
///
/// # Type Parameters
///
/// * `T` - A type implementing the `QuorumChangeSetupMessage` trait
/// * `R` - A type implementing the `Relay` trait for message communication
///
/// # Arguments
///
/// * `setup` - The protocol setup configuration
/// * `seed` - The random seed for cryptographic operations
/// * `relay` - The message relay for communication between parties
/// 
/// # Returns
///
/// * `Ok(Some(Keyshare))` - The new key share if the protocol succeeds
/// * `Ok(None)` - If the participant is not part of the new quorum
/// * `Err(KeygenError)` - If the protocol fails
#[allow(non_snake_case)]
pub(crate) async fn run_inner<T, R>(
    setup: T,
    seed: Seed,
    relay: &mut FilteredMsgRelay<R>,
) -> Result<Option<Keyshare>, KeygenError>
where
    T: QuorumChangeSetupMessage<Keyshare, ProjectivePoint>,
    R: Relay,
{
    let mut rng = ChaCha20Rng::from_seed(seed);

    let mut scheme = crate::proto::Scheme::new(&mut rng);

    let expected_public_key = setup.expected_public_key();
    assert!(expected_public_key != &ProjectivePoint::IDENTITY);

    let NEW_T = setup.new_threshold() as usize;
    let NEW_N = setup.new_party_indices().len();

    let new_x_i_list: Vec<NonZeroScalar> = (1..=NEW_N as u32)
        .map(Scalar::from)
        .map(|s| NonZeroScalar::new(s).unwrap())
        .collect();

    let my_party_index = setup.participant_index();
    let my_old_party_id = setup.old_keyshare().map(|k| k.party_id);
    let my_party_is_old = my_old_party_id.is_some();
    let my_new_party_id = setup.new_party_id(my_party_index);
    let my_party_is_new = my_new_party_id.is_some();

    relay.ask_messages(&setup, ABORT_MESSAGE_TAG, false).await?;

    let _r0 = relay
        .ask_messages_from_slice(&setup, QC_MSG_R0, setup.old_party_indices(), false)
        .await?;

    relay.ask_messages(&setup, QC_MSG_R1, false).await?;

    let _p2p_1 = if my_party_is_new {
        relay
            .ask_messages_from_slice(&setup, QC_MSG_P2P_1, setup.old_party_indices(), true)
            .await?
    } else {
        0
    };

    let _p2p_2 = if my_party_is_new {
        relay
            .ask_messages_from_slice(&setup, QC_MSG_P2P_2, setup.old_party_indices(), true)
            .await?
    } else {
        0
    };

    let _r2 = relay
        .ask_messages_from_slice(&setup, QC_MSG_R2, setup.old_party_indices(), false)
        .await?;

    let sid_i = SessionId::new(rng.gen());

    let mut old_party_ids = Pairs::new();

    if let Some(party_id) = my_old_party_id {
        // Broadcast our old-party-id
        relay
            .send(SignedMessage::build(
                &setup.msg_id(None, QC_MSG_R0),
                setup.message_ttl().as_secs() as _,
                0,
                setup.signer(),
                |msg: &mut u8, _| {
                    *msg = party_id;
                },
            ))
            .await?;
        old_party_ids.push(my_party_index, party_id);
    }

    Round::new(_r0, QC_MSG_R0, relay)
        .of_signed_messages(
            &setup,
            KeygenError::AbortProtocol,
            |&party_id: &u8, index| {
                old_party_ids.push(index, party_id);
                Ok(())
            },
        )
        .await?;

    // only for old parties
    // calculate additive share s_i_0 of participant_i,
    // \sum_{i=0}^{n-1} s_i_0 = private_key
    let s_i_0 = setup
        .old_keyshare()
        .map(|keyshare| {
            let my_old_party_id = keyshare.party_id as usize;

            let s_i = keyshare.s_i();
            let old_rank_list = keyshare.rank_list();
            let old_x_i_list = keyshare.x_i_list();
            let x_i = old_x_i_list[my_old_party_id];

            assert!(setup.old_party_indices().len() >= keyshare.threshold as usize);

            let old_party_id_list = old_party_ids.remove_ids();

            let all_ranks_zero = old_rank_list.iter().all(|&r| r == 0);

            let lambda = if all_ranks_zero {
                get_lagrange_coeff(&x_i, &old_x_i_list, &old_party_id_list)
            } else {
                get_birkhoff_coefficients(&old_rank_list, &old_x_i_list, &old_party_id_list)
                    .get(&my_old_party_id)
                    .copied()
                    .unwrap_or_default()
            };

            lambda * s_i
        })
        .unwrap_or_default();

    // only for old parties
    let mut polynomial = Polynomial::random(&mut rng, NEW_T - 1);
    polynomial.set_constant(s_i_0);

    let big_p_i_poly = polynomial.commit();
    let r1_i = rng.gen();

    let commitment1_i = if my_party_is_old {
        hash_commitment_1(&sid_i, my_party_index, &big_p_i_poly, &r1_i)
    } else {
        [0u8; 32]
    };

    // Broadcast 1 from all parties to all
    let (sid_i_list, enc_pub_keys, commitment1_list, _) = broadcast_4(
        &setup,
        relay,
        QC_MSG_R1,
        (sid_i, scheme.public_key().to_vec(), commitment1_i, ()),
    )
    .await?;

    for (receiver, pub_key) in enc_pub_keys.into_iter().enumerate() {
        if receiver != setup.participant_index() {
            scheme
                .receiver_public_key(receiver, &pub_key)
                .map_err(|_| KeygenError::InvalidMessage)?;
        }
    }

    let final_session_id: [u8; 32] = sid_i_list
        .iter()
        .fold(Sha256::new(), |hash, sid| hash.chain_update(sid))
        .finalize()
        .into();

    // Old party_i sends p2p commit values to new parties
    let mut p_i_list: Pairs<Scalar, u8> = Pairs::new();
    if my_party_is_old && my_party_is_new {
        let my_old_party_id = my_old_party_id.unwrap();
        let my_new_party_id = my_new_party_id.unwrap();
        let my_new_rank = setup.new_participant_rank(my_new_party_id);
        let x_i = new_x_i_list[my_new_party_id as usize];
        let p_i_i = block_in_place(|| polynomial.derivative_at(my_new_rank as usize, &x_i));
        p_i_list.push(my_old_party_id, p_i_i);
    }

    // blind commitment2 values for receiver_ids
    let mut r2_j_list: Pairs<[u8; 32], u8> = Pairs::new();
    let mut p_i_j_list: Pairs<Scalar, u8> = Pairs::new();
    if my_party_is_old {
        for &receiver_index in setup.new_party_indices() {
            if receiver_index == my_party_index {
                continue;
            }
            let receiver_id = setup.new_party_id(receiver_index).unwrap();

            let r2_j: [u8; 32] = rng.gen();
            r2_j_list.push(receiver_id, r2_j);

            let party_j_rank = setup.new_participant_rank(receiver_id);
            let x_j = new_x_i_list[receiver_id as usize];
            let p_i_j = block_in_place(|| polynomial.derivative_at(party_j_rank as usize, &x_j));
            p_i_j_list.push(receiver_id, p_i_j);

            let commitment_2_i = hash_commitment_2(
                &final_session_id,
                my_party_index,
                receiver_index,
                &p_i_j,
                &r2_j,
            );

            let mut enc_msg1 = EncryptedMessage::<QCP2PMsg1>::new(
                &setup.msg_id(Some(receiver_index), QC_MSG_P2P_1),
                setup.message_ttl().as_secs() as u32,
                0,
                0,
                &scheme,
            );

            let (msg1, _) = enc_msg1.payload(&scheme);
            msg1.commitment_2_i = commitment_2_i;

            // send out P2P message. We call feed() in the loop
            // and following send_broadcast() will call .send() that
            // implies feed() + flush()
            relay
                .feed(
                    enc_msg1
                        .encrypt(&mut scheme, receiver_index)
                        .ok_or(KeygenError::SendMessage)?,
                )
                .await
                .map_err(|_| KeygenError::SendMessage)?;
        }
    }

    // new_party collects all old_t commitments2 from old parties
    let mut commitment2_list: Pairs<[u8; 32], u8> = Pairs::new();

    Round::new(_p2p_1, QC_MSG_P2P_1, relay)
        .of_encrypted_messages(
            &setup,
            &mut scheme,
            0,
            KeygenError::AbortProtocol,
            |p2p_msg1: &QCP2PMsg1, from_party_index, _, _| {
                let from_party_id = *old_party_ids.find_pair(from_party_index);

                commitment2_list.push(from_party_id, p2p_msg1.commitment_2_i);

                Ok(None)
            },
        )
        .await?;

    // Old party_i sends p2p decommit2 values to new parties
    // and broadcast decommit1
    let decommit_data = if let Some(keyshare) = setup.old_keyshare() {
        for &receiver_index in setup.new_party_indices() {
            if receiver_index == my_party_index {
                continue;
            }
            let receiver_id = setup.new_party_id(receiver_index).unwrap();

            let p_i_j = p_i_j_list.find_pair(receiver_id);
            let r2_j = r2_j_list.find_pair(receiver_id);

            let mut enc_msg2 = EncryptedMessage::<QCP2PMsg2>::new(
                &setup.msg_id(Some(receiver_index), QC_MSG_P2P_2),
                setup.message_ttl().as_secs() as u32,
                0,
                0,
                &scheme,
            );

            let (msg2, _) = enc_msg2.payload(&scheme);
            msg2.p_i = encode_scalar(p_i_j);
            msg2.r_2_i = *r2_j;
            msg2.root_chain_code = keyshare.root_chain_code;

            // send out R2 P2P message. We call feed() in the loop
            // and following send_broadcast() will call .send() that
            // implies feed() + flush()
            relay
                .feed(
                    enc_msg2
                        .encrypt(&mut scheme, receiver_index)
                        .ok_or(KeygenError::SendMessage)?,
                )
                .await
                .map_err(|_| KeygenError::SendMessage)?;
        }

        // Broadcast 2 from old parties to all
        let (big_p_j_poly_list, r1_j_list, _, _) = Round::new(_r2, QC_MSG_R2, relay)
            .broadcast_4(&setup, (big_p_i_poly.clone(), r1_i, (), ()))
            .await?;

        // checks for old party
        for &old_party_index in setup.old_party_indices() {
            let r1_j = r1_j_list.find_pair(old_party_index);
            let sid_j = &sid_i_list[old_party_index];
            let commitment1 = &commitment1_list[old_party_index];
            let big_p_i_poly = big_p_j_poly_list.find_pair(old_party_index);

            if big_p_i_poly.coeffs.len() != NEW_T {
                return Err(KeygenError::InvalidMessage);
            }

            if big_p_i_poly.points().any(|p| p.is_identity().into()) {
                return Err(KeygenError::InvalidPolynomialPoint);
            }

            let commit_hash1 = hash_commitment_1(sid_j, old_party_index, big_p_i_poly, r1_j);
            if commit_hash1.ct_ne(commitment1).into() {
                return Err(KeygenError::InvalidCommitmentHash);
            }
        }

        let mut big_p_vec = GroupPolynomial::identity(NEW_T);
        for (_, v) in &big_p_j_poly_list {
            big_p_vec.add_mut(v); // big_f_vec += v;
        }

        if &big_p_vec.get_constant() != expected_public_key {
            return Err(KeygenError::PublicKeyMismatch);
        }

        // complete the protocol for an old party that is not in the list of new parties
        if !my_party_is_new {
            return Ok(None);
        }

        Some(big_p_j_poly_list)
    } else {
        None
    };

    let mut root_chain_code_list = setup
        .old_keyshare()
        .map(|share| Pairs::new_with_item(share.party_id, share.root_chain_code))
        .unwrap_or_default();

    // new_party processes all old_t decommits2 from old parties
    // and processes decommit1
    Round::new(_p2p_2, QC_MSG_P2P_2, relay)
        .of_encrypted_messages(
            &setup,
            &mut scheme,
            0,
            KeygenError::AbortProtocol,
            |p2p_msg2: &QCP2PMsg2, from_party_index, _, _| {
                let from_party_id = *old_party_ids.find_pair(from_party_index);

                let p_j_i = decode_scalar(&p2p_msg2.p_i).ok_or(KeygenError::InvalidMessage)?;

                let commitment2 = commitment2_list.find_pair(from_party_id);

                let commit_hash_2 = hash_commitment_2(
                    &final_session_id,
                    from_party_index,
                    my_party_index,
                    &p_j_i,
                    &p2p_msg2.r_2_i,
                );

                if commit_hash_2.ct_ne(commitment2).into() {
                    return Err(KeygenError::InvalidCommitmentHash);
                }

                p_i_list.push(from_party_id, p_j_i);

                root_chain_code_list.push(from_party_id, p2p_msg2.root_chain_code);

                Ok(None)
            },
        )
        .await?;

    // check that root_chain_code_list contains the same elements
    let root_chain_code_list = root_chain_code_list.remove_ids();
    let root_chain_code = root_chain_code_list[0];
    if !root_chain_code_list
        .iter()
        .all(|&item| item == root_chain_code)
    {
        return Err(KeygenError::InvalidQuorumChange);
    };

    let big_p_j_poly_list = if let Some(decommit_data) = decommit_data {
        decommit_data
    } else {
        // only for new parties, not for old parties

        let (big_p_j_poly_list, r1_j_list, _, _) = Round::new(_r2, QC_MSG_R2, relay)
            .recv_broadcast_4::<_, _, _, (), ()>(&setup, &[big_p_i_poly.external_size(), 32, 0, 0])
            .await?;

        // checks for new party
        for &old_party_index in setup.old_party_indices() {
            let r1_j = r1_j_list.find_pair(old_party_index);
            let sid_j = &sid_i_list[old_party_index];
            let commitment1 = &commitment1_list[old_party_index];
            let big_p_i_vec: &GroupPolynomial<ProjectivePoint> =
                big_p_j_poly_list.find_pair(old_party_index);

            if big_p_i_vec.coeffs.len() != NEW_T {
                return Err(KeygenError::InvalidMessage);
            }

            if big_p_i_vec.points().any(|p| p.is_identity().into()) {
                return Err(KeygenError::InvalidPolynomialPoint);
            }

            let commit_hash1 = hash_commitment_1(sid_j, old_party_index, big_p_i_vec, r1_j);
            if commit_hash1.ct_ne(commitment1).into() {
                return Err(KeygenError::InvalidCommitmentHash);
            }
        }

        big_p_j_poly_list
    };

    let mut big_p_poly = GroupPolynomial::identity(NEW_T);

    // sort by old_party_id
    let mut big_p_j_poly_list_sorted_by_old_id = Pairs::new();
    for &old_party_index in setup.old_party_indices() {
        let old_party_id = old_party_ids.find_pair(old_party_index);
        big_p_j_poly_list_sorted_by_old_id.push(
            *old_party_id,
            big_p_j_poly_list.find_pair(old_party_index).clone(),
        );
    }

    let big_p_j_poly_list = big_p_j_poly_list_sorted_by_old_id.remove_ids();
    let p_i_list = p_i_list.remove_ids();
    for v in &big_p_j_poly_list {
        big_p_poly.add_mut(v); // big_f_vec += v;
    }

    if big_p_j_poly_list.len() != p_i_list.len() {
        return Err(KeygenError::FailedFelmanVerify);
    }

    let my_party_id = my_new_party_id.unwrap();
    let my_rank = setup.new_participant_rank(my_party_id);

    // check that P_j(x_i) = p_j_i * G
    for (big_p_j, p_j_i) in big_p_j_poly_list.iter().zip(&p_i_list) {
        let coeffs = block_in_place(|| big_p_j.derivative_coeffs(my_rank as usize));
        let valid = feldman_verify(
            coeffs,
            &new_x_i_list[my_party_id as usize],
            p_j_i,
            &ProjectivePoint::GENERATOR,
        );
        if !valid {
            return Err(KeygenError::FailedFelmanVerify);
        }
    }

    let p_i = p_i_list.iter().sum();

    // check if p_i is correct, P(x_i) = p_i * G
    let big_p_i = ProjectivePoint::GENERATOR * p_i;
    let x_i = new_x_i_list[my_party_id as usize];
    let coeff_multipliers = polynomial_coeff_multipliers(&x_i, my_rank as usize, NEW_T);

    let expected_point: ProjectivePoint = big_p_poly
        .points()
        .zip(coeff_multipliers)
        .map(|(point, coeff)| point * &coeff)
        .sum();

    if expected_point != big_p_i {
        return Err(KeygenError::BigSMismatch);
    }

    let public_key = big_p_poly.get_constant();

    if &public_key != expected_public_key {
        return Err(KeygenError::PublicKeyMismatch);
    }

    let big_s_list: Vec<ProjectivePoint> = new_x_i_list
        .iter()
        .enumerate()
        .map(|(party_id, x_i)| {
            let party_rank = setup.new_participant_rank(party_id as u8);

            let coeff_multipliers = polynomial_coeff_multipliers(x_i, party_rank as usize, NEW_T);

            big_p_poly
                .points()
                .zip(coeff_multipliers)
                .map(|(point, coeff)| point * &coeff)
                .sum()
        })
        .collect();

    let mut rank_list = vec![];
    for &party_index in setup.new_party_indices() {
        let party_id = setup.new_party_id(party_index).unwrap();
        rank_list.push(setup.new_participant_rank(party_id));
    }

    if !rank_list.iter().all(|&r| r == 0) {
        // check that rank_list is correct and participants can sign
        check_secret_recovery(&new_x_i_list, &rank_list, &big_s_list, &public_key)?;
    }

    let mut new_keyshare = Keyshare::new(
        NEW_N as u8,
        NEW_T as u8,
        my_party_id,
        setup.keyshare_extra(),
    );

    new_keyshare.info_mut().final_session_id = final_session_id;
    new_keyshare.info_mut().root_chain_code = root_chain_code;
    new_keyshare.info_mut().public_key = encode_point(&public_key);
    new_keyshare.info_mut().s_i = encode_scalar(&p_i);
    new_keyshare.info_mut().key_id = setup.derive_key_id(&public_key.to_bytes());

    for p in 0..NEW_N {
        let each = new_keyshare.each_mut(p as u8);

        each.x_i = encode_scalar(&new_x_i_list[p]);
        each.big_s = encode_point(&big_s_list[p]);
        each.rank = rank_list[p];
    }

    /////////////////////////////////
    // new parties create OT seeds //
    /////////////////////////////////
    let _ot1 = relay
        .ask_messages_from_slice(&setup, QC_MSG_OT1, setup.new_party_indices(), true)
        .await?;

    let _ot2 = relay
        .ask_messages_from_slice(&setup, QC_MSG_OT2, setup.new_party_indices(), true)
        .await?;

    let mut base_ot_receivers: Pairs<EndemicOTReceiver> = Pairs::new();
    for &receiver_index in setup.new_party_indices() {
        if receiver_index == my_party_index {
            continue;
        }

        let receiver_id = setup.new_party_id(receiver_index).unwrap();

        let sid = get_base_ot_session_id(my_party_id, receiver_id, &new_keyshare.final_session_id);

        let mut enc_ot_msg1 = EncryptedMessage::<EndemicOTMsg1>::new(
            &setup.msg_id(Some(receiver_index), QC_MSG_OT1),
            setup.message_ttl().as_secs() as u32,
            0,
            0,
            &scheme,
        );
        let (msg1, _) = enc_ot_msg1.payload(&scheme);

        let receiver = EndemicOTReceiver::new(&sid, msg1, &mut rng);
        base_ot_receivers.push(receiver_id, receiver);

        // send out P2P message. We call feed() in the loop
        // and following send_broadcast() will call .send() that
        // implies feed() + flush()
        relay
            .feed(
                enc_ot_msg1
                    .encrypt(&mut scheme, receiver_index)
                    .ok_or(KeygenError::SendMessage)?,
            )
            .await
            .map_err(|_| KeygenError::SendMessage)?;
    }

    Round::new(_ot1, QC_MSG_OT1, relay)
        .of_encrypted_messages(
            &setup,
            &mut scheme,
            0,
            KeygenError::AbortProtocol,
            |base_ot_msg1: &EndemicOTMsg1, receiver_index, _, scheme| {
                let receiver_id = setup.new_party_id(receiver_index).unwrap();

                let mut enc_buf = EncryptedMessage::<QCOTMsg2>::new(
                    &setup.msg_id(Some(receiver_index), QC_MSG_OT2),
                    setup.message_ttl().as_secs() as _,
                    0,
                    0,
                    scheme,
                );

                let (msg3, _trailer) = enc_buf.payload(scheme);

                let sender_ot_seed = {
                    let sid = get_base_ot_session_id(
                        receiver_id,
                        my_party_id,
                        &new_keyshare.final_session_id,
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
                    &new_keyshare.final_session_id,
                );

                build_pprf(
                    &all_but_one_session_id,
                    &sender_ot_seed,
                    &mut new_keyshare.other_mut(receiver_id).send_ot_seed,
                    &mut msg3.pprf_output,
                );

                if receiver_id > my_party_id {
                    rng.fill_bytes(&mut msg3.seed_i_j);
                    new_keyshare.each_mut(receiver_id - 1).zeta_seed = msg3.seed_i_j;
                };

                Ok(Some(
                    enc_buf
                        .encrypt(scheme, receiver_index)
                        .ok_or(KeygenError::SendMessage)?,
                ))
            },
        )
        .await?;

    Round::new(_ot2, QC_MSG_OT2, relay)
        .of_encrypted_messages(
            &setup,
            &mut scheme,
            0,
            KeygenError::AbortProtocol,
            |msg3: &QCOTMsg2, party_index, _, _| {
                let party_id = setup.new_party_id(party_index).unwrap();

                let receiver = base_ot_receivers.pop_pair(party_id);
                let receiver_output = block_in_place(|| receiver.process(&msg3.base_ot_msg2))
                    .map_err(|_| KeygenError::InvalidMessage)?;
                let all_but_one_session_id = get_all_but_one_session_id(
                    party_id as usize,
                    my_party_id as usize,
                    &new_keyshare.final_session_id,
                );

                block_in_place(|| {
                    eval_pprf(
                        &all_but_one_session_id,
                        &receiver_output,
                        &msg3.pprf_output,
                        &mut new_keyshare.other_mut(party_id).recv_ot_seed,
                    )
                })
                .map_err(KeygenError::PPRFError)?;

                if party_id < my_party_id {
                    new_keyshare.each_mut(party_id).zeta_seed = msg3.seed_i_j;
                }

                Ok(None)
            },
        )
        .await?;

    Ok(Some(new_keyshare))
}

/// Computes the hash commitment for the first round of the protocol.
///
/// This function generates a commitment to the polynomial coefficients
/// and random value used in the first round of the quorum change protocol.
///
/// # Arguments
///
/// * `session_id` - The session identifier
/// * `party_index` - The index of the party generating the commitment
/// * `big_f_i_vec` - The polynomial commitment vector
/// * `r1_i` - The random value for the commitment
///
/// # Returns
///
/// A 32-byte hash commitment
fn hash_commitment_1(
    session_id: &[u8],
    party_index: usize,
    big_f_i_vec: &GroupPolynomial<ProjectivePoint>,
    r1_i: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(QC_LABEL);
    hasher.update(session_id);
    hasher.update((party_index as u64).to_be_bytes());
    for point in big_f_i_vec.points() {
        hasher.update(point.to_bytes());
    }
    hasher.update(r1_i);
    hasher.update(QC_COMMITMENT_1_LABEL);

    hasher.finalize().into()
}

/// Computes the hash commitment for the second round of the protocol.
///
/// This function generates a commitment to the share values and random
/// value used in the second round of the quorum change protocol.
///
/// # Arguments
///
/// * `session_id` - The session identifier
/// * `from_party_i_index` - The index of the sending party
/// * `to_party_j_index` - The index of the receiving party
/// * `p_i_j` - The share value being committed
/// * `r2_i` - The random value for the commitment
///
/// # Returns
///
/// A 32-byte hash commitment
fn hash_commitment_2(
    session_id: &[u8],
    from_party_i_index: usize,
    to_party_j_index: usize,
    p_i_j: &Scalar,
    r2_i: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(QC_LABEL);
    hasher.update(session_id);
    hasher.update((from_party_i_index as u64).to_be_bytes());
    hasher.update((to_party_j_index as u64).to_be_bytes());
    hasher.update(p_i_j.to_bytes());
    hasher.update(r2_i);
    hasher.update(QC_COMMITMENT_2_LABEL);

    hasher.finalize().into()
}

/// Processes message receivers for the quorum change protocol.
///
/// This function handles the distribution of messages to the appropriate
/// receivers based on the protocol setup and message type.
///
/// # Type Parameters
///
/// * `S` - A type implementing the `QuorumChangeSetupMessage` trait
/// * `F` - A closure type for processing message receivers
///
/// # Arguments
///
/// * `setup` - The protocol setup configuration
/// * `msg_receiver` - A closure that processes each message receiver
pub fn message_receivers<S, F>(setup: &S, mut msg_receiver: F)
where
    S: QuorumChangeSetupMessage<Keyshare, ProjectivePoint>,
    F: FnMut(MsgId, &S::MessageVerifier),
{
    let my_party_index = setup.participant_index();
    let my_party_is_old = setup.old_keyshare().is_some();
    let my_new_party_id = setup.new_party_id(my_party_index);
    let my_party_is_new = my_new_party_id.is_some();

    let _old = setup.old_party_indices();
    let new = setup.new_party_indices();

    setup.all_other_parties().for_each(|receiver_idx| {
        let receiver = setup.verifier(receiver_idx);

        msg_receiver(setup.msg_id(None, ABORT_MESSAGE_TAG), receiver);

        if my_party_is_old {
            msg_receiver(setup.msg_id(None, QC_MSG_R0), receiver);
        }

        msg_receiver(setup.msg_id(None, QC_MSG_R1), receiver);

        if my_party_is_old && new.contains(&receiver_idx) {
            msg_receiver(setup.msg_id(Some(receiver_idx), QC_MSG_P2P_1), receiver);
        }

        if my_party_is_old && new.contains(&receiver_idx) {
            msg_receiver(setup.msg_id(Some(receiver_idx), QC_MSG_P2P_2), receiver);
        }

        if my_party_is_old {
            msg_receiver(setup.msg_id(None, QC_MSG_R2), receiver);
        }

        if my_party_is_new && new.contains(&receiver_idx) {
            msg_receiver(setup.msg_id(Some(receiver_idx), QC_MSG_OT1), receiver);
        }

        if my_party_is_new && new.contains(&receiver_idx) {
            msg_receiver(setup.msg_id(Some(receiver_idx), QC_MSG_OT2), receiver);
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use tokio::task::JoinSet;

    use sl_mpc_mate::{
        coord::{
            adversary::{EvilMessageRelay, EvilPlay},
            MessageRelayService, SimpleMessageRelay,
        },
        message::MsgId,
    };

    use crate::{
        keygen::utils::{
            gen_keyshares, setup_quorum_change, setup_quorum_change_extend_parties,
            setup_quorum_change_threshold,
        },
        setup::quorum_change::SetupMessage as QuorumChangeSetupMessage,
        sign::{run as run_dsg, setup_dsg},
    };

    async fn sim<S, R>(
        old_keyshares: &[Arc<Keyshare>],
        new_threshold: u8,
        new_ranks: Vec<u8>,
        coord: S,
    ) -> Vec<Option<Arc<Keyshare>>>
    where
        S: MessageRelayService<MessageRelay = R>,
        R: Relay + Send + 'static,
    {
        let parties = setup_quorum_change(old_keyshares, new_threshold, &new_ranks);

        sim_parties(parties, coord).await
    }

    async fn sim_extend<S, R>(
        old_keyshares: &[Arc<Keyshare>],
        new_threshold: u8,
        new_parties_len: u8,
        new_ranks: Vec<u8>,
        coord: S,
    ) -> Vec<Option<Arc<Keyshare>>>
    where
        S: MessageRelayService<MessageRelay = R>,
        R: Relay + Send + 'static,
    {
        let parties = setup_quorum_change_extend_parties(
            old_keyshares,
            new_threshold,
            new_parties_len,
            &new_ranks,
        );
        sim_parties(parties, coord).await
    }

    async fn sim_only_change_threshold<S, R>(
        old_keyshares: &[Arc<Keyshare>],
        new_threshold: u8,
        new_ranks: Vec<u8>,
        coord: S,
    ) -> Vec<Option<Arc<Keyshare>>>
    where
        S: MessageRelayService<MessageRelay = R>,
        R: Relay + Send + 'static,
    {
        let parties = setup_quorum_change_threshold(old_keyshares, new_threshold, &new_ranks);
        sim_parties(parties, coord).await
    }

    async fn sim_parties<S, R>(
        parties: Vec<(QuorumChangeSetupMessage, [u8; 32])>,
        coord: S,
    ) -> Vec<Option<Arc<Keyshare>>>
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
            match share {
                None => shares.push(None),
                Some(v) => shares.push(Some(Arc::new(v))),
            }
        }

        shares
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn quorum_change_all_new_parties() {
        let old_threshold = 2;
        let old_n = 3;
        let ranks = [0, 0, 0];
        let shares = gen_keyshares(old_threshold, old_n, Some(&ranks)).await;
        let expected_public_key = shares[0].public_key;

        let shares = [shares[1].clone(), shares[0].clone(), shares[2].clone()];

        let new_threshold = 3;
        let new_n = 4;
        let new_ranks = vec![0, 0, 1, 1];
        let result = sim(
            &shares[..old_threshold as usize],
            new_threshold,
            new_ranks,
            SimpleMessageRelay::new(),
        )
        .await;

        let mut new_shares: Vec<Arc<Keyshare>> = result.iter().flatten().cloned().collect();
        assert_eq!(new_shares.len(), new_n as usize);
        assert_eq!(expected_public_key, new_shares[0].public_key);

        // test dsg with new_shares after quorum change
        let coord = SimpleMessageRelay::new();

        new_shares.sort_by_key(|share| share.party_id);
        let subset = &new_shares[0..new_threshold as usize];

        let mut parties: JoinSet<Result<_, _>> = JoinSet::new();
        for (setup, seed) in setup_dsg(None, subset, "m") {
            parties.spawn(run_dsg(setup, seed, coord.connect()));
        }

        while let Some(fini) = parties.join_next().await {
            let fini = fini.unwrap();

            if let Err(ref err) = fini {
                println!("error {err:?}");
            }
            let _fini = fini.unwrap();
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn quorum_change_extend_parties() {
        let old_threshold = 2;
        let old_n = 3;
        let ranks = [0, 0, 0];
        let shares = gen_keyshares(old_threshold, old_n, Some(&ranks)).await;
        let expected_public_key = shares[0].public_key;

        let shares = [shares[1].clone(), shares[0].clone(), shares[2].clone()];

        let new_threshold = 2;
        let new_parties_len = 2;
        let new_n = old_n + new_parties_len;
        let new_ranks = vec![0, 0, 0, 1, 1];
        let result = sim_extend(
            &shares,
            new_threshold,
            new_parties_len,
            new_ranks,
            SimpleMessageRelay::new(),
        )
        .await;

        let mut new_shares: Vec<Arc<Keyshare>> = result.iter().flatten().cloned().collect();
        assert_eq!(new_shares.len(), new_n as usize);
        assert_eq!(expected_public_key, new_shares[0].public_key);

        // test dsg with new_shares after quorum change
        let coord = SimpleMessageRelay::new();

        new_shares.sort_by_key(|share| share.party_id);
        let subset = &new_shares[0..new_threshold as usize];

        let mut parties: JoinSet<Result<_, _>> = JoinSet::new();
        for (setup, seed) in setup_dsg(None, subset, "m") {
            parties.spawn(run_dsg(setup, seed, coord.connect()));
        }

        while let Some(fini) = parties.join_next().await {
            let fini = fini.unwrap();

            if let Err(ref err) = fini {
                println!("error {err:?}");
            }
            let _fini = fini.unwrap();
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn quorum_change_only_change_threshold() {
        let old_threshold = 2;
        let old_n = 4;
        let ranks = [0, 0, 0, 0];
        let mut shares = gen_keyshares(old_threshold, old_n, Some(&ranks)).await;
        let expected_public_key = shares[0].public_key;

        shares.shuffle(&mut thread_rng());

        let new_threshold = 3;
        let new_n = old_n;
        let new_ranks = vec![0, 0, 0, 0];
        let result =
            sim_only_change_threshold(&shares, new_threshold, new_ranks, SimpleMessageRelay::new())
                .await;

        let mut new_shares: Vec<Arc<Keyshare>> = result.iter().flatten().cloned().collect();
        assert_eq!(new_shares.len(), new_n as usize);
        assert_eq!(expected_public_key, new_shares[0].public_key);

        // test dsg with new_shares after quorum change
        let coord = SimpleMessageRelay::new();

        new_shares.sort_by_key(|share| share.party_id);
        let subset = &new_shares[0..new_threshold as usize];

        let mut parties: JoinSet<Result<_, _>> = JoinSet::new();
        for (setup, seed) in setup_dsg(None, subset, "m") {
            parties.spawn(run_dsg(setup, seed, coord.connect()));
        }

        while let Some(fini) = parties.join_next().await {
            let fini = fini.unwrap();

            if let Err(ref err) = fini {
                println!("error {err:?}");
            }
            let _fini = fini.unwrap();
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn n1() {
        let old_threshold = 2;
        let old_n = 3;
        let ranks = [0, 0, 0];
        let shares = gen_keyshares(old_threshold, old_n, Some(&ranks)).await;

        let play = EvilPlay::new().drop_message(MsgId::ZERO_ID, None);

        let new_threshold = 2;
        let new_ranks = vec![0, 0, 1, 1];
        sim(
            &shares[..old_threshold as usize],
            new_threshold,
            new_ranks,
            EvilMessageRelay::new(play),
        )
        .await;
    }
}
