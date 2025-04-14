// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::collections::HashMap;

use k256::{
    ecdsa::{
        signature::hazmat::PrehashVerifier, RecoveryId, Signature,
        VerifyingKey,
    },
    elliptic_curve::{
        group::GroupEncoding,
        ops::Reduce,
        point::AffineCoordinates,
        scalar::IsHigh,
        subtle::{Choice, ConstantTimeEq},
        PrimeField,
    },
    sha2::{Digest, Sha256},
    NonZeroScalar, ProjectivePoint, Scalar, Secp256k1, U256,
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use zeroize::Zeroizing;

use sl_mpc_mate::{coord::*, math::birkhoff_coeffs};

use sl_oblivious::rvole::{RVOLEReceiver, RVOLESender};

use crate::{
    keygen::Keyshare,
    proto::{
        create_abort_message, tags::*, EncryptedMessage, SignedMessage, *,
    },
    setup::{
        FinalSignSetupMessage, PreSignSetupMessage, ProtocolParticipant,
        SignSetupMessage, ABORT_MESSAGE_TAG,
    },
    sign::constants::*,
    sign::messages::*,
    Seed,
};

use super::SignError;

use crate::pairs::Pairs;

/// Inner function for the pre-signature phase of the DSG protocol
///
/// This function implements the core logic of the pre-signature phase,
/// where parties generate a pre-signature that can be used to sign any
/// message later.
///
/// # Type Parameters
///
/// * `R`: Type implementing the `Relay` trait for message communication
/// * `S`: Type implementing the `PreSignSetupMessage` trait for setup parameters
///
/// # Arguments
///
/// * `setup`: Setup parameters for the protocol
/// * `seed`: Random seed for generating random values
/// * `relay`: Message relay for communication between parties
///
/// # Returns
///
/// A `Result` containing either:
/// * `Ok(PreSign)`: The pre-signature result
/// * `Err(SignError)`: An error if the protocol fails
async fn pre_signature_inner<R: Relay, S: PreSignSetupMessage>(
    setup: &S,
    seed: Seed,
    relay: &mut FilteredMsgRelay<R>,
) -> Result<PreSign, SignError> {
    let mut rng = ChaCha20Rng::from_seed(seed);
    let mut scheme = crate::proto::Scheme::new(&mut rng);

    // For DKG part_id == part_idx.
    //
    // For DSG: party_idx is an index of the party in the setup messages.
    //
    // In the first message a party sends its part_id from Keyshare and
    // its encryption public key
    //
    let my_party_id = setup.keyshare().party_id;
    let my_party_idx = setup.participant_index();

    let phi_i: Scalar = Scalar::generate_biased(&mut rng);
    let r_i: Scalar = Scalar::generate_biased(&mut rng);
    let blind_factor: [u8; 32] = rng.gen();

    let big_r_i = ProjectivePoint::GENERATOR * r_i;

    // TODO: Replace with SmallVec 2?
    let mut commitments =
        vec![([0; 32], [0; 32]); setup.total_participants()];

    commitments[my_party_idx].0 = rng.gen(); // generate SessionId
    commitments[my_party_idx].1 = hash_commitment_r_i(
        &commitments[my_party_idx].0,
        &big_r_i,
        &blind_factor,
    );

    relay
        .send(SignedMessage::build(
            &setup.msg_id(None, DSG_MSG_R1),
            setup.message_ttl().as_secs() as _,
            0,
            setup.signer(),
            |msg: &mut SignMsg1, _| {
                msg.session_id = commitments[my_party_idx].0;
                msg.commitment_r_i = commitments[my_party_idx].1;
                msg.party_id = my_party_id;
                msg.enc_pk = scheme.public_key().try_into().unwrap();
            },
        ))
        .await?;

    // vector of pairs (party_idx, party_id)
    let mut party_idx_to_id_map = vec![(my_party_idx, my_party_id)];

    Round::new(setup.total_participants() - 1, DSG_MSG_R1, relay)
        .of_signed_messages(
            setup,
            SignError::AbortProtocol,
            |msg: &SignMsg1, party_idx| {
                party_idx_to_id_map.push((party_idx, msg.party_id));
                commitments[party_idx] = (msg.session_id, msg.commitment_r_i);
                scheme
                    .receiver_public_key(party_idx, &msg.enc_pk)
                    .map_err(|_| SignError::InvalidMessage)?;

                Ok(())
            },
        )
        .await?;

    party_idx_to_id_map.sort_by_key(|&(_, pid)| pid);

    // there is no party-id duplicates
    if !party_idx_to_id_map.windows(2).all(|w| w[0] != w[1]) {
        return Err(SignError::InvalidMessage);
    }

    // all party-id are in range
    if !party_idx_to_id_map
        .iter()
        .all(|&(_, pid)| pid < setup.keyshare().total_parties)
    {
        return Err(SignError::InvalidMessage);
    }

    // IDX -> ID
    let find_party_id = |idx: usize| {
        party_idx_to_id_map
            .iter()
            .find_map(|&(i, p)| (i == idx).then_some(p))
            .unwrap()
    };

    let final_session_id: [u8; 32] = commitments
        .iter()
        .fold(Sha256::new(), |hash, (sid, _)| hash.chain_update(sid))
        .chain_update(setup.keyshare().final_session_id)
        .finalize()
        .into();

    let digest_i: [u8; 32] = commitments
        .iter()
        .enumerate()
        .fold(
            Sha256::new().chain_update(DSG_LABEL),
            |hash, (key, (sid, commitment))| {
                hash.chain_update((key as u32).to_be_bytes())
                    .chain_update(sid)
                    .chain_update(commitment)
            },
        )
        .chain_update(DIGEST_I_LABEL)
        .finalize()
        .into();

    let mut to_send = vec![];

    let mut mta_receivers = Pairs::from(
        setup
            .all_other_parties()
            .map(|party_idx| {
                let sender_id = find_party_id(party_idx);

                let sid =
                    mta_session_id(&final_session_id, sender_id, my_party_id);

                let sender_ot_results =
                    setup.keyshare().sender_seed(sender_id);

                let mut enc_msg = EncryptedMessage::<SignMsg2>::new(
                    &setup.msg_id(Some(party_idx), DSG_MSG_R2),
                    setup.message_ttl().as_secs() as u32,
                    0,
                    0,
                    &scheme,
                );

                let (msg2, _) = enc_msg.payload(&scheme);
                msg2.final_session_id = final_session_id;

                let (mta_receiver, chi_i_j) = RVOLEReceiver::new(
                    sid,
                    sender_ot_results,
                    &mut msg2.mta_msg1,
                    &mut rng,
                );

                to_send.push(
                    enc_msg
                        .encrypt(&mut scheme, party_idx)
                        .ok_or(SignError::SendMessage)?,
                );

                Ok((party_idx, (mta_receiver, chi_i_j)))
            })
            .collect::<Result<Vec<_>, SignError>>()?,
    );

    for msg in to_send {
        relay.feed(msg).await.map_err(|_| SignError::SendMessage)?;
    }

    relay.flush().await?;

    let zeta_i =
        get_zeta_i(setup.keyshare(), &party_idx_to_id_map, &digest_i);

    let coeff = if setup.keyshare().zero_ranks() {
        get_lagrange_coeff(setup.keyshare(), &party_idx_to_id_map)
    } else {
        let betta_coeffs =
            get_birkhoff_coefficients(setup.keyshare(), &party_idx_to_id_map);

        *betta_coeffs
            .get(&(my_party_id as usize))
            .expect("betta_i not found") // FIXME
    };

    let (additive_offset, derived_public_key) = setup
        .keyshare()
        .derive_with_offset(setup.chain_path())
        .unwrap(); // FIXME: report error
    let threshold_inv = Scalar::from(setup.total_participants() as u32)
        .invert()
        .unwrap(); // threshold > 0 so it has an invert
    let additive_offset = additive_offset * threshold_inv;

    let sk_i = coeff * setup.keyshare().s_i() + additive_offset + zeta_i;
    let pk_i = ProjectivePoint::GENERATOR * sk_i;

    let mut sender_additive_shares = vec![];

    let mut round =
        Round::new(setup.total_participants() - 1, DSG_MSG_R2, relay);

    while let Some((msg, party_idx, is_abort)) = round.recv().await? {
        if is_abort {
            check_abort(setup, &msg, party_idx, SignError::AbortProtocol)?;
            round.put_back(&msg, ABORT_MESSAGE_TAG, party_idx);
            continue;
        }

        let mut msg = Zeroizing::new(msg);
        let msg2 = match EncryptedMessage::<SignMsg2>::decrypt(
            &mut msg, 0, &scheme, party_idx,
        ) {
            Some((refs, _)) => refs,
            _ => {
                round.put_back(&msg, DSG_MSG_R2, party_idx);
                continue;
            }
        };

        // Check final_session_id
        if msg2.final_session_id.ct_ne(&final_session_id).into() {
            return Err(SignError::InvalidFinalSessionID);
        }

        let receiver_id = find_party_id(party_idx);

        let sid = mta_session_id(&final_session_id, my_party_id, receiver_id);

        let seed_ot_results = setup.keyshare().receiver_seed(receiver_id);

        let mut enc_msg3 = EncryptedMessage::<SignMsg3>::new(
            &setup.msg_id(Some(party_idx), DSG_MSG_R3),
            setup.message_ttl().as_secs() as _,
            0,
            0,
            &scheme,
        );

        let (msg3, _) = enc_msg3.payload(&scheme);

        let [c_u, c_v] = RVOLESender::process(
            &sid,
            seed_ot_results,
            &[r_i, sk_i],
            &msg2.mta_msg1,
            &mut msg3.mta_msg2,
            &mut rng,
        )
        .map_err(|_| SignError::AbortProtocolAndBanParty(party_idx as u8))?;

        let gamma_u = ProjectivePoint::GENERATOR * c_u;
        let gamma_v = ProjectivePoint::GENERATOR * c_v;
        let (_mta_receiver, chi_i_j) = mta_receivers.find_pair(party_idx);

        let psi = phi_i - chi_i_j;

        msg3.final_session_id = final_session_id;
        msg3.digest_i = digest_i;
        msg3.pk_i = encode_point(&pk_i);
        msg3.big_r_i = encode_point(&big_r_i);
        msg3.blind_factor = blind_factor;
        msg3.gamma_v = encode_point(&gamma_v);
        msg3.gamma_u = encode_point(&gamma_u);
        msg3.psi = encode_scalar(&psi);

        round
            .relay
            .send(
                enc_msg3
                    .encrypt(&mut scheme, party_idx)
                    .ok_or(SignError::SendMessage)?,
            )
            .await?;

        sender_additive_shares.push([c_u, c_v]);
    }

    let mut big_r_star = ProjectivePoint::IDENTITY;
    let mut sum_pk_j = ProjectivePoint::IDENTITY;
    let mut sum_psi_j_i = Scalar::ZERO;

    let mut receiver_additive_shares = vec![];

    let mut round =
        Round::new(setup.total_participants() - 1, DSG_MSG_R3, relay);

    while let Some((msg, party_idx, is_abort)) = round.recv().await? {
        if is_abort {
            check_abort(setup, &msg, party_idx, SignError::AbortProtocol)?;
            round.put_back(&msg, ABORT_MESSAGE_TAG, party_idx);
            continue;
        }

        let mut msg = Zeroizing::new(msg);
        let msg3 = match EncryptedMessage::<SignMsg3>::decrypt(
            &mut msg, 0, &scheme, party_idx,
        ) {
            Some((refs, _)) => refs,
            _ => {
                round.put_back(&msg, DSG_MSG_R3, party_idx);
                continue;
            }
        };

        // Check final_session_id
        if msg3.final_session_id != final_session_id {
            return Err(SignError::InvalidFinalSessionID);
        }

        let (mta_receiver, chi_i_j) = mta_receivers.pop_pair(party_idx);

        let [d_u, d_v] =
            mta_receiver.process(&msg3.mta_msg2).map_err(|_| {
                SignError::AbortProtocolAndBanParty(party_idx as u8)
            })?;

        let (sid_i, commitment) = &commitments[party_idx];

        let big_r_j =
            decode_point(&msg3.big_r_i).ok_or(SignError::InvalidMessage)?;

        if !verify_commitment_r_i(
            sid_i,
            &big_r_j,
            &msg3.blind_factor,
            commitment,
        ) {
            return Err(SignError::InvalidCommitment);
        }

        if digest_i.ct_ne(&msg3.digest_i).into() {
            return Err(SignError::InvalidDigest);
        }

        let pk_j =
            decode_point(&msg3.pk_i).ok_or(SignError::InvalidMessage)?;

        big_r_star += big_r_j;
        sum_pk_j += pk_j;
        sum_psi_j_i +=
            decode_scalar(&msg3.psi).ok_or(SignError::InvalidMessage)?;

        let cond1 = (big_r_j * chi_i_j)
            == (ProjectivePoint::GENERATOR * d_u
                + decode_point(&msg3.gamma_u)
                    .ok_or(SignError::InvalidMessage)?);
        if !cond1 {
            return Err(SignError::AbortProtocolAndBanParty(party_idx as u8));
        }

        let cond2 = (pk_j * chi_i_j)
            == (ProjectivePoint::GENERATOR * d_v
                + decode_point(&msg3.gamma_v)
                    .ok_or(SignError::InvalidMessage)?);
        if !cond2 {
            return Err(SignError::AbortProtocolAndBanParty(party_idx as u8));
        }

        receiver_additive_shares.push([d_u, d_v]);
    }

    // new var
    let big_r = big_r_star + big_r_i;
    sum_pk_j += pk_i;

    // Checks
    if sum_pk_j != derived_public_key {
        return Err(SignError::FailedCheck("Consistency check 3 failed"));
    }

    let mut sum_v = Scalar::ZERO;
    let mut sum_u = Scalar::ZERO;

    for i in 0..setup.total_participants() - 1 {
        let sender_shares = &sender_additive_shares[i];
        let receiver_shares = &receiver_additive_shares[i];
        sum_u += sender_shares[0] + receiver_shares[0];
        sum_v += sender_shares[1] + receiver_shares[1];
    }

    let r_point = big_r.to_affine();
    let r_x = <Scalar as Reduce<U256>>::reduce_bytes(&r_point.x());
    let phi_plus_sum_psi = phi_i + sum_psi_j_i;
    let s_0 = r_x * (sk_i * phi_plus_sum_psi + sum_v);
    let s_1 = r_i * phi_plus_sum_psi + sum_u;

    let pre_sign_result = PreSign {
        final_session_id,
        public_key: encode_point(&derived_public_key),
        s_0: encode_scalar(&s_0),
        s_1: encode_scalar(&s_1),
        phi_i: encode_scalar(&phi_i),
        r: encode_point(&big_r),
        party_id: my_party_id,
    };

    Ok(pre_sign_result)
}

/// Creates a partial signature from a pre-signature result
///
/// This function takes a pre-signature result and a message hash,
/// and creates a partial signature that can be combined with other
/// partial signatures to form the final signature.
///
/// # Arguments
///
/// * `pre_sign_result`: The pre-signature result from the pre-signature phase
/// * `message_hash`: The hash of the message to be signed
///
/// # Returns
///
/// A `Result` containing either:
/// * `Ok(PartialSignature)`: The partial signature
/// * `Err(SignError)`: An error if the partial signature cannot be created
fn create_partial_signature(
    pre_sign_result: &PreSign,
    message_hash: [u8; 32],
) -> Result<PartialSignature, SignError> {
    let m = Scalar::reduce(U256::from_be_slice(&message_hash));

    let phi_i = decode_scalar(&pre_sign_result.phi_i)
        .ok_or(SignError::InvalidPreSign)?;

    let s_0 = decode_scalar(&pre_sign_result.s_0)
        .ok_or(SignError::InvalidPreSign)?;

    let s_0 = m * phi_i + s_0;

    let s_1 = decode_scalar(&pre_sign_result.s_1)
        .ok_or(SignError::InvalidPreSign)?;

    let r =
        decode_point(&pre_sign_result.r).ok_or(SignError::InvalidPreSign)?;

    let public_key = decode_point(&pre_sign_result.public_key)
        .ok_or(SignError::InvalidPreSign)?;

    Ok(PartialSignature {
        final_session_id: pre_sign_result.final_session_id,
        public_key,
        message_hash,
        s_0,
        s_1,
        r,
    })
}

/// Combines partial signatures into a final signature
///
/// This function takes a collection of partial signatures and combines
/// them to produce the final ECDSA signature and recovery ID.
///
/// # Arguments
///
/// * `partial_signatures`: A slice of partial signatures to combine
///
/// # Returns
///
/// A `Result` containing either:
/// * `Ok((Signature, RecoveryId))`: The final signature and recovery ID
/// * `Err(SignError)`: An error if the signatures cannot be combined
fn combine_partial_signature(
    partial_signatures: &[PartialSignature],
) -> Result<(Signature, RecoveryId), SignError> {
    let p0 = &partial_signatures[0];

    let mut check = Choice::from(0);

    let mut sum_s_0 = p0.s_0;
    let mut sum_s_1 = p0.s_1;

    for pn in &partial_signatures[1..] {
        check |= pn.final_session_id.ct_ne(&p0.final_session_id);
        check |= pn.public_key.ct_ne(&p0.public_key);
        check |= pn.r.ct_ne(&p0.r);
        check |= pn.message_hash.ct_ne(&p0.message_hash);

        sum_s_0 += pn.s_0;
        sum_s_1 += pn.s_1;
    }

    if check.into() {
        return Err(SignError::FailedCheck(
            "Invalid list of partial signatures",
        ));
    }

    let r = p0.r.to_affine();

    let is_y_odd: bool = r.y_is_odd().into();

    let r_x = <Scalar as Reduce<U256>>::reduce_bytes(&r.x());
    let is_x_reduced = r_x.to_repr() != r.x();
    let recid = RecoveryId::new(is_y_odd, is_x_reduced);

    let sum_s_1_inv = sum_s_1.invert().unwrap();
    let s = sum_s_0 * sum_s_1_inv;

    let is_y_odd = recid.is_y_odd() ^ bool::from(s.is_high());
    let recid = RecoveryId::new(is_y_odd, recid.is_x_reduced());

    let sign = Signature::from_scalars(r_x, s)?;
    let sign = sign.normalize_s().unwrap_or(sign);

    VerifyingKey::from_affine(p0.public_key.to_affine())?
        .verify_prehash(&p0.message_hash, &sign)?;

    Ok((sign, recid))
}

/// Main entry point for the DSG protocol
///
/// This function executes the complete DSG protocol, including both
/// the pre-signature and finish phases.
///
/// # Type Parameters
///
/// * `R`: Type implementing the `Relay` trait for message communication
/// * `S`: Type implementing the `SignSetupMessage` trait for setup parameters
///
/// # Arguments
///
/// * `setup`: Setup parameters for the protocol
/// * `seed`: Random seed for generating random values
/// * `relay`: Message relay for communication between parties
///
/// # Returns
///
/// A `Result` containing either:
/// * `Ok((Signature, RecoveryId))`: The final signature and recovery ID
/// * `Err(SignError)`: An error if the protocol fails
pub async fn run<R: Relay, S: SignSetupMessage>(
    setup: S,
    seed: Seed,
    relay: R,
) -> Result<(Signature, RecoveryId), SignError> {
    let abort_msg = create_abort_message(&setup);
    let mut relay = FilteredMsgRelay::new(relay);

    relay.ask_messages(&setup, ABORT_MESSAGE_TAG, false).await?;
    relay.ask_messages(&setup, DSG_MSG_R1, false).await?;
    relay.ask_messages(&setup, DSG_MSG_R2, true).await?;
    relay.ask_messages(&setup, DSG_MSG_R3, true).await?;
    relay.ask_messages(&setup, DSG_MSG_R4, false).await?;

    let result = match run_inner(setup, seed, &mut relay).await {
        Ok(sign) => Ok(sign),
        Err(SignError::AbortProtocol(p)) => Err(SignError::AbortProtocol(p)),
        Err(SignError::SendMessage) => Err(SignError::SendMessage),
        Err(err) => {
            // ignore error of sending abort message
            let _ = relay.send(abort_msg).await;
            Err(err)
        }
    };

    let _ = relay.close().await;

    result
}

/// Inner function for the main DSG protocol execution
///
/// This function implements the core logic of the DSG protocol,
/// handling both the pre-signature and finish phases.
///
/// # Type Parameters
///
/// * `R`: Type implementing the `Relay` trait for message communication
/// * `S`: Type implementing the `SignSetupMessage` trait for setup parameters
///
/// # Arguments
///
/// * `setup`: Setup parameters for the protocol
/// * `seed`: Random seed for generating random values
/// * `relay`: Message relay for communication between parties
///
/// # Returns
///
/// A `Result` containing either:
/// * `Ok((Signature, RecoveryId))`: The final signature and recovery ID
/// * `Err(SignError)`: An error if the protocol fails
async fn run_inner<R: Relay, S: SignSetupMessage>(
    setup: S,
    seed: Seed,
    relay: &mut FilteredMsgRelay<R>,
) -> Result<(Signature, RecoveryId), SignError> {
    let t = setup.total_participants();

    let pre_signature_result =
        pre_signature_inner(&setup, seed, relay).await?;

    let msg_hash = setup.message_hash();

    run_final(&setup, relay, t, msg_hash, &pre_signature_result).await
}

/// Executes the pre-signature phase of the DSG protocol
///
/// This function runs only the pre-signature phase of the protocol,
/// producing a pre-signature that can be used later to sign messages.
///
/// # Type Parameters
///
/// * `R`: Type implementing the `Relay` trait for message communication
/// * `S`: Type implementing the `PreSignSetupMessage` trait for setup parameters
///
/// # Arguments
///
/// * `setup`: Setup parameters for the protocol
/// * `seed`: Random seed for generating random values
/// * `relay`: Message relay for communication between parties
///
/// # Returns
///
/// A `Result` containing either:
/// * `Ok(PreSign)`: The pre-signature result
/// * `Err(SignError)`: An error if the protocol fails
pub async fn pre_signature<R: Relay, S: PreSignSetupMessage>(
    setup: S,
    seed: Seed,
    relay: R,
) -> Result<PreSign, SignError> {
    let abort_msg = create_abort_message(&setup);
    let mut relay = FilteredMsgRelay::new(relay);

    relay.ask_messages(&setup, ABORT_MESSAGE_TAG, false).await?;
    relay.ask_messages(&setup, DSG_MSG_R1, false).await?;
    relay.ask_messages(&setup, DSG_MSG_R2, true).await?;
    relay.ask_messages(&setup, DSG_MSG_R3, true).await?;

    let result = match pre_signature_inner(&setup, seed, &mut relay).await {
        Ok(result) => Ok(result),
        Err(SignError::AbortProtocol(p)) => Err(SignError::AbortProtocol(p)),
        Err(SignError::SendMessage) => Err(SignError::SendMessage),
        Err(err) => {
            relay.send(abort_msg).await?;
            Err(err)
        }
    };

    let _ = relay.close().await;

    result
}

/// Executes the finish phase of the DSG protocol
///
/// This function runs the finish phase of the protocol, using a
/// pre-signature to generate the final signature for a message.
///
/// # Type Parameters
///
/// * `R`: Type implementing the `Relay` trait for message communication
/// * `S`: Type implementing the `FinalSignSetupMessage` trait for setup parameters
///
/// # Arguments
///
/// * `setup`: Setup parameters for the protocol
/// * `relay`: Message relay for communication between parties
///
/// # Returns
///
/// A `Result` containing either:
/// * `Ok((Signature, RecoveryId))`: The final signature and recovery ID
/// * `Err(SignError)`: An error if the protocol fails
pub async fn finish<R: Relay, S: FinalSignSetupMessage>(
    setup: S,
    relay: R,
) -> Result<(Signature, RecoveryId), SignError> {
    let pre_signature_result = setup.pre_signature();
    let msg_hash = setup.message_hash();
    let mut relay = FilteredMsgRelay::new(relay);

    relay.ask_messages(&setup, ABORT_MESSAGE_TAG, false).await?;
    relay.ask_messages(&setup, DSG_MSG_R4, false).await?;

    let result = run_final(
        &setup,
        &mut relay,
        setup.total_participants(),
        msg_hash,
        pre_signature_result,
    )
    .await;

    let _ = relay.close().await;

    result
}

/// Inner function for the finish phase of the DSG protocol
///
/// This function implements the core logic of the finish phase,
/// where parties use a pre-signature to generate the final signature.
///
/// # Type Parameters
///
/// * `R`: Type implementing the `Relay` trait for message communication
/// * `S`: Type implementing the `ProtocolParticipant` trait for participant information
///
/// # Arguments
///
/// * `setup`: Setup parameters for the protocol
/// * `relay`: Message relay for communication between parties
/// * `t`: Threshold value for the signature
/// * `msg_hash`: Hash of the message to be signed
/// * `pre_signature_result`: The pre-signature result from the pre-signature phase
///
/// # Returns
///
/// A `Result` containing either:
/// * `Ok((Signature, RecoveryId))`: The final signature and recovery ID
/// * `Err(SignError)`: An error if the protocol fails
async fn run_final<R: Relay, S: ProtocolParticipant>(
    setup: &S,
    relay: &mut FilteredMsgRelay<R>,
    t: usize,
    msg_hash: [u8; 32],
    pre_signature_result: &PreSign,
) -> Result<(Signature, RecoveryId), SignError> {
    let public_key = decode_point(&pre_signature_result.public_key).unwrap();
    let r = decode_point(&pre_signature_result.r).unwrap();

    let partial_signature =
        create_partial_signature(pre_signature_result, msg_hash)?;

    relay
        .send(SignedMessage::build(
            &setup.msg_id(None, DSG_MSG_R4),
            setup.message_ttl().as_secs() as _,
            0,
            setup.signer(),
            |msg4: &mut SignMsg4, _| {
                msg4.session_id = partial_signature.final_session_id;
                msg4.s_0 = encode_scalar(&partial_signature.s_0);
                msg4.s_1 = encode_scalar(&partial_signature.s_1);
            },
        ))
        .await?;

    let mut partial_signatures: Vec<PartialSignature> = Vec::with_capacity(t);

    partial_signatures.push(partial_signature);

    Round::new(setup.total_participants() - 1, DSG_MSG_R4, relay)
        .of_signed_messages(
            setup,
            SignError::AbortProtocol,
            |msg: &SignMsg4, _party_idx| {
                partial_signatures.push(PartialSignature {
                    final_session_id: msg.session_id,
                    public_key,
                    message_hash: msg_hash,
                    s_0: decode_scalar(&msg.s_0)
                        .ok_or(SignError::InvalidMessage)?,
                    s_1: decode_scalar(&msg.s_1)
                        .ok_or(SignError::InvalidMessage)?,
                    r,
                });

                Ok(())
            },
        )
        .await?;

    combine_partial_signature(&partial_signatures)
}

/// Computes the hash of a commitment value
///
/// This function computes the hash of a commitment value using the
/// session ID, R point, and blind factor.
///
/// # Arguments
///
/// * `session_id`: The session identifier
/// * `big_r_i`: The R point value
/// * `blind_factor`: The blind factor value
///
/// # Returns
///
/// A 32-byte array containing the hash of the commitment
fn hash_commitment_r_i(
    session_id: &[u8],
    big_r_i: &ProjectivePoint,
    blind_factor: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DSG_LABEL);
    hasher.update(session_id.as_ref());
    hasher.update(big_r_i.to_bytes());
    hasher.update(blind_factor);
    hasher.update(COMMITMENT_LABEL);

    hasher.finalize().into()
}

/// Computes the zeta_i value for a party
///
/// This function computes the zeta_i value used in the signature
/// generation process.
///
/// # Arguments
///
/// * `keyshare`: The key share of the party
/// * `party_id_list`: List of party IDs participating in the protocol
/// * `sig_id`: The signature identifier
///
/// # Returns
///
/// The computed zeta_i scalar value
fn get_zeta_i(
    keyshare: &Keyshare,
    party_id_list: &[(usize, u8)],
    sig_id: &[u8],
) -> Scalar {
    let mut sum_p_0 = Scalar::ZERO;
    for &(_, p_0_party) in party_id_list {
        if p_0_party >= keyshare.party_id {
            continue;
        }

        let seed_j_i = keyshare.each(p_0_party).zeta_seed;

        let mut hasher = Sha256::new();
        hasher.update(DSG_LABEL);
        hasher.update(seed_j_i);
        hasher.update(sig_id);
        hasher.update(PAIRWISE_RANDOMIZATION_LABEL);
        sum_p_0 += Scalar::reduce(U256::from_be_slice(&hasher.finalize()));
    }

    let mut sum_p_1 = Scalar::ZERO;
    for &(_, p_1_party) in party_id_list {
        if p_1_party <= keyshare.party_id {
            continue;
        }

        let seed_i_j = keyshare.each(p_1_party - 1).zeta_seed;

        let mut hasher = Sha256::new();
        hasher.update(DSG_LABEL);
        hasher.update(seed_i_j);
        hasher.update(sig_id);
        hasher.update(PAIRWISE_RANDOMIZATION_LABEL);
        sum_p_1 += Scalar::reduce(U256::from_be_slice(&hasher.finalize()));
    }

    sum_p_0 - sum_p_1
}

/// Computes the Birkhoff coefficients for the protocol
///
/// This function computes the Birkhoff coefficients used in the
/// signature generation process.
///
/// # Arguments
///
/// * `keyshare`: The key share of the party
/// * `sign_party_ids`: List of party IDs participating in the protocol
///
/// # Returns
///
/// A map of party indices to their corresponding Birkhoff coefficients
fn get_birkhoff_coefficients(
    keyshare: &Keyshare,
    sign_party_ids: &[(usize, u8)],
) -> HashMap<usize, Scalar> {
    let params = sign_party_ids
        .iter()
        .map(|&(_, pid)| {
            (keyshare.get_x_i(pid), keyshare.get_rank(pid) as usize)
        })
        .collect::<Vec<_>>();

    let betta_vec = birkhoff_coeffs::<Secp256k1>(&params);

    sign_party_ids
        .iter()
        .zip(betta_vec.iter())
        .map(|((_, pid), w_i)| (*pid as usize, *w_i))
        .collect::<HashMap<_, _>>()
}

/// Computes the Lagrange coefficient for a party
///
/// This function computes the Lagrange coefficient used in the
/// signature generation process.
///
/// # Arguments
///
/// * `keyshare`: The key share of the party
/// * `sign_party_ids`: List of party IDs participating in the protocol
///
/// # Returns
///
/// The computed Lagrange coefficient
fn get_lagrange_coeff(
    keyshare: &Keyshare,
    sign_party_ids: &[(usize, u8)],
) -> Scalar {
    let mut coeff = Scalar::from(1u64);
    let pid = keyshare.party_id;
    let x_i = &keyshare.get_x_i(pid) as &Scalar;

    for &(_, party_id) in sign_party_ids {
        let x_j = &keyshare.get_x_i(party_id) as &Scalar;
        if x_i.ct_ne(x_j).into() {
            let sub = x_j - x_i;
            coeff *= x_j * &sub.invert().unwrap();
        }
    }

    coeff
}

/// Computes a list of Lagrange coefficients
///
/// This function computes a list of Lagrange coefficients for a set
/// of party points.
///
/// # Type Parameters
///
/// * `K`: Type of the key function
/// * `T`: Type of the party points
///
/// # Arguments
///
/// * `party_points`: List of party points
/// * `k`: Function to extract the key from a party point
///
/// # Returns
///
/// An iterator over the computed Lagrange coefficients
pub(crate) fn get_lagrange_coeff_list<'a, K, T>(
    party_points: &'a [T],
    k: K,
) -> impl Iterator<Item = Scalar> + 'a
where
    K: Fn(&T) -> &NonZeroScalar + 'a,
{
    party_points.iter().map(move |x_i| {
        let x_i = k(x_i);
        let mut coeff = Scalar::ONE;
        for x_j in party_points {
            let x_j = k(x_j);
            if x_i.ct_ne(x_j).into() {
                let sub = x_j.sub(x_i);
                // SAFETY: Invert is safe because we check x_j != x_i, so sub is not zero.
                coeff *= x_j.as_ref() * &sub.invert().unwrap();
            }
        }
        coeff
    })
}

/// Verifies a commitment value
///
/// This function verifies that a commitment value matches the expected
/// hash of the session ID, R point, and blind factor.
///
/// # Arguments
///
/// * `sid`: The session identifier
/// * `big_r_i`: The R point value
/// * `blind_factor`: The blind factor value
/// * `commitment`: The commitment value to verify
///
/// # Returns
///
/// `true` if the commitment is valid, `false` otherwise
fn verify_commitment_r_i(
    sid: &[u8],
    big_r_i: &ProjectivePoint,
    blind_factor: &[u8; 32],
    commitment: &[u8],
) -> bool {
    let compare_commitment = hash_commitment_r_i(sid, big_r_i, blind_factor);

    commitment.ct_eq(&compare_commitment).into()
}

/// Generates a session ID for the MtA protocol
///
/// This function generates a unique session ID for the MtA protocol
/// based on the final session ID and the sender/receiver IDs.
///
/// # Arguments
///
/// * `final_session_id`: The final session identifier
/// * `sender_id`: The ID of the sender party
/// * `receiver_id`: The ID of the receiver party
///
/// # Returns
///
/// A 32-byte array containing the generated session ID
fn mta_session_id(
    final_session_id: &[u8],
    sender_id: u8,
    receiver_id: u8,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DSG_LABEL);
    h.update(final_session_id);
    h.update(b"sender");
    h.update([sender_id]);
    h.update(b"receiver");
    h.update([receiver_id]);
    h.update(PAIRWISE_MTA_LABEL);
    h.finalize().into()
}

/// Test module for the DSG protocol
///
/// This module contains various test cases for the DSG protocol,
/// including tests for different party configurations and scenarios.
#[cfg(test)]
mod tests {
    use super::*;

    use tokio::task::JoinSet;

    use sl_mpc_mate::coord::SimpleMessageRelay;

    use crate::{
        keygen::utils::gen_keyshares,
        sign::{setup_dsg, setup_finish_sign},
    };

    #[tokio::test(flavor = "multi_thread")]
    async fn s2x2() {
        let coord = SimpleMessageRelay::new();

        let shares = gen_keyshares(2, 2, Some(&[0, 0])).await;

        let chain_path = "m";

        let mut parties = JoinSet::new();
        for (setup, seed) in setup_dsg(None, &shares, chain_path) {
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

    #[tokio::test(flavor = "multi_thread")]
    async fn s2x3() {
        let coord = SimpleMessageRelay::new();

        let shares = gen_keyshares(2, 3, Some(&[0, 1, 1])).await;

        let vk =
            VerifyingKey::from_affine(shares[0].public_key().to_affine())
                .unwrap();

        let chain_path = "m";

        let mut parties = JoinSet::new();
        for (setup, seed) in setup_dsg(None, &shares[0..2], chain_path) {
            parties.spawn(run(setup, seed, coord.connect()));
        }

        while let Some(fini) = parties.join_next().await {
            let fini = fini.unwrap();

            if let Err(ref err) = fini {
                println!("error {err:?}");
            }

            let (sign, recid) = fini.unwrap();

            let hash = [1u8; 32];

            let recid2 =
                RecoveryId::trial_recovery_from_prehash(&vk, &hash, &sign)
                    .unwrap();

            assert_eq!(recid, recid2);
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn s2x3_all_shares() {
        let coord = SimpleMessageRelay::new();

        let shares = gen_keyshares(2, 3, Some(&[0, 1, 1])).await;

        let vk =
            VerifyingKey::from_affine(shares[0].public_key().to_affine())
                .unwrap();

        let chain_path = "m";

        let mut parties = JoinSet::new();
        for (setup, seed) in setup_dsg(None, &shares, chain_path) {
            parties.spawn(run(setup, seed, coord.connect()));
        }

        while let Some(fini) = parties.join_next().await {
            let fini = fini.unwrap();

            if let Err(ref err) = fini {
                println!("error {err:?}");
            }

            let (sign, recid) = fini.unwrap();

            let hash = [1u8; 32];

            let recid2 =
                RecoveryId::trial_recovery_from_prehash(&vk, &hash, &sign)
                    .unwrap();

            assert_eq!(recid, recid2);
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn s3x5() {
        let coord = SimpleMessageRelay::new();

        let shares = gen_keyshares(3, 5, Some(&[0, 1, 1, 1, 1])).await;

        let vk =
            VerifyingKey::from_affine(shares[0].public_key().to_affine())
                .unwrap();

        let chain_path = "m";

        let mut parties = JoinSet::new();
        for (setup, seed) in setup_dsg(None, &shares[0..3], chain_path) {
            parties.spawn(run(setup, seed, coord.connect()));
        }

        while let Some(fini) = parties.join_next().await {
            let fini = fini.unwrap();

            if let Err(ref err) = fini {
                println!("error {err:?}");
            }

            let (sign, recid) = fini.unwrap();

            let hash = [1u8; 32];

            let recid2 =
                RecoveryId::trial_recovery_from_prehash(&vk, &hash, &sign)
                    .unwrap();

            assert_eq!(recid, recid2);
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn pre2x3() {
        let shares = gen_keyshares(2, 3, Some(&[0, 1, 1])).await;
        let chain_path = "m";

        let coord = SimpleMessageRelay::new();
        let mut parties = JoinSet::new();

        for (setup, seed) in setup_dsg(None, &shares[0..2], chain_path) {
            parties.spawn(pre_signature(setup, seed, coord.connect()));
        }

        let mut pre_sign = vec![];

        while let Some(fini) = parties.join_next().await {
            let fini = fini.unwrap();

            if let Err(ref err) = fini {
                println!("error {err:?}");
            }

            pre_sign.push(fini.unwrap())
        }

        let coord = SimpleMessageRelay::new();
        let mut parties = JoinSet::new();

        for setup in setup_finish_sign(pre_sign) {
            parties.spawn(finish(setup, coord.connect()));
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
