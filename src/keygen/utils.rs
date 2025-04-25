// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! Utility Functions for DKG Protocol
//!
//! This module provides utility functions used throughout the DKG protocol implementation,
//! including polynomial operations, key generation setup, and protocol execution helpers.
//! It also includes test utilities for protocol simulation and verification.

use std::collections::HashMap;

#[cfg(any(test, feature = "test-support"))]
use std::sync::Arc;

use k256::{
    elliptic_curve::subtle::ConstantTimeEq, NonZeroScalar, ProjectivePoint, Scalar, Secp256k1,
};
#[cfg(any(test, feature = "test-support"))]
use rand::prelude::*;
#[cfg(any(test, feature = "test-support"))]
use sha2::{Digest, Sha256};

use sl_mpc_mate::math::birkhoff_coeffs;

#[cfg(any(test, feature = "test-support"))]
use crate::setup::{keygen::SetupMessage, *};

#[cfg(any(test, feature = "test-support"))]
use crate::setup::{
    keygen::SetupMessage as KeygenSetupMessage,
    quorum_change::SetupMessage as QuorumChangeSetupMessage,
};
use crate::sign::get_lagrange_coeff_list;

#[cfg(any(test, feature = "test-support"))]
use super::Keyshare;

use super::KeygenError;

/// Computes the Lagrange coefficient for a given point in a polynomial.
///
/// This function calculates the Lagrange coefficient for a specific point `x_i`
/// given a list of points `x_i_list` and their corresponding party IDs.
///
/// # Arguments
/// * `x_i` - The point for which to compute the coefficient
/// * `x_i_list` - List of all points in the polynomial
/// * `party_ids` - List of party IDs corresponding to the points
///
/// # Returns
/// The computed Lagrange coefficient as a scalar value
pub(crate) fn get_lagrange_coeff(
    x_i: &NonZeroScalar,
    x_i_list: &[NonZeroScalar],
    party_ids: &[u8],
) -> Scalar {
    let mut coeff = Scalar::ONE;
    let x_i = x_i as &Scalar;
    for &party_id in party_ids {
        let x_j = &x_i_list[party_id as usize] as &Scalar;
        if x_i.ct_ne(x_j).into() {
            let sub = x_j - x_i;
            coeff *= x_j * &sub.invert().unwrap();
        }
    }

    coeff
}

/// Computes Birkhoff coefficients for a set of points with ranks.
///
/// This function calculates the Birkhoff coefficients for a set of points with
/// associated ranks, which are used in the Birkhoff interpolation process.
///
/// # Arguments
/// * `rank_list` - List of ranks for each point
/// * `x_i_list` - List of points in the polynomial
/// * `party_ids` - List of party IDs corresponding to the points
///
/// # Returns
/// A map of party IDs to their corresponding Birkhoff coefficients
pub(crate) fn get_birkhoff_coefficients(
    rank_list: &[u8],
    x_i_list: &[NonZeroScalar],
    party_ids: &[u8],
) -> HashMap<usize, Scalar> {
    let params = party_ids
        .iter()
        .map(|&pid| (x_i_list[pid as usize], rank_list[pid as usize] as usize))
        .collect::<Vec<_>>();

    let betta_vec = birkhoff_coeffs::<Secp256k1>(&params);

    party_ids
        .iter()
        .zip(betta_vec)
        .map(|(&pid, w_i)| (pid as usize, w_i))
        .collect::<HashMap<_, _>>()
}

/// Verifies that a secret can be recovered from the given shares.
///
/// This function checks whether the provided shares can be used to reconstruct
/// the original secret by verifying that the reconstructed public key matches
/// the expected public key.
///
/// # Arguments
/// * `x_i_list` - List of x-coordinates for the shares
/// * `rank_list` - List of ranks for each share
/// * `big_s_list` - List of public key components
/// * `public_key` - The expected public key
///
/// # Returns
/// `Ok(())` if the secret can be recovered, or an error if verification fails
#[allow(dead_code)]
pub(crate) fn check_secret_recovery(
    x_i_list: &[NonZeroScalar],
    rank_list: &[u8],
    big_s_list: &[ProjectivePoint],
    public_key: &ProjectivePoint,
) -> Result<(), KeygenError> {
    // If ranks are all zero, then we use lagrange interpolation
    let exp_public_key = if rank_list.iter().all(|&r| r == 0) {
        let coeff_vector = get_lagrange_coeff_list(x_i_list, |x| x);
        big_s_list
            .iter()
            .zip(coeff_vector)
            .fold(ProjectivePoint::IDENTITY, |acc, (point, betta_i)| {
                acc + point * &betta_i
            })
    } else {
        // Otherwise, we use Birkhoff interpolation
        let mut party_params_list = x_i_list
            .iter()
            .zip(rank_list)
            .zip(big_s_list)
            .collect::<Vec<((&NonZeroScalar, &u8), &ProjectivePoint)>>();

        party_params_list.sort_by_key(|((_, &n_i), _)| n_i);

        let params = party_params_list
            .iter()
            .map(|((&x_i, &n_i), _)| (x_i, n_i as usize))
            .collect::<Vec<_>>();

        let betta_vector = birkhoff_coeffs(&params);

        party_params_list
            .into_iter()
            .map(|((_, _), &big_s_i)| big_s_i)
            .zip(betta_vector)
            .fold(ProjectivePoint::IDENTITY, |acc, (point, betta_i)| {
                acc + point * betta_i
            })
    };

    (public_key == &exp_public_key)
        .then_some(())
        .ok_or(KeygenError::PublicKeyMismatch)
}

/// Generates setup messages and seeds for DKG parties.
///
/// This function creates the necessary setup messages and seeds for all parties
/// participating in the DKG protocol. It handles both the case where ranks are
/// provided and where they are not.
///
/// # Arguments
/// * `instance` - Optional instance identifier for the protocol
/// * `t` - Threshold value for the protocol
/// * `n` - Total number of parties
/// * `ranks` - Optional list of ranks for each party
///
/// # Returns
/// A vector of tuples containing setup messages and seeds for each party
#[cfg(any(test, feature = "test-support"))]
pub fn setup_keygen(
    instance: Option<[u8; 32]>,
    t: u8,
    n: u8,
    ranks: Option<&[u8]>,
) -> Vec<(KeygenSetupMessage, [u8; 32])> {
    use std::time::Duration;

    use sl_mpc_mate::message::InstanceId;

    let ranks = if let Some(ranks) = ranks {
        assert_eq!(ranks.len(), n as usize);
        ranks.to_vec()
    } else {
        vec![0u8; n as usize]
    };

    let instance = instance.unwrap_or_else(rand::random);

    // a signing key for each party.
    let party_sk: Vec<NoSigningKey> = std::iter::repeat_with(|| NoSigningKey)
        .take(n as usize)
        .collect();

    let party_vk: Vec<NoVerifyingKey> = party_sk
        .iter()
        .enumerate()
        .map(|(party_id, _)| NoVerifyingKey::new(party_id))
        .collect();

    party_sk
        .into_iter()
        .enumerate()
        .map(|(party_id, sk)| {
            SetupMessage::new(
                InstanceId::new(instance),
                sk,
                party_id,
                party_vk.clone(),
                &ranks,
                t as usize,
            )
            .with_ttl(Duration::from_secs(1000)) // for dkls-metrics benchmarks
        })
        .map(|setup| {
            let mixin = [setup.participant_index() as u8 + 1];

            (
                setup,
                Sha256::new()
                    .chain_update(instance)
                    .chain_update(b"party-seed")
                    .chain_update(mixin)
                    .finalize()
                    .into(),
            )
        })
        .collect::<Vec<_>>()
}

/// Executes the DKG protocol with the given parameters.
///
/// This function runs the DKG protocol for a set of parties with the specified
/// threshold and number of participants. It returns the generated key shares.
///
/// # Arguments
/// * `t` - Threshold value for the protocol
/// * `n` - Total number of parties
/// * `ranks` - Optional list of ranks for each party
///
/// # Returns
/// A vector of key shares, one for each party
#[cfg(any(test, feature = "test-support"))]
pub async fn gen_keyshares(t: u8, n: u8, ranks: Option<&[u8]>) -> Vec<Arc<Keyshare>> {
    let coord = sl_mpc_mate::coord::SimpleMessageRelay::new();

    let mut parties = tokio::task::JoinSet::new();
    for (setup, seed) in setup_keygen(None, t, n, ranks) {
        parties.spawn({
            let relay = coord.connect();
            crate::keygen::run(setup, seed, relay)
        });
    }

    let mut shares = vec![];

    while let Some(fini) = parties.join_next().await {
        if let Err(ref err) = fini {
            println!("error {err:?}");
        } else {
            match fini.unwrap() {
                Err(err) => panic!("err {:?}", err),
                Ok(share) => shares.push(Arc::new(share)),
            }
        }
    }

    shares.sort_by_key(|share| share.party_id);

    shares
}

/// Generates setup messages and seeds for quorum change parties.
///
/// This function creates setup messages and seeds for all parties participating
/// in a quorum change protocol, including both existing and new parties.
///
/// # Arguments
/// * `old_keyshares` - Existing key shares from the current quorum
/// * `new_threshold` - New threshold value for the protocol
/// * `new_n_i_list` - List of ranks for new parties
///
/// # Returns
/// A vector of tuples containing setup messages and seeds for each party
#[cfg(any(test, feature = "test-support"))]
pub fn setup_quorum_change(
    old_keyshares: &[Arc<Keyshare>],
    new_threshold: u8,
    new_n_i_list: &[u8],
) -> Vec<(QuorumChangeSetupMessage, [u8; 32])> {
    let old_threshold = old_keyshares[0].threshold as usize;
    let old_participants = old_keyshares.len();
    assert!(old_keyshares.len() >= old_threshold);

    let public_key = old_keyshares[0].public_key();

    let total_parties = old_participants + new_n_i_list.len();

    let old_parties = (0..old_participants).collect::<Vec<usize>>();
    let new_parties = new_n_i_list
        .iter()
        .enumerate()
        .map(|(p, &r)| ((p + old_participants), r))
        .collect::<Vec<_>>();

    let mut rng = rand::thread_rng();

    let instance = rng.gen::<[u8; 32]>().into();

    // a signing key for each party.
    let party_sk: Vec<NoSigningKey> = std::iter::repeat_with(|| NoSigningKey)
        .take(total_parties)
        .collect();

    let party_vk: Vec<NoVerifyingKey> = party_sk
        .iter()
        .enumerate()
        .map(|(p, _)| NoVerifyingKey::new(p))
        .collect();

    party_sk
        .into_iter()
        .enumerate()
        .map(|(p, sk)| {
            // first old_parties_n with Keyshare
            let keyshare = if p < old_participants {
                Some(old_keyshares[p].clone())
            } else {
                None
            };

            QuorumChangeSetupMessage::new(
                instance,
                p,
                &old_parties,
                &new_parties,
                new_threshold as usize,
                sk,
                party_vk.clone(),
                public_key,
            )
            .with_keyshare_opt(keyshare)
        })
        .map(|setup| (setup, rng.gen()))
        .collect::<Vec<_>>()
}

/// Generates setup messages and seeds for extending the quorum with new parties.
///
/// This function creates setup messages and seeds for a quorum change that
/// adds new parties to the existing quorum.
///
/// # Arguments
/// * `old_keyshares` - Existing key shares from the current quorum
/// * `new_threshold` - New threshold value for the protocol
/// * `new_participants_len` - Number of new participants to add
/// * `new_n_i_list` - List of ranks for new parties
///
/// # Returns
/// A vector of tuples containing setup messages and seeds for each party
#[cfg(any(test, feature = "test-support"))]
pub fn setup_quorum_change_extend_parties(
    old_keyshares: &[Arc<Keyshare>],
    new_threshold: u8,
    new_participants_len: u8,
    new_n_i_list: &[u8],
) -> Vec<(QuorumChangeSetupMessage, [u8; 32])> {
    let new_n = old_keyshares.len() + new_participants_len as usize;

    let old_threshold = old_keyshares[0].threshold as usize;
    let old_participants = old_keyshares.len();
    assert!(old_keyshares.len() >= old_threshold);

    let public_key = old_keyshares[0].public_key();

    let total_parties = new_n;

    let old_parties = (0..old_keyshares.len()).collect::<Vec<_>>();
    let new_parties = new_n_i_list
        .iter()
        .enumerate()
        .map(|(p, &r)| (p, r))
        .collect::<Vec<_>>();

    let mut rng = rand::thread_rng();

    let instance = rng.gen::<[u8; 32]>().into();

    // a signing key for each party.
    let party_sk: Vec<NoSigningKey> = std::iter::repeat_with(|| NoSigningKey)
        .take(total_parties)
        .collect();
    let party_vk: Vec<NoVerifyingKey> = party_sk
        .iter()
        .enumerate()
        .map(|(p, _)| NoVerifyingKey::new(p))
        .collect();

    party_sk
        .into_iter()
        .enumerate()
        .map(|(p, sk)| {
            // first old_parties_n with Keyshare
            let keyshare = if p < old_participants {
                Some(old_keyshares[p].clone())
            } else {
                None
            };

            QuorumChangeSetupMessage::new(
                instance,
                p,
                &old_parties,
                &new_parties,
                new_threshold as usize,
                sk,
                party_vk.clone(),
                public_key,
            )
            .with_keyshare_opt(keyshare)
        })
        .map(|setup| (setup, rng.gen()))
        .collect::<Vec<_>>()
}

/// Generates setup messages and seeds for changing the quorum threshold.
///
/// This function creates setup messages and seeds for a quorum change that
/// modifies the threshold value while keeping the same set of parties.
///
/// # Arguments
/// * `old_keyshares` - Existing key shares from the current quorum
/// * `new_threshold` - New threshold value for the protocol
/// * `new_n_i_list` - List of ranks for the parties
///
/// # Returns
/// A vector of tuples containing setup messages and seeds for each party
#[cfg(any(test, feature = "test-support"))]
pub fn setup_quorum_change_threshold(
    old_keyshares: &[Arc<Keyshare>],
    new_threshold: u8,
    new_n_i_list: &[u8],
) -> Vec<(QuorumChangeSetupMessage, [u8; 32])> {
    assert!(old_keyshares.len() >= old_keyshares[0].threshold as usize);

    let total_parties = old_keyshares.len();

    let old_participants = old_keyshares.len();

    let public_key = old_keyshares[0].public_key();

    let old_parties = (0..old_keyshares.len()).collect::<Vec<_>>();

    let new_parties = new_n_i_list.iter().copied().enumerate().collect::<Vec<_>>();

    let mut rng = rand::thread_rng();

    let instance = rng.gen::<[u8; 32]>().into();

    // a signing key for each party.
    let party_sk: Vec<NoSigningKey> = std::iter::repeat_with(|| NoSigningKey)
        .take(total_parties)
        .collect();
    let party_vk: Vec<NoVerifyingKey> = party_sk
        .iter()
        .enumerate()
        .map(|(p, _)| NoVerifyingKey::new(p))
        .collect();

    party_sk
        .into_iter()
        .enumerate()
        .map(|(p, sk)| {
            // first old_parties_n with Keyshare
            let keyshare = if p < old_participants {
                Some(old_keyshares[p].clone())
            } else {
                None
            };

            QuorumChangeSetupMessage::new(
                instance,
                p,
                &old_parties,
                &new_parties,
                new_threshold as usize,
                sk,
                party_vk.clone(),
                public_key,
            )
            .with_keyshare_opt(keyshare)
        })
        .map(|setup| (setup, rng.gen()))
        .collect::<Vec<_>>()
}
