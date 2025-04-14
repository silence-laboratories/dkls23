// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! Module for importing private key into the protocol

use k256::{NonZeroScalar, ProjectivePoint, Scalar};
use rand::{CryptoRng, RngCore};
use sl_mpc_mate::math::Polynomial;

use crate::keygen::key_refresh::KeyshareForRefresh;

/// Create ecdsa keyshares from private key.
///
pub fn ecdsa_secret_shares<T: RngCore + CryptoRng>(
    threshold: u8,
    rank_list: Vec<u8>,
    private_key: &NonZeroScalar,
    root_chain_code: [u8; 32],
    skip: Option<&[u8]>,
    rng: &mut T,
) -> Vec<KeyshareForRefresh> {
    let lost = skip.unwrap_or(&[]).to_vec();

    let private_key: &Scalar = private_key;
    let public_key = ProjectivePoint::GENERATOR * private_key;

    // u_i_k
    let mut polynomial =
        Polynomial::<ProjectivePoint>::random(rng, threshold as usize - 1);

    polynomial.set_constant(*private_key); // making a copy of private key

    let x_i_list = (0..rank_list.len())
        .map(|i| NonZeroScalar::from_uint((i as u64 + 1).into()).unwrap())
        .collect::<Vec<_>>();

    let shares = rank_list
        .iter()
        .zip(&x_i_list)
        .enumerate()
        .filter(|&(i, _)| !lost.contains(&(i as u8)))
        .map(|(i, (&n_i, x_i))| {
            let s_i: Scalar = polynomial.derivative_at(n_i as usize, x_i);

            KeyshareForRefresh::new(
                rank_list.clone(),
                threshold,
                public_key,
                root_chain_code,
                Some(s_i),
                Some(x_i_list.clone()),
                lost.clone(),
                i as u8,
            )
        })
        .collect();

    // FIXME: it should be Zeroize
    polynomial.reset_contant();

    shares
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use k256::{
        elliptic_curve::sec1::ToEncodedPoint, NonZeroScalar, ProjectivePoint,
    };
    use rand::Rng;
    use sl_mpc_mate::coord::SimpleMessageRelay;
    use tokio::task::JoinSet;

    use crate::{
        key_import::ecdsa_secret_shares,
        keygen::{
            key_refresh::{run, setup_key_refresh, KeyshareForRefresh},
            Keyshare,
        },
        sign::setup_dsg,
    };

    async fn refresh(
        keyshares: Vec<KeyshareForRefresh>,
    ) -> Vec<Arc<Keyshare>> {
        let coord = SimpleMessageRelay::new();
        let mut parties = JoinSet::new();

        for (setup, seed, share) in
            setup_key_refresh(2, 3, Some(&[0, 0, 0]), keyshares)
        {
            parties.spawn(run(setup, seed, coord.connect(), share));
        }

        let mut new_shares = vec![];
        while let Some(fini) = parties.join_next().await {
            let fini = fini.unwrap();

            if let Err(ref err) = fini {
                println!("error {}", err);
            }

            assert!(fini.is_ok());

            let new_share = fini.unwrap();
            new_shares.push(Arc::new(new_share));
        }

        new_shares
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn import_key() {
        let mut rng = rand::thread_rng();
        let private_key = NonZeroScalar::random(&mut rng);
        let original_pubkey = ProjectivePoint::GENERATOR * *private_key;

        let keyshares = ecdsa_secret_shares(
            2,
            vec![0, 0, 0],
            &private_key,
            rng.gen(),
            None,
            &mut rng,
        );
        let original_chain_code = keyshares[0].root_chain_code;

        let mut new_shares = refresh(keyshares).await;

        let pubkey = new_shares[0].public_key;
        let new_chain_code = new_shares[0].root_chain_code;
        // Check if the chain code is not the default chain code
        assert_ne!(new_chain_code, [0; 32]);

        // Check if the public key is the same as the original public key after refreshing
        // keyshares
        assert_eq!(pubkey, original_pubkey.to_encoded_point(true).as_bytes());
        assert_eq!(new_chain_code, original_chain_code);

        // sign with party_0 and party_1 new key_shares
        let coord = SimpleMessageRelay::new();

        new_shares.sort_by_key(|share| share.party_id);
        let subset = &new_shares[0..2_usize];

        let mut parties: JoinSet<Result<_, _>> = JoinSet::new();
        for (setup, seed) in setup_dsg(None, subset, "m") {
            parties.spawn(crate::sign::run(setup, seed, coord.connect()));
        }

        while let Some(fini) = parties.join_next().await {
            let fini = fini.unwrap();

            if let Err(ref err) = fini {
                println!("error {err:?}");
            }
            let _fini = fini.unwrap();
        }
    }

    // this is the same test as above but it uses first 2 shares returned by
    // `ecdsa_secret_shares()` and runs key recovery protocol.
    #[tokio::test(flavor = "multi_thread")]
    async fn import_key_2x3() {
        let mut rng = rand::thread_rng();
        let private_key = NonZeroScalar::random(&mut rng);
        let original_pubkey = ProjectivePoint::GENERATOR * *private_key;

        let mut keyshares = ecdsa_secret_shares(
            2,
            vec![0, 0, 0],
            &private_key,
            rng.gen(),
            Some(&[2]), // skip party-id 2
            &mut rng,
        );
        let original_chain_code = keyshares[0].root_chain_code;

        keyshares.push(KeyshareForRefresh::from_lost_keyshare(
            vec![0; 3],
            2,
            original_pubkey,
            vec![2],
            2,
        ));

        let new_shares = refresh(keyshares).await;

        let pubkey = new_shares[0].public_key;
        let new_chain_code = new_shares[0].root_chain_code;
        // Check if the chain code is not the default chain code
        assert_ne!(new_chain_code, [0; 32]);

        // Check if the public key is the same as the original public
        // key after refreshing keyshares
        assert_eq!(pubkey, original_pubkey.to_encoded_point(true).as_bytes());
        assert_eq!(new_chain_code, original_chain_code);

        let coord = SimpleMessageRelay::new();
        let subset = &new_shares[0..2_usize];

        let mut parties: JoinSet<Result<_, _>> = JoinSet::new();
        for (setup, seed) in setup_dsg(None, subset, "m") {
            parties.spawn(crate::sign::run(setup, seed, coord.connect()));
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
