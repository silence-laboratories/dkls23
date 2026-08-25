//! Distributed signature generation with associated data.
//! Based on <https://eprint.iacr.org/2023/765.pdf>

use sl_mpc_mate::coord::*;

use super::{pre_signature_inner, run_final, SignError};
use crate::sign::associated_data_proof::AssociatedDataProof;
use crate::{
    proto::{create_abort_message, tags::*},
    setup::{SignSetupMessage, ABORT_MESSAGE_TAG},
    sign::constants::*,
    Seed,
};
use k256::ecdsa::{RecoveryId, Signature};

/// Execute DSG with associated data bound into the nonce.
pub async fn run<R: Relay, S: SignSetupMessage>(
    setup: S,
    seed: Seed,
    associated_data: Vec<u8>,
    relay: R,
) -> Result<(Signature, RecoveryId, AssociatedDataProof), SignError> {
    let abort_msg = create_abort_message(&setup);
    let mut relay = FilteredMsgRelay::new(relay);

    relay.ask_messages(&setup, ABORT_MESSAGE_TAG, false).await?;
    relay.ask_messages(&setup, DSG_MSG_R1, false).await?;
    relay.ask_messages(&setup, DSG_MSG_R2, true).await?;
    relay.ask_messages(&setup, DSG_MSG_R3, true).await?;
    relay.ask_messages(&setup, DSG_MSG_R4, false).await?;

    let result = match run_inner(setup, associated_data, seed, &mut relay).await {
        Ok(sign) => Ok(sign),
        Err(SignError::AbortProtocol(p)) => Err(SignError::AbortProtocol(p)),
        Err(SignError::SendMessage) => Err(SignError::SendMessage),
        Err(err) => {
            let _ = relay.send(abort_msg).await;
            Err(err)
        }
    };

    let _ = relay.close().await;
    result
}

async fn run_inner<R: Relay, S: SignSetupMessage>(
    setup: S,
    associated_data: Vec<u8>,
    seed: Seed,
    relay: &mut FilteredMsgRelay<R>,
) -> Result<(Signature, RecoveryId, AssociatedDataProof), SignError> {
    let t = setup.total_participants();

    let (pre_signature_result, proof) =
        pre_signature_inner(&setup, Some(associated_data), seed, relay).await?;

    let msg_hash = setup.message_hash();

    let (signature, recovery_id) =
        run_final(&setup, relay, t, msg_hash, &pre_signature_result).await?;

    Ok((signature, recovery_id, proof.unwrap()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::{
        ecdsa::{
            signature::hazmat::{PrehashSigner, PrehashVerifier},
            SigningKey, VerifyingKey,
        },
        elliptic_curve::group::GroupEncoding,
        sha2::{Digest, Sha256},
    };
    use sl_mpc_mate::coord::SimpleMessageRelay;
    use tokio::task::JoinSet;

    use crate::keygen::utils::gen_keyshares;
    use crate::sign::setup_dsg_with_message_hash;

    struct MultisigAssociatedData {
        prehash: [u8; 32],
        parties_set: Vec<(VerifyingKey, Signature)>,
    }

    impl MultisigAssociatedData {
        fn new(
            prehash: [u8; 32],
            parties_set: Vec<(VerifyingKey, Signature)>,
        ) -> Option<Self> {
            for (vk_i, sign_i) in parties_set.iter() {
                if vk_i.verify_prehash(&prehash, sign_i).is_err() {
                    return None;
                }
            }
            Some(Self {
                prehash,
                parties_set,
            })
        }

        fn get_participants_public_keys(&self) -> Vec<[u8; 33]> {
            self.parties_set
                .iter()
                .map(|(vk, _)| vk.as_affine().to_bytes().into())
                .collect()
        }

        fn to_bytes(&self) -> Vec<u8> {
            let mut res = Vec::new();
            res.extend_from_slice(&self.prehash);
            for (vk_i, sign_i) in self.parties_set.iter() {
                res.extend_from_slice(&vk_i.as_affine().to_bytes());
                res.extend_from_slice(&sign_i.to_bytes());
            }
            res
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn s2x3_with_associated_data() {
        let mut rng = rand::thread_rng();

        let sk_0 = SigningKey::random(&mut rng);
        let vk_0 = VerifyingKey::from(&sk_0);
        let sk_1 = SigningKey::random(&mut rng);
        let vk_1 = VerifyingKey::from(&sk_1);

        let message = b"Some transaction message";
        let message_hash: [u8; 32] = Sha256::digest(message).into();

        let sign_0: Signature = sk_0.sign_prehash(&message_hash).unwrap();
        let sign_1: Signature = sk_1.sign_prehash(&message_hash).unwrap();

        let associated_data = MultisigAssociatedData::new(
            message_hash,
            vec![(vk_0, sign_0), (vk_1, sign_1)],
        )
        .unwrap();
        let associated_data_bytes = associated_data.to_bytes();

        let coord = SimpleMessageRelay::new();
        let shares = gen_keyshares(2, 3, None).await;
        let vk =
            VerifyingKey::from_affine(shares[0].public_key().to_affine()).unwrap();
        let chain_path = "m";

        let mut parties = JoinSet::new();
        for (setup, seed) in setup_dsg_with_message_hash(
            None,
            &shares[0..2],
            chain_path,
            &message_hash,
        ) {
            parties.spawn(run(
                setup,
                seed,
                associated_data_bytes.clone(),
                coord.connect(),
            ));
        }

        while let Some(fini) = parties.join_next().await {
            let (sign, recid, proof) = fini.unwrap().unwrap();

            let recid2 =
                RecoveryId::trial_recovery_from_prehash(&vk, &message_hash, &sign)
                    .unwrap();
            assert_eq!(recid, recid2);

            assert!(proof.verify(
                &vk,
                &message_hash,
                &sign,
                &associated_data_bytes
            ));
        }

        let participants_pk = associated_data.get_participants_public_keys();
        assert_eq!(participants_pk.len(), 2);
        assert!(participants_pk.contains(&vk_0.as_affine().to_bytes().into()));
        assert!(participants_pk.contains(&vk_1.as_affine().to_bytes().into()));
    }

    /// Micro-benchmark for associated-data proving and verification.
    ///
    /// ```text
    /// cargo test --release --lib bench_associated_data_1000 -- --ignored --nocapture
    /// ```
    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn bench_associated_data_1000() {
        use std::hint::black_box;
        use std::time::{Duration, Instant};

        const N: usize = 1000;

        let mut rng = rand::thread_rng();
        let sk_0 = SigningKey::random(&mut rng);
        let vk_0 = VerifyingKey::from(&sk_0);
        let sk_1 = SigningKey::random(&mut rng);
        let vk_1 = VerifyingKey::from(&sk_1);

        let message = b"Some transaction message";
        let message_hash: [u8; 32] = Sha256::digest(message).into();
        let sign_0: Signature = sk_0.sign_prehash(&message_hash).unwrap();
        let sign_1: Signature = sk_1.sign_prehash(&message_hash).unwrap();
        let associated_data = MultisigAssociatedData::new(
            message_hash,
            vec![(vk_0, sign_0), (vk_1, sign_1)],
        )
        .unwrap();
        let associated_data_bytes = associated_data.to_bytes();

        let shares = gen_keyshares(2, 3, None).await;
        let vk =
            VerifyingKey::from_affine(shares[0].public_key().to_affine()).unwrap();
        let chain_path = "m";

        let mut prove_extra_ns = Vec::with_capacity(N);
        let mut verify_ns = Vec::with_capacity(N);
        let mut proof_size = 0usize;

        for i in 0..N {
            let coord = SimpleMessageRelay::new();
            let mut parties = JoinSet::new();
            for (setup, seed) in setup_dsg_with_message_hash(
                None,
                &shares[0..2],
                chain_path,
                &message_hash,
            ) {
                parties.spawn(run(
                    setup,
                    seed,
                    associated_data_bytes.clone(),
                    coord.connect(),
                ));
            }

            let mut round_proof = None;
            let mut round_sign = None;
            while let Some(fini) = parties.join_next().await {
                let (sign, _recid, proof) = fini.unwrap().unwrap();
                round_proof = Some(proof);
                round_sign = Some(sign);
            }
            let proof = round_proof.expect("proof");
            let sign = round_sign.expect("signature");

            let t0 = Instant::now();
            let tweak =
                AssociatedDataProof::ro(&proof.big_r_prime, &associated_data_bytes);
            let _tweaked = black_box(proof.big_r_prime * tweak);
            prove_extra_ns.push(t0.elapsed().as_nanos());

            let t1 = Instant::now();
            let ok = proof.verify(&vk, &message_hash, &sign, &associated_data_bytes);
            verify_ns.push(t1.elapsed().as_nanos());
            assert!(ok, "verification failed at iteration {i}");

            proof_size = proof.big_r_prime.to_bytes().len();
        }

        let prove_sum: u128 = prove_extra_ns.iter().sum();
        let ver_sum: u128 = verify_ns.iter().sum();
        let prove_mean = prove_sum as f64 / N as f64;
        let ver_mean = ver_sum as f64 / N as f64;

        println!("=== associated-data evaluation (N={N}) ===");
        println!("proof_size_bytes: {proof_size}");
        println!("associated_data_len_bytes: {}", associated_data_bytes.len());
        println!(
            "proof_computation_mean_us: {:.2}",
            prove_mean / 1000.0
        );
        println!(
            "verify_cumulative_ms: {:?}",
            Duration::from_nanos(ver_sum as u64)
        );
        println!("verify_mean_us: {:.2}", ver_mean / 1000.0);
    }
}
