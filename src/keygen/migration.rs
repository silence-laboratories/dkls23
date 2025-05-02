// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! This module provides functionality for migrating existing key shares from the other threshold ECDSA protocols
//! such as GG** to the DKLS23 protocol format. The migration process preserves the cryptographic properties
//! of the original key shares while updating them to the new protocol format.

use crate::keygen::{KeyRefreshData, KeygenError, Keyshare};
use crate::proto::{create_abort_message, FilteredMsgRelay};
use crate::setup::KeygenSetupMessage;
use crate::{keygen, Seed};
use futures_util::SinkExt;
use k256::{ProjectivePoint, Scalar};
use sl_mpc_mate::coord::Relay;

/// Migrates key shares from other ECDSA threshold protocols to DKLS23 format.
///
/// This function performs the migration of existing key shares to the DKLS23 protocol.
/// It uses the same underlying logic as the key refresh process but with a hardcoded initial secret
/// share value. The migration preserves the original public key and chain code while updating the
/// internal representation to the new protocol format.
///
/// # Type Parameters
///
/// * `R` - A type implementing the `Relay` trait for message communication
/// * `S` - A type implementing the `KeygenSetupMessage` trait for protocol setup
///
/// # Arguments
///
/// * `setup` - The protocol setup configuration
/// * `seed` - The random seed for key generation
/// * `relay` - The message relay for communication between parties
/// * `s_i_0` - The initial additive secret share value from the existing protocol
/// * `public_key` - The public key to be preserved during migration
/// * `root_chain_code` - The root chain code to be preserved during migration
///
/// # Returns
///
/// * `Ok(Keyshare)` - The migrated key share in DKLS23 format
/// * `Err(KeygenError)` - If the migration process fails
///
/// # Errors
///
/// This function may return the following errors:
/// * `KeygenError::AbortProtocol` - If the protocol is aborted by a participant
/// * `KeygenError::SendMessage` - If there's an error sending messages
/// * Other `KeygenError` variants for various protocol failures
pub async fn run<R, S>(
    setup: S,
    seed: Seed,
    relay: R,
    s_i_0: Scalar,
    public_key: ProjectivePoint,
    root_chain_code: [u8; 32],
) -> Result<Keyshare, KeygenError>
where
    S: KeygenSetupMessage,
    R: Relay,
{
    let abort_msg = create_abort_message(&setup);

    let mut relay = FilteredMsgRelay::new(relay);

    let key_refresh_data = KeyRefreshData {
        s_i_0,
        lost_keyshare_party_ids: vec![],
        expected_public_key: public_key,
        root_chain_code, //we expect always a chain code from the migration
    };

    let result: Result<Keyshare, KeygenError> =
        keygen::run_inner(setup, seed, &mut relay, Some(&key_refresh_data))
            .await;

    let new_keyshare = match result {
        Ok(eph_keyshare) => eph_keyshare,

        Err(KeygenError::AbortProtocol(p)) => {
            return Err(KeygenError::AbortProtocol(p))
        }

        Err(KeygenError::SendMessage) => {
            return Err(KeygenError::SendMessage)
        }

        Err(err_message) => {
            #[cfg(feature = "tracing")]
            tracing::debug!("sending abort message");

            relay.send(abort_msg).await?;

            return Err(err_message);
        }
    };

    Ok(new_keyshare)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::utils::setup_keygen;
    use crate::sign::{run as run_dsg, setup_dsg};
    use k256::elliptic_curve::group::GroupEncoding;
    use k256::elliptic_curve::ops::MulByGenerator;
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::{CompressedPoint, NonZeroScalar, U256};
    use sl_mpc_mate::coord::SimpleMessageRelay;
    use std::collections::VecDeque;
    use std::sync::Arc;
    use tokio::task::JoinSet;

    #[tokio::test(flavor = "multi_thread")]
    async fn migration_test() {
        let coord = SimpleMessageRelay::new();

        let mut parties = JoinSet::new();

        let binding = hex::decode(
            "02eba32793892022121314aed023df242292d313cb657f6f69016d90b6cfc92d33".as_bytes(),
        )
        .unwrap();
        let public_key = ProjectivePoint::from_bytes(
            CompressedPoint::from_slice(&binding),
        );

        let mut s_i_0 = VecDeque::new();

        s_i_0.push_back(
            NonZeroScalar::from_uint(U256::from_be_hex(
                "3B6661CC3A28C174AF9D0FDD966E9F9D9D2A96682A504E1E9165D700BDC47809",
            ))
            .unwrap(),
        );
        s_i_0.push_back(
            NonZeroScalar::from_uint(U256::from_be_hex(
                "3361D26EBB452DDA716E38F20405B42E3ABDC890CAEE1150AB0D019D45091DC4",
            ))
            .unwrap(),
        );
        s_i_0.push_back(
            NonZeroScalar::from_uint(U256::from_be_hex(
                "71FDD4E9358DB270FA0EF15F4D72A6267B012781D154D2A380ECFCA86E85BEA2",
            ))
            .unwrap(),
        );

        let sk = s_i_0.iter().fold(Scalar::ZERO, |sum, val| sum.add(val));
        let pub_key = ProjectivePoint::mul_by_generator(&sk);
        println!(
            "{:?}",
            pub_key
                .to_encoded_point(true)
                .x()
                .iter()
                .map(|v| format!("{:02X}", v))
                .collect::<Vec<_>>()
                .join(".")
        );
        let root_chain_code = "253453627f65463253453627f6546321".as_bytes()
            [0..32]
            .try_into()
            .unwrap();

        for (setupmsg, seed) in setup_keygen(None, 2, 3, None) {
            parties.spawn(run(
                setupmsg,
                seed,
                coord.connect(),
                *s_i_0.pop_front().unwrap(),
                public_key.unwrap(),
                root_chain_code,
            ));
        }

        let mut new_shares = vec![];
        while let Some(fini) = parties.join_next().await {
            let fini = fini.unwrap();

            if let Err(ref err) = fini {
                println!("error {}", err);
            }
            //fixme
            assert!(fini.is_ok());

            let new_share = fini.unwrap();
            let pk = hex::encode(new_share.public_key().to_bytes());

            new_shares.push(Arc::new(new_share));

            println!("PK {}", pk);
        }

        // sign with new key_shares
        let coord = SimpleMessageRelay::new();

        new_shares.sort_by_key(|share| share.party_id);
        let subset = &new_shares[0..2_usize];

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
}
