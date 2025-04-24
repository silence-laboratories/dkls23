// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use k256::{NonZeroScalar, ProjectivePoint, Scalar};
use rand::prelude::*;
use x25519_dalek::{PublicKey, ReusableSecret};
use zeroize::Zeroizing;

use sl_mpc_mate::{
    coord::*,
    math::birkhoff_coeffs,
    message::{MessageTag, MsgId, MESSAGE_HEADER_SIZE},
};

/// Tag of an encypted keyshare message
pub const KEYSHARE_EXPORT_TAG: MessageTag = MessageTag::tag(1);

/// Receiver of an encrypted keyshare.
const EXPORTED_KEYSHARE_RECEIVER: usize = 0;

use crate::{
    keygen::Keyshare,
    pairs::Pairs,
    proto::{check_abort, decode_scalar, tags::*, EncryptedMessage, EncryptionScheme, ScalarBytes},
    setup::{
        KeyExportReceiverSetupMessage, KeyExporterSetupMessage, ProtocolParticipant,
        ABORT_MESSAGE_TAG,
    },
    sign::get_lagrange_coeff_list,
};

#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
/// Distributed key generation errors
pub enum KeyExportError {
    #[error("Error while deserializing message or invalid message data length")]
    InvalidMessage,

    #[error("Public key mismatch after combining keyshares")]
    PublicKeyMismatch,

    /// Missing message
    #[error("Missing message")]
    MissingMessage,

    /// We can't a send message
    #[error("Send message")]
    SendMessage,

    /// Some party decided to not participate in the protocol.
    #[error("Abort protocol by party {0}")]
    AbortProtocol(usize),
}

impl From<MessageSendError> for KeyExportError {
    fn from(_err: MessageSendError) -> Self {
        KeyExportError::SendMessage
    }
}

impl From<Error> for KeyExportError {
    fn from(err: Error) -> Self {
        match err {
            Error::Abort(p) => KeyExportError::AbortProtocol(p as _),
            Error::Recv => KeyExportError::MissingMessage,
            Error::Send => KeyExportError::SendMessage,
            Error::InvalidMessage => KeyExportError::InvalidMessage,
        }
    }
}

/// Helper method to combine the secret shares into the private key
/// You can use all the shares or the threshold number of shares to
/// combine the private key
///
/// # Arguments
///
/// * `x_i_list` - List of (x_i, rank_i) pairs
///
/// * `s_i_list` - List of s_i (secret shares of the parties)
///
pub fn combine_shares(
    x_i_list: &[(NonZeroScalar, usize)],
    s_i_list: &[Scalar],
    public_key: &ProjectivePoint,
) -> Option<Scalar> {
    if s_i_list.len() != x_i_list.len() {
        return None;
    }

    let is_lagrange = x_i_list.iter().all(|&(_, rank)| rank == 0);

    let s = if is_lagrange {
        get_lagrange_coeff_list(x_i_list, |(x, _)| x)
            .zip(s_i_list)
            .map(|(c, s_i)| c * s_i)
            .sum()
    } else {
        birkhoff_coeffs(x_i_list)
            .into_iter()
            .zip(s_i_list)
            .map(|(c, s_i)| c * s_i)
            .sum()
    };

    let calculated_public_key = ProjectivePoint::GENERATOR * s;

    (public_key == &calculated_public_key).then_some(s)
}

/// Export keyshare.
///
/// Encrypt `s_i` and send as a P2P message to an a party combining keyshares.
///
pub fn export_keyshare<S, R>(mut rng: R, setup: &S) -> Option<Vec<u8>>
where
    S: KeyExporterSetupMessage<PublicKey, Keyshare>,
    R: RngCore + CryptoRng,
{
    let mut scheme = crate::proto::Scheme::new(&mut rng);

    scheme
        .receiver_public_key(0, setup.receiver_public_key().as_bytes())
        .ok()?;

    let pub_key = scheme.public_key();

    let mut msg = EncryptedMessage::<ScalarBytes>::new_with_ad(
        &setup.msg_id(Some(EXPORTED_KEYSHARE_RECEIVER), KEYSHARE_EXPORT_TAG),
        setup.message_ttl().as_secs() as u32,
        0,
        pub_key.len(),
        1,
        &scheme,
    );

    let (payload, trailer, ad) = msg.payload_with_ad(&scheme);

    payload.copy_from_slice(&setup.keyshare().s_i);
    trailer[0] = setup.keyshare().party_id;
    ad.copy_from_slice(pub_key);

    msg.encrypt(&mut scheme, 0)
}

/// Decrypt share encrypted by `export_keyshare()`
pub fn decrypt_share(
    mut msg: Zeroizing<Vec<u8>>,
    enc_key: &ReusableSecret,
) -> Option<(Scalar, u8)> {
    let mut scheme = crate::proto::Scheme::from_secret(enc_key.clone());

    let enc_pub_key = msg
        .get(MESSAGE_HEADER_SIZE..)
        .and_then(|msg| msg.get(0..32))?;

    scheme.receiver_public_key(0, enc_pub_key).ok()?;

    let (s_i, pid, _) = EncryptedMessage::<[u8; 32]>::decrypt_with_ad(&mut msg, 32, 1, &scheme, 0)?;

    let party_id = pid[0];

    let s_i = decode_scalar(s_i)?;

    Some((s_i, party_id))
}

/// Receive exported key shares, combine them and calculate private key.
pub async fn receive_keyshares<S, R>(setup: S, relay: R) -> Result<Scalar, KeyExportError>
where
    S: KeyExportReceiverSetupMessage<ReusableSecret>,
    R: Relay,
{
    let share = setup.keyshare();

    let mut relay = FilteredMsgRelay::new(relay);

    relay.ask_messages(&setup, ABORT_MESSAGE_TAG, false).await?;

    relay
        .ask_messages(&setup, KEYSHARE_EXPORT_TAG, true)
        .await?;

    let pk = setup.keyshare().public_key();

    let rank_list = setup.keyshare().rank_list();
    let x_i_list = setup.keyshare().x_i_list();

    let mut x_i_list_2 = Pairs::new_with_item(
        share.party_id as usize,
        (
            x_i_list[share.party_id as usize],
            rank_list[share.party_id as usize] as usize,
        ),
    );
    let mut s_i_list = Pairs::new_with_item(share.party_id as usize, share.s_i());

    let mut round = Round::new(
        setup.total_participants() - 1,
        KEYSHARE_EXPORT_TAG,
        &mut relay,
    );

    while let Some((msg, party_idx, is_abort)) = round.recv().await? {
        if is_abort {
            check_abort(&setup, &msg, party_idx, KeyExportError::AbortProtocol)?;
            round.put_back(&msg, ABORT_MESSAGE_TAG, party_idx);
            continue;
        }

        let msg = Zeroizing::new(msg);

        let (s_i, party_id) = decrypt_share(msg, setup.receiver_private_key())
            .ok_or(KeyExportError::InvalidMessage)?;

        let x_j = x_i_list
            .get(party_id as usize)
            .ok_or(KeyExportError::InvalidMessage)?;
        let rank_j = rank_list
            .get(party_id as usize)
            .ok_or(KeyExportError::InvalidMessage)?;
        x_i_list_2.push(party_id as usize, (*x_j, *rank_j as usize));
        s_i_list.push(party_id as usize, s_i);
    }

    let private_key = combine_shares(&x_i_list_2.remove_ids(), &s_i_list.remove_ids(), &pk)
        .ok_or(KeyExportError::PublicKeyMismatch)?;

    Ok(private_key)
}

/// Generate message receiver map.
///
/// Call the passed closure for each pair (msg_id, receiver)
///
pub fn message_receivers<S, F>(setup: &S, mut msg_receiver: F)
where
    S: ProtocolParticipant,
    F: FnMut(MsgId, &S::MessageVerifier),
{
    setup.all_other_parties().for_each(|p| {
        let vk = setup.verifier(p);

        msg_receiver(setup.msg_id(None, ABORT_MESSAGE_TAG), vk);
        msg_receiver(setup.msg_id(Some(p), KEYSHARE_EXPORT_TAG), vk);
    })
}

#[cfg(test)]
mod tests {
    use k256::{NonZeroScalar, ProjectivePoint};
    use rand::seq::SliceRandom;
    use x25519_dalek::ReusableSecret;

    use sl_mpc_mate::{coord::SimpleMessageRelay, message::InstanceId};

    use crate::{
        key_import::ecdsa_secret_shares,
        keygen::utils::gen_keyshares,
        setup::{
            key_export::{exporter::KeyExporter, receiver::KeyExportReceiver},
            NoSigningKey, NoVerifyingKey,
        },
    };

    use super::{combine_shares, export_keyshare, receive_keyshares, PublicKey};

    #[test]
    fn test_combine() {
        const T: u8 = 5;
        const N: usize = 9;

        let mut rng = rand::thread_rng();

        let private_key = NonZeroScalar::random(&mut rng);
        let public_key = ProjectivePoint::GENERATOR * *private_key;

        let root_chain_code = [1u8; 32];

        let shares =
            ecdsa_secret_shares(T, vec![0; N], &private_key, root_chain_code, None, &mut rng);

        let s_i_list = shares.iter().map(|s| s.s_i.unwrap()).collect::<Vec<_>>();

        let x_i_list = shares[0]
            .x_i_list
            .clone()
            .unwrap()
            .into_iter()
            .map(|x_i| (x_i, 0))
            .collect::<Vec<_>>();

        for t in T as usize..=N {
            let recovered_private_key =
                combine_shares(&x_i_list[..t], &s_i_list[..t], &public_key).unwrap();

            assert_eq!(recovered_private_key, *private_key);
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn parties() {
        let mut rng = rand::thread_rng();

        const T: u8 = 3;
        const N: u8 = 5;

        let mut shares = gen_keyshares(T, N, None).await;
        let pk = shares[0].public_key();

        let inst = rand::random();

        let vk: Vec<NoVerifyingKey> = (0..N as usize).map(NoVerifyingKey::new).collect();

        for _ in 0..10 {
            // let's try 10 different permutation of shares.

            // We should be able to export key using any subset of
            //        t in (T..=N) of keyshares
            shares.shuffle(&mut rng);

            for t in T..=N {
                let enc_key = ReusableSecret::random_from_rng(&mut rng);
                let enc_pub_key = PublicKey::from(&enc_key);

                let msgs = (1..t)
                    .map(|party_id| {
                        let setup = KeyExporter::new(
                            InstanceId::new(inst),
                            NoSigningKey,
                            party_id as _,
                            vk[..t as usize].to_vec(),
                            shares[party_id as usize].clone(),
                            enc_pub_key,
                        );

                        export_keyshare(&mut rng, &setup).unwrap()
                    })
                    .collect::<Vec<_>>();

                let relay = SimpleMessageRelay::new();

                for msg in msgs {
                    relay.send(msg);
                }

                let recv = <KeyExportReceiver>::new(
                    InstanceId::new(inst),
                    NoSigningKey,
                    0,
                    vk[..t as usize].to_vec(),
                    shares[0].clone(),
                    enc_key,
                );

                let sk = receive_keyshares(recv, relay.connect()).await.unwrap();

                assert_eq!(ProjectivePoint::GENERATOR * sk, pk);
            }
        }
    }
}
