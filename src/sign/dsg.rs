//! Distributed sign generation protocol.

use std::collections::HashMap;

use k256::{
    ecdsa::Signature,
    elliptic_curve::{
        group::GroupEncoding, ops::Reduce, point::AffineCoordinates, subtle::ConstantTimeEq,
        PrimeField,
    },
    sha2::{Digest, Sha256},
    ProjectivePoint, Scalar, Secp256k1, U256,
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

use sl_mpc_mate::{coord::*, math::birkhoff_coeffs, message::*, HashBytes, SessionId};

use sl_oblivious::soft_spoken_mod::Round1Output;

use crate::{
    keygen::{get_idx_from_id, messages::Keyshare},
    setup::sign::ValidatedSetup,
    sign::{
        messages::{SignMsg1, SignMsg3, SignMsg4},
        pairwise_mta::{PairwiseMtaRec, PairwiseMtaSender},
    },
    utils::{parse_raw_sign, verify_final_signature},
    BadPartyIndex, Seed,
};

use super::SignError;

const DSG_MSG_R1: MessageTag = MessageTag::tag(1);
const DSG_MSG_R2: MessageTag = MessageTag::tag(2);
const DSG_MSG_R3: MessageTag = MessageTag::tag(3);
const DSG_MSG_R4: MessageTag = MessageTag::tag(4);

fn find_pair<K: Eq, T>(pairs: &[(K, T)], party_id: K) -> Result<&T, BadPartyIndex> {
    pairs
        .iter()
        .find(|(p, _)| *p == party_id)
        .map(|(_, v)| v)
        .ok_or(BadPartyIndex)
}

fn pop_pair<K: Eq, T>(pairs: &mut Vec<(K, T)>, party_id: K) -> Result<T, BadPartyIndex> {
    let pos = pairs
        .iter()
        .position(|(p, _)| *p == party_id)
        .ok_or(BadPartyIndex)?;

    Ok(pairs.remove(pos).1)
}

fn pop_tag<T>(msg_map: &mut Vec<(MsgId, T)>, id: &MsgId) -> Option<T> {
    if let Some(idx) = msg_map.iter().position(|prev| prev.0.eq(id)) {
        let (_, tag) = msg_map.swap_remove(idx);
        return Some(tag);
    }

    None
}

async fn request_messages<R: Relay>(
    setup: &ValidatedSetup,
    tag: MessageTag,
    relay: &mut R,
    p2p: bool,
) -> Result<Vec<(MsgId, usize)>, InvalidMessage> {
    let mut tags = vec![];
    let me = if p2p { Some(setup.party_idx()) } else { None };

    for (p, vk) in setup.other_parties_iter() {
        // A message from party VK (p) to me.
        let msg_id = setup.msg_id_from(vk, me, tag);

        let msg = AskMsg::allocate(&msg_id, setup.ttl().as_secs() as _);

        tags.push((msg_id, p));

        relay.feed(msg).await?;
    }

    relay.flush().await?;

    Ok(tags)
}

fn decode_signed_message<T: bincode::Decode>(
    tags: &mut Vec<(MsgId, usize)>,
    mut msg: Vec<u8>,
    setup: &ValidatedSetup,
) -> Result<(T, usize), InvalidMessage> {
    let msg = Message::from_buffer(&mut msg)?;
    let mid = msg.id();

    let party_id = pop_tag(tags, &mid).ok_or(InvalidMessage::RecvError)? as _;

    let msg = msg.verify_and_decode(setup.party_verifying_key(party_id).unwrap())?;

    Ok((msg, party_id))
}

fn decode_encrypted_message<T: bincode::Decode>(
    tags: &mut Vec<(MsgId, usize)>,
    mut msg: Vec<u8>,
    secret: &ReusableSecret,
    enc_pub_keys: &[(usize, PublicKey)],
) -> Result<(T, usize), InvalidMessage> {
    let mut msg = Message::from_buffer(&mut msg)?;
    let mid = msg.id();

    let party_id = pop_tag(tags, &mid).ok_or(InvalidMessage::RecvError)? as _;

    let msg = msg.decrypt_and_decode(
        MESSAGE_HEADER_SIZE,
        secret,
        find_pair(enc_pub_keys, party_id).map_err(|_| InvalidMessage::RecvError)?,
    )?;

    Ok((msg, party_id))
}

/// Result after pre-signature of party_i
#[derive(Clone, bincode::Encode, bincode::Decode)]
pub struct PreSignResult {
    /// final_session_id
    pub final_session_id: Opaque<SessionId>,

    /// public_key
    pub public_key: Opaque<ProjectivePoint, GR>,

    /// s_0 Scalar
    pub s_0: Opaque<Scalar, PF>,

    /// s_1 Scalar
    pub s_1: Opaque<Scalar, PF>,

    /// R point
    pub r: Opaque<ProjectivePoint, GR>,

    /// phi_i Scalar
    pub phi_i: Opaque<Scalar, PF>,
}

/// Partial signature of party_i
#[derive(Clone, bincode::Encode, bincode::Decode)]
pub struct PartialSignature {
    /// final_session_id
    pub final_session_id: Opaque<SessionId>,

    /// public_key
    pub public_key: Opaque<ProjectivePoint, GR>,

    /// 32 bytes message_hash
    pub message_hash: Opaque<HashBytes>,

    /// s_0 Scalar
    pub s_0: Opaque<Scalar, PF>,

    /// s_1 Scalar
    pub s_1: Opaque<Scalar, PF>,

    /// R point
    pub r: Opaque<ProjectivePoint, GR>,
}

/// Method to create a pre-signature without any message information for the signature
pub async fn pre_signature<R: Relay>(
    setup: &ValidatedSetup,
    seed: Seed,
    relay: &mut R,
) -> Result<PreSignResult, SignError> {
    let mut rng = ChaCha20Rng::from_seed(seed);
    let mut nonce_counter = NonceCounter::new();

    // For DKG part_id == part_idx.
    //
    // For DSG: party_idx is an index of the party in the setup messages.
    //
    // In the first message a party sends its part_id from Keyshare and
    // its encryption public key
    //
    let my_party_id = setup.keyshare().party_id;
    let my_party_idx = setup.party_idx();

    let mut commitments = vec![];
    let mut enc_pub_keys = vec![];

    let session_id: SessionId = SessionId::random(&mut rng);
    let phi_i: Scalar = Scalar::generate_biased(&mut rng);
    let k_i: Scalar = Scalar::generate_biased(&mut rng);
    let blind_factor: [u8; 32] = rng.gen();

    let enc_keys = ReusableSecret::random_from_rng(&mut rng);

    let big_r_i = ProjectivePoint::GENERATOR * k_i;
    let commitment_r_i = hash_commitment_r_i(&session_id, &big_r_i, &blind_factor);

    commitments.push((setup.party_idx(), (session_id, commitment_r_i)));

    relay
        .send(Builder::<Signed>::encode(
            &setup.msg_id(None, DSG_MSG_R1),
            setup.ttl(),
            setup.signing_key(),
            &SignMsg1 {
                session_id: Opaque::from(session_id),
                commitment_r_i: Opaque::from(commitment_r_i),
                party_id: setup.keyshare().party_id,
                enc_pk: Opaque::from(PublicKey::from(&enc_keys).to_bytes()),
            },
        )?)
        .await?;

    // vector of pairs (party_idx, party_id)
    let mut party_idx_to_id_map = vec![(my_party_idx, my_party_id)];

    let mut js = request_messages(setup, DSG_MSG_R1, relay, false).await?;
    while !js.is_empty() {
        let msg = relay.next().await.ok_or(SignError::MissingMessage)?;
        let (msg, party_idx) = decode_signed_message::<SignMsg1>(&mut js, msg, setup)?;

        party_idx_to_id_map.push((party_idx, msg.party_id));
        commitments.push((party_idx, (*msg.session_id, *msg.commitment_r_i)));
        enc_pub_keys.push((party_idx, PublicKey::from(*msg.enc_pk)));
    }

    party_idx_to_id_map.sort_by_key(|(_, pid)| *pid);

    let find_party_id = |idx: usize| {
        party_idx_to_id_map
            .iter()
            .find(|(i, _)| *i == idx)
            .map(|(_, p)| *p)
    };

    commitments.sort_by_key(|(idx, _)| *idx);

    let final_session_id = SessionId::new(
        commitments
            .iter()
            .fold(Sha256::new(), |hash, (_, (sid, _))| hash.chain_update(sid))
            .finalize()
            .into(),
    );

    let mut to_send = vec![];

    let mut mta_receivers = setup
        .other_parties_iter()
        .map(|(party_idx, _vk)| {
            let sender_id = find_party_id(party_idx).unwrap();

            let sid = mta_session_id(&final_session_id, sender_id, my_party_id);

            let sender_ot_results =
                &setup.keyshare().seed_ot_senders[get_idx_from_id(my_party_id, sender_id) as usize];

            let mta_receiver = PairwiseMtaRec::new(sid, sender_ot_results, &mut rng);
            
            let xi_i_j = Scalar::generate_biased(&mut rng);
            let (mta_receiver, mta_msg_1) = mta_receiver.process(&xi_i_j);

            to_send.push(Builder::<Encrypted>::encode(
                &setup.msg_id(Some(party_idx), DSG_MSG_R2),
                setup.ttl(),
                &enc_keys,
                find_pair(&enc_pub_keys, party_idx)?,
                &mta_msg_1,
                nonce_counter.next_nonce(),
            )?);

            Ok((party_idx as u8, (mta_receiver, xi_i_j)))
        })
        .collect::<Result<Vec<_>, SignError>>()?;

    for msg in to_send.into_iter() {
        relay.send(msg).await?;
    }

    let mut mta_senders = setup
        .other_parties_iter()
        .map(|(party_idx, _vk)| {
            let receiver_id = find_party_id(party_idx).unwrap();

            let sid = mta_session_id(&final_session_id, my_party_id, receiver_id);

            let seed_ot_results = &setup.keyshare().seed_ot_receivers
                [get_idx_from_id(my_party_id, receiver_id) as usize];

            let sender = PairwiseMtaSender::new(sid, seed_ot_results, &mut rng);

            Ok((party_idx as u8, sender))
        })
        .collect::<Result<Vec<_>, SignError>>()?;

    let digest_i = {
        let mut h = Sha256::new();
        for (key, (sid_i, commitment_i)) in &commitments {
            h.update((*key as u32).to_be_bytes());
            h.update(sid_i);
            h.update(commitment_i);
        }

        HashBytes::new(h.finalize().into())
    };

    let mu_i = get_mu_i(setup.keyshare(), &party_idx_to_id_map, digest_i);

    let coeff = if setup.keyshare().rank_list.iter().all(|&r| r == 0) {
        get_lagrange_coeff(setup.keyshare(), &party_idx_to_id_map)
    } else {
        let betta_coeffs = get_birkhoff_coefficients(setup.keyshare(), &party_idx_to_id_map);

        *betta_coeffs
            .get(&(my_party_id as usize))
            .expect("betta_i not found")
    };

    let (additive_offset, derived_public_key) = setup
        .keyshare()
        .derive_with_offset(setup.chain_path())
        .unwrap();
    let threshold_inv = Scalar::from(setup.keyshare().threshold as u32)
        .invert()
        .unwrap();
    let additive_offset = additive_offset * threshold_inv;

    let x_i = coeff * *setup.keyshare().s_i + additive_offset + mu_i;
    let big_x_i = ProjectivePoint::GENERATOR * x_i;

    let mut sender_additive_shares = vec![];

    let mut js = request_messages(setup, DSG_MSG_R2, relay, true).await?;
    while !js.is_empty() {
        let msg = relay.next().await.ok_or(SignError::MissingMessage)?;
        let (msg1, party_idx) =
            decode_encrypted_message::<Round1Output>(&mut js, msg, &enc_keys, &enc_pub_keys)?;

        let mta_sender = pop_pair(&mut mta_senders, party_idx as u8)?;

        let (additive_shares, mta_msg2) = mta_sender.process((x_i, k_i, msg1));

        let gamma0 = ProjectivePoint::GENERATOR * additive_shares[0];
        let gamma1 = ProjectivePoint::GENERATOR * additive_shares[1];
        let (_mta_receiver, xi_i_j) = find_pair(&mut mta_receivers, party_idx as u8)?;
        let psi = phi_i - xi_i_j;

        let msg3 = SignMsg3 {
            session_id: Opaque::from(final_session_id),
            mta_msg2,
            digest_i: Opaque::from(digest_i),
            big_x_i: Opaque::from(big_x_i),
            big_r_i: Opaque::from(big_r_i),
            blind_factor: Opaque::from(blind_factor),
            gamma0: Opaque::from(gamma0),
            gamma1: Opaque::from(gamma1),
            psi: Opaque::from(psi)
        };

        relay
            .send(Builder::<Encrypted>::encode(
                &setup.msg_id(Some(party_idx), DSG_MSG_R3),
                setup.ttl(),
                &enc_keys,
                find_pair(&enc_pub_keys, party_idx)?,
                &msg3,
                nonce_counter.next_nonce(),
            )?)
            .await?;

        sender_additive_shares.push(additive_shares);
    }

    let mut big_r_star = ProjectivePoint::IDENTITY;
    let mut sum_x_j = ProjectivePoint::IDENTITY;
    let mut sum_psi_j_i = Scalar::ZERO;

    let mut receiver_additive_shares = vec![];

    let mut js = request_messages(setup, DSG_MSG_R3, relay, true).await?;
    while !js.is_empty() {
        let msg = relay.next().await.ok_or(SignError::MissingMessage)?;
        let (msg3, party_idx) =
            decode_encrypted_message::<SignMsg3>(&mut js, msg, &enc_keys, &enc_pub_keys)?;

        let (mta_receiver, xi_i_j) = pop_pair(&mut mta_receivers, party_idx as u8)?;

        let receiver_additive_shares_i = mta_receiver
            .process(msg3.mta_msg2)
            .map_err(SignError::MtaError)?;

        receiver_additive_shares.push(receiver_additive_shares_i);

        let (sid_i, commitment) = find_pair(&commitments, party_idx)?;

        if !verify_commitment_r_i(sid_i, &msg3.big_r_i, &msg3.blind_factor, commitment) {
            return Err(SignError::InvalidCommitment);
        }

        if digest_i.ct_eq(&msg3.digest_i).unwrap_u8() != 1 {
            return Err(SignError::InvalidDigest);
        }

        let big_r_j = &*msg3.big_r_i;
        let big_x_j = &*msg3.big_x_i;

        big_r_star += big_r_j;
        sum_x_j += big_x_j;
        sum_psi_j_i += &*msg3.psi;

        let cond1 = (big_r_j * &xi_i_j) == (ProjectivePoint::GENERATOR * &receiver_additive_shares_i[1] + &*msg3.gamma1);
        if !cond1 {
            return Err(SignError::FailedCheck(
                "Consistency check 1 failed",
            ));
        }

        let cond2 = (big_x_j * &xi_i_j) == (ProjectivePoint::GENERATOR * &receiver_additive_shares_i[0] + &*msg3.gamma0);
        if !cond2 {
            return Err(SignError::FailedCheck(
                "Consistency check 2 failed",
            ));
        }
    }

    // new var
    let big_r = big_r_star + big_r_i;
    sum_x_j += big_x_i;
    // Checks
    if sum_x_j != derived_public_key {
        return Err(SignError::FailedCheck("Consistency check 3 failed"));
    }

    let mut sum0 = Scalar::ZERO;
    let mut sum1 = Scalar::ZERO;

    for i in 0..setup.keyshare().threshold as usize - 1 {
        let sender_shares = &sender_additive_shares[i];
        let receiver_shares = &receiver_additive_shares[i];
        sum0 += sender_shares[0] + receiver_shares[0];
        sum1 += sender_shares[1] + receiver_shares[1];
    }

    let r_point = big_r.to_affine();
    let r_x = Scalar::from_repr(r_point.x()).unwrap();
    //        let recid = r_point.y_is_odd().unwrap_u8();
    let phi_plus_sum_psi = &phi_i + &sum_psi_j_i;
    let s_0 = r_x * (x_i * &phi_plus_sum_psi + sum0);
    let s_1 = k_i * phi_plus_sum_psi + sum1;

    let pre_sign_result = PreSignResult {
        final_session_id: Opaque::from(final_session_id),
        public_key: Opaque::from(derived_public_key),
        s_0: Opaque::from(s_0),
        s_1: Opaque::from(s_1),
        phi_i: Opaque::from(phi_i),
        r: Opaque::from(big_r),
    };

    Ok(pre_sign_result)
}

/// Locally create a partial signature from pre-signature and msg_hash
fn create_partial_signature(
    pre_sign_result: PreSignResult,
    msg_hash: HashBytes,
) -> PartialSignature {
    let m = Scalar::reduce(U256::from_be_slice(&msg_hash));
    let s_0 = m * pre_sign_result.phi_i.0 + pre_sign_result.s_0.0;

    PartialSignature {
        final_session_id: pre_sign_result.final_session_id,
        public_key: pre_sign_result.public_key,
        message_hash: Opaque::from(msg_hash),
        s_0: Opaque::from(s_0),
        s_1: pre_sign_result.s_1,
        r: pre_sign_result.r,
    }
}

/// Locally combine list of t partial signatures into a final signature
pub fn combine_partial_signature(
    partial_signatures: Vec<PartialSignature>,
    t: usize,
) -> Result<Signature, SignError> {
    if partial_signatures.len() != t {
        return Err(SignError::FailedCheck(
            "Invalid number of partial signatures",
        ));
    }

    let final_session_id = partial_signatures[0].final_session_id;
    let public_key = partial_signatures[0].public_key;
    let message_hash = partial_signatures[0].message_hash;
    let r = partial_signatures[0].r;

    let mut sum_s_0 = Scalar::ZERO;
    let mut sum_s_1 = Scalar::ZERO;
    for partial_sign in partial_signatures.iter() {
        let cond = (partial_sign.final_session_id != final_session_id)
            || (partial_sign.public_key != public_key)
            || (partial_sign.r != r)
            || (partial_sign.message_hash != message_hash);
        if cond {
            return Err(SignError::FailedCheck("Invalid list of partial signatures"));
        }
        sum_s_0 += partial_sign.s_0.0;
        sum_s_1 += partial_sign.s_1.0;
    }

    let r = r.0.to_affine().x();
    let sum_s_1_inv = sum_s_1.invert().unwrap();
    let sig = sum_s_0 * sum_s_1_inv;

    let sign = parse_raw_sign(&r, &sig.to_bytes())?;

    verify_final_signature(&message_hash.0, &sign, &public_key.0.to_bytes())?;

    Ok(sign)
}

///
pub async fn run<R: Relay>(
    setup: ValidatedSetup,
    seed: Seed,
    mut relay: R,
) -> Result<Signature, SignError> {
    let pre_signature_result = pre_signature(&setup, seed, &mut relay).await?;
    let final_session_id = pre_signature_result.final_session_id;
    let public_key = pre_signature_result.public_key;
    let r: Opaque<ProjectivePoint, GR> = pre_signature_result.r;

    let msg_hash = setup.hash();
    let partial_signature = create_partial_signature(pre_signature_result, msg_hash);

    relay
        .send(Builder::<Signed>::encode(
            &setup.msg_id(None, DSG_MSG_R4),
            setup.ttl(),
            setup.signing_key(),
            &SignMsg4 {
                session_id: partial_signature.final_session_id,
                s_0: partial_signature.s_0,
                s_1: partial_signature.s_1,
            },
        )?)
        .await?;

    let mut partial_signatures: Vec<PartialSignature> = Vec::new();
    partial_signatures.push(partial_signature);

    let mut js = request_messages(&setup, DSG_MSG_R4, &mut relay, false).await?;
    while !js.is_empty() {
        let msg = relay.next().await.ok_or(SignError::MissingMessage)?;
        let (msg, _party_idx) = decode_signed_message::<SignMsg4>(&mut js, msg, &setup)?;
        let party_j_partial_sign = PartialSignature {
            final_session_id,
            public_key,
            message_hash: Opaque::from(msg_hash),
            s_0: msg.s_0,
            s_1: msg.s_1,
            r,
        };
        partial_signatures.push(party_j_partial_sign);
    }

    let t = setup.keyshare().threshold;
    combine_partial_signature(partial_signatures, t as usize)
}

fn hash_commitment_r_i(
    session_id: &SessionId,
    big_r_i: &ProjectivePoint,
    blind_factor: &[u8; 32],
) -> HashBytes {
    let mut hasher = Sha256::new();
    hasher.update(session_id.as_ref());
    hasher.update(big_r_i.to_bytes());
    hasher.update(blind_factor);
    HashBytes::new(hasher.finalize().into())
}

fn get_mu_i(keyshare: &Keyshare, party_id_list: &[(usize, u8)], sig_id: HashBytes) -> Scalar {
    let mut p_0_list = Vec::new();
    let mut p_1_list = Vec::new();

    for (_, party_id) in party_id_list {
        if party_id < &keyshare.party_id {
            p_0_list.push(*party_id);
        }
        if party_id > &keyshare.party_id {
            p_1_list.push(*party_id);
        }
    }

    let mut sum_p_0 = Scalar::ZERO;
    for p_0_party in &p_0_list {
        let seed_j_i = keyshare.rec_seed_list[*p_0_party as usize];
        let mut hasher = Sha256::new();
        hasher.update(seed_j_i);
        hasher.update(sig_id);
        let value = Scalar::reduce(U256::from_be_slice(&hasher.finalize()));
        sum_p_0 += value;
    }

    let mut sum_p_1 = Scalar::ZERO;
    for p_1_party in &p_1_list {
        let seed_i_j =
            keyshare.sent_seed_list[*p_1_party as usize - keyshare.party_id as usize - 1];
        let mut hasher = Sha256::new();
        hasher.update(seed_i_j);
        hasher.update(sig_id.as_ref());
        let value = Scalar::reduce(U256::from_be_slice(&hasher.finalize()));
        sum_p_1 += value;
    }

    sum_p_0 - sum_p_1
}

fn get_birkhoff_coefficients(
    keyshare: &Keyshare,
    sign_party_ids: &[(usize, u8)],
) -> HashMap<usize, Scalar> {
    let params = sign_party_ids
        .iter()
        .map(|(_, pid)| {
            (
                *keyshare.x_i_list[*pid as usize],
                keyshare.rank_list[*pid as usize] as usize,
            )
        })
        .collect::<Vec<_>>();

    let betta_vec = birkhoff_coeffs::<Secp256k1>(&params);

    sign_party_ids
        .iter()
        .zip(betta_vec.iter())
        .map(|((_, pid), w_i)| (*pid as usize, *w_i))
        .collect::<HashMap<_, _>>()
}

fn get_lagrange_coeff(keyshare: &Keyshare, sign_party_ids: &[(usize, u8)]) -> Scalar {
    let mut coeff = Scalar::from(1u64);
    let pid = keyshare.party_id;
    let x_i = &*keyshare.x_i_list[pid as usize] as &Scalar;
    for (_, index) in sign_party_ids {
        let x_j = &*keyshare.x_i_list[*index as usize] as &Scalar;
        if x_i.ct_ne(x_j).into() {
            let sub = x_j - x_i;
            coeff *= *x_j * sub.invert().unwrap();
        }
    }
    coeff
}

fn verify_commitment_r_i(
    sid: &SessionId,
    big_r_i: &ProjectivePoint,
    blind_factor: &[u8; 32],
    commitment: &HashBytes,
) -> bool {
    let compare_commitment = hash_commitment_r_i(sid, big_r_i, blind_factor);

    commitment.ct_eq(&compare_commitment).into()
}

fn mta_session_id(final_session_id: &SessionId, sender_id: u8, receiver_id: u8) -> SessionId {
    let mut h = Sha256::new();
    h.update(b"SL-DKLS-PAIRWISE-MTA");
    h.update(final_session_id);
    h.update(b"sender");
    h.update([sender_id]);
    h.update(b"receiver");
    h.update([receiver_id]);

    SessionId::new(h.finalize().into())
}

#[cfg(test)]
mod tests {
    use tokio::task::JoinSet;

    use super::*;
    use k256::AffinePoint;
    use std::array;

    use sl_mpc_mate::coord::SimpleMessageRelay;

    use crate::keygen::gen_keyshares;
    use crate::setup::{sign::*, SETUP_MESSAGE_TAG};
    use derivation_path::DerivationPath;

    fn setup_dsg(
        pk: &AffinePoint,
        shares: &[Keyshare],
        chain_path: &DerivationPath,
    ) -> Vec<(ValidatedSetup, Seed)> {
        let mut rng = rand::thread_rng();

        let instance = InstanceId::from(rng.gen::<[u8; 32]>());

        // signing key to sing the setup message
        let setup_sk = SigningKey::from_bytes(&rng.gen());
        let setup_vk = setup_sk.verifying_key();
        let setup_pk = setup_vk.to_bytes();

        let setup_msg_id = MsgId::new(&instance, &setup_pk, None, SETUP_MESSAGE_TAG);

        const T: usize = 2;

        // a signing key for each party.
        let party_sk: [SigningKey; T] = array::from_fn(|_| SigningKey::from_bytes(&rng.gen()));

        let mut setup = (0..T)
            .fold(
                SetupBuilder::new(pk).chain_path(Some(chain_path)),
                |setup, p| {
                    let vk = party_sk[p].verifying_key();
                    setup.add_party(vk)
                },
            )
            .with_hash(HashBytes::new([1; 32]))
            .build(&setup_msg_id, 100, &setup_sk)
            .unwrap();

        party_sk
            .into_iter()
            .enumerate()
            .map(|(idx, party_sk)| {
                ValidatedSetup::decode(&mut setup, &instance, &setup_vk, party_sk, |_, _| {
                    Some(shares[idx].clone())
                })
                .unwrap()
            })
            .map(|setup| (setup, rng.gen()))
            .collect::<Vec<_>>()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn s2x2() {
        let coord = SimpleMessageRelay::new();

        let shares = gen_keyshares(2, 2, Some(&[0, 0])).await;

        let pk = shares[0].public_key.to_affine();
        let chain_path = "m".parse().unwrap();

        let mut parties = JoinSet::new();
        for (setup, seed) in setup_dsg(&pk, &shares, &chain_path).into_iter() {
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
    async fn s1() {
        let coord = SimpleMessageRelay::new();

        let shares = gen_keyshares(2, 3, Some(&[0, 1, 1])).await;

        let pk = shares[0].public_key.to_affine();
        let chain_path = "m".parse().unwrap();

        let mut parties = JoinSet::new();
        for (setup, seed) in setup_dsg(&pk, &shares, &chain_path).into_iter() {
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
}
