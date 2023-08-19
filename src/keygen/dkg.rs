#![allow(unused_imports, dead_code)]

///! Distributed key generation protocol.
///
use digest::{generic_array::GenericArray, Digest};
use k256::{
    elliptic_curve::{group::GroupEncoding, subtle::ConstantTimeEq, PrimeField},
    FieldBytes, NonZeroScalar, ProjectivePoint, Scalar, Secp256k1,
};
use merlin::Transcript;
use rand::prelude::*;
use rand_chacha::ChaCha20Rng;
use rayon::prelude::*;
use sha2::Sha256;

use sl_oblivious::{
    soft_spoken::{build_pprf, eval_pprf, PPRFOutput, SenderOTSeed},
    soft_spoken_mod::SOFT_SPOKEN_K,
    utils::TranscriptProtocol,
    vsot::{
        InitRec, RecR1, RecR2, SendR1, SendR2, VSOTError, VSOTMsg1, VSOTMsg5, VSOTReceiver,
        VSOTSender,
    },
    zkproofs::DLogProof,
};

use sl_mpc_mate::{
    math::{feldman_verify, polynomial_coeff_multipliers, GroupPolynomial, Polynomial},
    message::*,
    nacl::{encrypt_data, sign_message, verify_signature, EncryptedData, HasSignature},
    state::{self, WaitQueue},
    traits::{HasFromParty, PersistentObject, Round},
    HashBytes, SessionId,
};

use crate::{
    keygen::{
        // check_secret_recovery,
        constants::*,
        // get_idx_from_id,
        messages::{
            KeyGenCompleteMsg, KeygenMsg1, KeygenMsg2, KeygenMsg3, KeygenMsg4, KeygenMsg5,
            KeygenMsg6, Keyshare,
        },
        types::KeygenParams,
        HasVsotMsg,
        KeygenError,
        PartyPublicKeys,
    },
    setup::keygen::ValidatedSetup,
    utils::get_hash,
};

/// Seed for our RNG
pub type Seed = <ChaCha20Rng as SeedableRng>::Seed;

type Pairs<T> = Vec<(u8, T)>;

/// Keygen logic for a single party
pub struct KeygenParty<T> {
    params: KeygenParams,
    state: T,
}

/// State of a keygen party after receiving public keys of all parties and generating the first message.
pub struct R1 {
    wait_queue: WaitQueue<u8>,
    big_f_i_vec: GroupPolynomial<Secp256k1>,

    commitment_list: Pairs<HashBytes>,
    x_i_list: Pairs<NonZeroScalar>,
    sid_i_list: Pairs<SessionId>,
    enc_pub_key: Pairs<PublicKey>,
}

/// State of a keygen party after processing the first message.
pub struct R2 {
    wait_queue: WaitQueue<(u8, bool)>,
    // big_f_i_vec: GroupPolynomial<Secp256k1>,
    big_f_i_vecs: Pairs<GroupPolynomial<Secp256k1>>,

    final_session_id: SessionId,
    vsot_receivers: Pairs<VSOTReceiver<InitRec>>,
    vsot_senders: Pairs<VSOTSender<SendR1>>,

    vsot_next_receivers: Pairs<VSOTReceiver<RecR1>>,

    commitment_list: Pairs<HashBytes>,
    x_i_list: Pairs<NonZeroScalar>,
    sid_i_list: Pairs<SessionId>,
    enc_pub_key: Pairs<PublicKey>,
}

/// State of a keygen party after processing the second message.
pub struct R3 {
    wait_queue: WaitQueue<u8>,
    final_session_id: SessionId,
    vsot_receivers: Pairs<VSOTReceiver<RecR1>>,
    vsot_senders: Pairs<VSOTSender<SendR1>>,
    x_i_list: Pairs<NonZeroScalar>,
    big_f_vec: GroupPolynomial<Secp256k1>,
    big_f_i_vecs: Pairs<GroupPolynomial<Secp256k1>>,
    enc_pub_key: Pairs<PublicKey>,
}

/// State of a keygen party after processing the third message.
pub struct R4 {
    wait_queue: WaitQueue<u8>,

    final_session_id: SessionId,
    vsot_receivers: Vec<VSOTReceiver<RecR1>>,
    vsot_senders: Vec<VSOTSender<SendR2>>,
    x_i_list: Vec<NonZeroScalar>,
    s_i: Scalar,
    public_key: ProjectivePoint,
    big_f_vec: GroupPolynomial<Secp256k1>,
}

/// State of a keygen party after processing the fourth message.
pub struct R5 {
    wait_queue: WaitQueue<u8>,

    final_session_id: SessionId,
    vsot_receivers: Vec<VSOTReceiver<RecR2>>,
    vsot_senders: Vec<VSOTSender<SendR2>>,
    x_i_list: Vec<NonZeroScalar>,
    s_i: Scalar,
    public_key: ProjectivePoint,
    big_s_list: Vec<ProjectivePoint>,
}

/// State of a keygen party after processing the fifth message.
pub struct R6 {
    wait_queue: WaitQueue<u8>,

    final_session_id: SessionId,
    vsot_receivers: Vec<VSOTReceiver<RecR2>>,
    seed_ot_senders: Vec<SenderOTSeed>,
    x_i_list: Vec<NonZeroScalar>,
    s_i: Scalar,
    public_key: ProjectivePoint,
    big_s_list: Vec<ProjectivePoint>,
    sent_seed_list: Vec<[u8; 32]>,
}

fn find_pair<T>(pairs: &[(u8, T)], party_id: u8) -> Result<&T, KeygenError> {
    pairs
        .iter()
        .find(|(p, _)| *p == party_id)
        .map(|(_, v)| v)
        .ok_or(KeygenError::InvalidParty(party_id))
}

fn pop_pair<T>(pairs: &mut Pairs<T>, party_id: u8) -> Result<T, KeygenError> {
    let pos = pairs
        .iter()
        .position(|(p, _)| *p == party_id)
        .ok_or(KeygenError::InvalidParty(party_id))?;

    Ok(pairs.remove(pos).1)
}

impl KeygenParty<R1> {
    /// Create a new keygen party.
    pub fn new(setup: ValidatedSetup, env: &mut dyn state::Env, seed: Seed) -> Self {
        let mut rng = ChaCha20Rng::from_seed(seed);

        let t = setup.threshold();
        let my_party_id = setup.party_id();

        let session_id = SessionId::new(rng.gen());
        let r_i = rng.gen();
        let polynomial = Polynomial::random(&mut rng, t as usize - 1);
        let x_i = NonZeroScalar::random(&mut rng);

        let enc_keys = ReusableSecret::random_from_rng(&mut rng);

        let params = KeygenParams {
            rng,
            encryption_keypair: enc_keys,
            r_i,
            polynomial,
            setup,
        };

        let mut wait_queue = WaitQueue::<u8>::new();

        params.setup.other_parties_iter().for_each(|(p, pk)| {
            let msg_id = MsgId::new(params.setup.instance(), pk.as_bytes(), None, DKG_MSG_R1);
            env.wait(&msg_id, 100);
            wait_queue.wait(&msg_id, p);
        });

        let big_f_i_vec = params.polynomial.commit(); // big_i_vector in dkg.py

        let commitment = hash_commitment(
            &session_id,
            params.setup.party_id() as usize,
            params.setup.party_rank() as usize,
            &x_i,
            &big_f_i_vec,
            &params.r_i,
        );

        let msg1 = KeygenMsg1 {
            session_id: Opaque::from(&session_id),
            commitment: Opaque::from(&commitment),
            x_i: Opaque::from(*x_i),
            enc_pk: Opaque::from(PublicKey::from(&params.encryption_keypair).to_bytes()),
        };

        let msg1_id = MsgId::new(
            params.setup.instance(),
            params.setup.verifying_key().as_bytes(),
            None,
            DKG_MSG_R1,
        );

        let mut msg = Builder::<Signed>::allocate(&msg1_id, 10, &msg1);

        msg.encode(&msg1).unwrap(); // FIXME

        env.publish(
            msg.sign(params.setup.signing_key())
                .expect("missing payload"),
        );

        KeygenParty {
            params,
            state: R1 {
                big_f_i_vec,
                wait_queue,
                commitment_list: vec![(my_party_id, commitment)],
                sid_i_list: vec![(my_party_id, session_id)],
                x_i_list: vec![(my_party_id, x_i)],
                enc_pub_key: vec![],
            },
        }
    }
}

impl state::State for KeygenParty<R1> {
    type Next = KeygenParty<R2>;
    type Error = KeygenError;

    fn process(self, env: &mut dyn state::Env, msg: &mut Message) -> state::StateResult<Self> {
        let Self {
            mut state,
            mut params,
        } = self;

        // make sure that we wait for this message.
        let party_id = state
            .wait_queue
            .remove(&msg.id())
            .ok_or(KeygenError::InvalidMessage)?;

        // We wait for the message, so we were able to create a message
        // id for it that implies that we have corresponding public key
        // could verify signature of the message.
        //
        let reader = msg.verify(
            params
                .setup
                .party_verifying_key(party_id)
                .expect("missing PK for a party"),
        )?;

        // Now, decode message
        let data: KeygenMsg1 =
            MessageReader::borrow_decode(reader).map_err(|_| KeygenError::InvalidMessage)?;

        // So far, so good. Collect decoded data as 4 vector of pairs
        // (part-id, datum)
        state.sid_i_list.push((party_id, **data.session_id));

        state.commitment_list.push((party_id, **data.commitment));

        state
            .x_i_list
            .push((party_id, NonZeroScalar::new(*data.x_i).unwrap())); // FIXME handle unwrap()!

        state
            .enc_pub_key
            .push((party_id, PublicKey::from(*data.enc_pk)));

        // If wait queue is not empty, wait for a next message
        if !state.wait_queue.is_empty() {
            // We wait for more messages. Return an updates state.
            return Ok(state::Output::Loop(KeygenParty { params, state }));
        }

        //
        // Otherwise, process what we got for a while next move to a next round
        //
        let R1 {
            mut sid_i_list,
            commitment_list,
            x_i_list,
            enc_pub_key,
            big_f_i_vec,
            ..
        } = state;

        let mut wait_queue = WaitQueue::<(u8, bool)>::new();

        //
        // Before we begin generation of broadcast Msg2,
        // inform the message relay that we are expecting
        // these messages for the next round.
        //
        params.setup.other_parties_iter().for_each(|(p, vk)| {
            let msg2_id = MsgId::broadcast(params.setup.instance(), vk.as_bytes(), DKG_MSG_R2);

            env.wait(&msg2_id, 100);

            wait_queue.wait(&msg2_id, (p, false));
        });

        //
        // Create a common session ID from pieces od random data that we received
        // from other parties.
        //
        // Sort party's session-id by party id
        sid_i_list.sort_by_key(|(p, _)| *p);

        // TODO: Should parties be initialized with rank_list and x_i_list? Ask Vlad.
        let final_session_id = SessionId::new(
            sid_i_list
                .iter()
                .fold(Sha256::new(), |hash, (_, sid)| hash.chain_update(sid))
                .finalize()
                .into(),
        );

        // Setup transcript for DLog proofs.
        let mut dlog_transcript = Transcript::new_dlog_proof(
            &final_session_id,
            params.setup.party_id() as usize,
            DLOG_PROOF1_LABEL,
            DKG_LABEL,
        );

        let dlog_proofs = params
            .polynomial
            .iter()
            .map(|f_i| {
                DLogProof::prove(
                    f_i,
                    &ProjectivePoint::GENERATOR,
                    &mut dlog_transcript,
                    &mut params.rng,
                )
            })
            .collect::<Vec<_>>();

        let my_party_id = params.setup.party_id();

        let vsot_receivers = params
            .setup
            .other_parties_iter()
            .map(|(p, _)| {
                (
                    p,
                    VSOTReceiver::new(
                        get_vsot_session_id(my_party_id as usize, p as usize, &final_session_id),
                        &mut params.rng,
                    ),
                )
            })
            .collect::<Vec<_>>();

        // Generate message for each other party.

        // let mut wait_queue = WaitQueue::<(u8, bool)>::new();

        let sender_pk = params.setup.signing_key().verifying_key().to_bytes();

        let vsot_senders = params
            .setup
            .other_parties_iter()
            .map(|(p, vk)| {
                let id = MsgId::new(
                    params.setup.instance(),
                    &sender_pk,
                    Some(vk.as_bytes()),
                    DKG_MSG_R2,
                );

                wait_queue.wait(&id, (p, true)); // true for P2P message
                env.wait(&id, 10);

                (p, id)
            })
            .map(|(p, id)| (p, params.rng.gen(), id, find_pair(&enc_pub_key, p).unwrap()))
            //            .par_bridge()
            .map(|(p, seed, msg_id, enc_pk)| {
                let mut rng = ChaCha20Rng::from_seed(seed); // TODO check!!!

                let vsot_session_id =
                    get_vsot_session_id(my_party_id as usize, p as usize, &final_session_id);

                let (sender, msg1) = VSOTSender::new(vsot_session_id, &mut rng);

                let mut enc_msg1 = Builder::<Encrypted>::allocate(&msg_id, 100, &msg1);

                enc_msg1.encode(&msg1)?;

                let enc_msg1 =
                    enc_msg1.encrypt(MESSAGE_HEADER_SIZE, &params.encryption_keypair, enc_pk)?;

                // println!("encrypt {} -> {} {:?}", my_party_id, p, msg_id);

                Ok((p, sender, enc_msg1))
            })
            .collect::<Result<Vec<_>, KeygenError>>()?
            .into_iter()
            .map(|(p, sender, msg)| {
                env.publish(msg);
                (p, sender)
            })
            .collect();

        let msg2 = KeygenMsg2 {
            session_id: Opaque::from(&final_session_id),
            big_f_i_vector: big_f_i_vec.clone(),
            r_i: Opaque::from(&params.r_i),
            dlog_proofs_i: dlog_proofs,
        };

        let msg2_id = MsgId::broadcast(
            params.setup.instance(),
            params.setup.signing_key().verifying_key().as_bytes(),
            DKG_MSG_R2,
        );

        let mut msg = Builder::<Signed>::allocate(&msg2_id, 100, &msg2);

        msg.encode(&msg2)?;

        env.publish(
            msg.sign(params.setup.signing_key())
                .expect("missing payload"),
        );

        // println!("R2 WQ me {} {:?}", my_party_id, wait_queue);

        let next_state = KeygenParty {
            state: R2 {
                wait_queue,
                final_session_id,
                vsot_receivers,
                vsot_next_receivers: vec![],
                vsot_senders,
                big_f_i_vecs: vec![(params.setup.party_id(), big_f_i_vec)],
                commitment_list,
                x_i_list,
                sid_i_list,
                enc_pub_key,
            },
            params,
        };

        Ok(state::Output::Next(next_state))
    }
}

impl state::State for KeygenParty<R2> {
    type Next = KeygenParty<R3>;
    type Error = KeygenError;

    fn process(self, env: &mut dyn state::Env, msg: &mut Message) -> state::StateResult<Self> {
        let Self { mut state, params } = self;

        // make sure that we wait for this message.
        let (party_id, is_p2p) = state
            .wait_queue
            .remove(&msg.id())
            .ok_or(KeygenError::InvalidMessage)?;

        if !is_p2p {
            let msg: KeygenMsg2 = msg.verify_and_borrow_decode(
                params
                    .setup
                    .party_verifying_key(party_id)
                    .expect("missing PK for a party"),
            )?;

            // Verify commitments.
            let rank = params.setup.part_rank(party_id).unwrap();
            let x_i = find_pair(&state.x_i_list, party_id)?;
            let sid = find_pair(&state.sid_i_list, party_id)?;
            let commitment = find_pair(&state.commitment_list, party_id)?;

            let commit_hash = hash_commitment(
                sid,
                party_id as usize,
                rank as usize,
                x_i,
                &msg.big_f_i_vector,
                &msg.r_i,
            );

            bool::from(commit_hash.ct_eq(&commitment))
                .then_some(())
                .ok_or(KeygenError::InvalidCommitmentHash)?;

            // Verify DLog proofs.
            let mut dlog_transcript = Transcript::new_dlog_proof(
                &state.final_session_id,
                party_id as usize,
                DLOG_PROOF1_LABEL,
                DKG_LABEL,
            );

            verfiy_dlog_proofs(
                &msg.dlog_proofs_i,
                msg.big_f_i_vector.points(),
                &mut dlog_transcript,
            )?;

            state.big_f_i_vecs.push((party_id, msg.big_f_i_vector));
        } else {
            // handle P2P message

            let vsot_msg1: VSOTMsg1 = msg.decrypt_and_decode(
                MESSAGE_HEADER_SIZE,
                &params.encryption_keypair,
                find_pair(&state.enc_pub_key, party_id)?,
            )?;

            let rank = params.setup.part_rank(party_id).unwrap();

            let receiver = pop_pair(&mut state.vsot_receivers, party_id)?;

            let (receiver, vsot_msg2) = receiver.process(vsot_msg1)?;

            state.vsot_next_receivers.push((party_id, receiver));

            let x_i = find_pair(&state.x_i_list, party_id)?;
            let d_i = params.polynomial.derivative_at(rank as usize, &x_i);

            let msg3 = KeygenMsg3 {
                vsot_msg2,
                d_i: Opaque::from(d_i),
                session_id: Opaque::from(&state.final_session_id),
                big_f_vec: state.big_f_i_vecs[0].1.clone(), // TODO explain why
            };

            let sender_pk = params.setup.signing_key().verifying_key().to_bytes();
            let vk = params.setup.party_verifying_key(party_id).unwrap();

            let msg3_id = MsgId::new(
                params.setup.instance(),
                &sender_pk,
                Some(vk.as_bytes()),
                DKG_MSG_R3,
            );

            let output = Builder::<Encrypted>::encode_and_encrypt(
                &msg3_id,
                100,
                &params.encryption_keypair,
                find_pair(&state.enc_pub_key, party_id)?,
                &msg3,
            )?;

            env.publish(output);
        }

        // If wait queue is not empty, wait for a next message
        if !state.wait_queue.is_empty() {
            // We wait for more messages. Return an updated state.
            return Ok(state::Output::Loop(KeygenParty { params, state }));
        }

        let R2 {
            final_session_id,
            x_i_list,
            big_f_i_vecs,
            vsot_next_receivers,
            vsot_senders,
            enc_pub_key,
            ..
        } = state;

        let mut big_f_vec = GroupPolynomial::new(
            (0..params.setup.threshold())
                .map(|_| ProjectivePoint::IDENTITY.into())
                .collect(),
        );

        for (_, v) in &big_f_i_vecs {
            big_f_vec.add_mut(v);
        }

        let mut wait_queue = WaitQueue::new();

        let sender_vk = params.setup.signing_key().verifying_key();
        let sender_pk = sender_vk.as_bytes();

        params.setup.other_parties_iter().for_each(|(p, vk)| {
            let msg3_id = MsgId::new(
                params.setup.instance(),
                vk.as_bytes(),
                Some(sender_pk),
                DKG_MSG_R3,
            );

            env.wait(&msg3_id, 10);

            wait_queue.wait(&msg3_id, p);
        });

        let state = R3 {
            wait_queue,
            final_session_id,
            x_i_list,
            vsot_receivers: vsot_next_receivers,
            vsot_senders,
            big_f_vec,
            big_f_i_vecs,
            enc_pub_key,
        };

        // println!("R2 done");

        Ok(state::Output::Next(KeygenParty { params, state }))
    }
}

// impl state::State for KeygenParty<R3> {
//     type Next = KeygenParty<R4>;
//     type Error = KeygenError;

//     fn process(self, env: &mut dyn state::Env, msg: &mut Message) -> state::StateResult<Self> {
//         let Self {
//             mut state,
//             mut params,
//         } = self;

//         // messages.par_iter().try_for_each(|msg| {
//         //     let msg3_hash = hash_msg3(
//         //         &self.state.final_session_id,
//         //         &msg.big_f_vec,
//         //         &msg.encrypted_d_i_vec,
//         //         &msg.enc_vsot_msgs2,
//         //     );

//         //     let verify_key = &self.params.party_pubkeys_list[msg.get_pid()].verify_key;

//         //     verify_signature(&msg3_hash, msg.get_signature(), verify_key)?;

//         //     (msg.big_f_vec == self.state.big_f_vec)
//         //         .then_some(())
//         //         .ok_or(KeygenError::BigFVecMismatch)?;

//         //     Ok::<(), KeygenError>(())
//         // })?;

//         let f_i_vals = messages
//             .iter()
//             .map(|msg| {
//                 let encrypted_d_i = &msg.encrypted_d_i_vec[self.params.party_id];
//                 let nonce = &encrypted_d_i.nonce;
//                 let d_i_bytes = encrypted_d_i.enc_data.decrypt_to_vec(
//                     nonce,
//                     &self.params.party_pubkeys_list[msg.get_pid()].encryption_key,
//                     &self.params.encryption_keypair.secret_key,
//                 )?;

//                 let f_i = Scalar::from_repr(*FieldBytes::from_slice(&d_i_bytes));

//                 if f_i.is_none().into() {
//                     return Err(KeygenError::InvalidDiPlaintext);
//                 }
//                 Ok(f_i.unwrap())
//             })
//             .collect::<Result<Vec<_>, KeygenError>>()?;

//         if f_i_vals.len() != self.params.n {
//             return Err(KeygenError::InvalidFiLen);
//         }

//         for (big_f_i_vec, f_i_val) in self.state.big_f_i_vecs.iter().zip(f_i_vals.iter()) {
//             let coeffs = big_f_i_vec.derivative_coeffs(self.params.rank);

//             let valid = feldman_verify(
//                 &coeffs,
//                 &self.state.x_i_list[self.params.party_id],
//                 f_i_val,
//                 &ProjectivePoint::GENERATOR,
//             )
//             .expect("u_i_k cannot be empty");

//             if !valid {
//                 return Err(KeygenError::FailedFelmanVerify);
//             }
//         }

//         let public_key = self.state.big_f_vec[0];
//         let s_i: Scalar = f_i_vals.iter().sum();
//         let big_s_i = ProjectivePoint::GENERATOR * s_i;

//         let mut transcript = Transcript::new_dlog_proof(
//             &self.state.final_session_id,
//             self.params.party_id,
//             DLOG_PROOF2_LABEL,
//             DKG_LABEL,
//         );

//         let proof = DLogProof::prove(
//             &s_i,
//             &ProjectivePoint::GENERATOR,
//             &mut transcript,
//             &mut params.rng,
//         );
//         let senders = self.state.vsot_senders.into_par_iter();

//         let (next_senders, enc_vsot_msgs3) = process_vsot_instances(
//             senders,
//             self.state.other_parties.par_iter(),
//             &messages,
//             self.params.party_id,
//             &self.params.party_pubkeys_list,
//             &self.params.encryption_keypair.secret_key,
//         )?;

//         // let msg4_hash = hash_msg4(
//         //     &self.state.final_session_id,
//         //     &public_key,
//         //     &big_s_i,
//         //     &proof,
//         //     &enc_vsot_msgs3,
//         // );

//         // let signature = sign_message(&self.params.signing_key, &msg4_hash)?;

//         let state = R4 {
//             final_session_id: self.state.final_session_id,
//             vsot_receivers: self.state.vsot_receivers,
//             vsot_senders: next_senders,
//             public_key,
//             s_i,
//             // rank_list: self.state.rank_list,
//             x_i_list: self.state.x_i_list,
//             big_f_vec: self.state.big_f_vec,
//             // other_parties: self.state.other_parties,
//         };

//         // let msg4 = KeygenMsg4 {
//         //     session_id: self.state.final_session_id,
//         //     public_key,
//         //     big_s_i,
//         //     dlog_proof: proof,
//         //     enc_vsot_msgs3,
//         // };

//         // let next_state = KeygenParty {
//         //     params,
//         //     state: new_state,
//         // };

//         Ok(state::Output::Next(KeygenParty { params, state }))
//     }
// }

// impl Round for KeygenParty<R4> {
//     type Input = Vec<KeygenMsg4>;

//     type Output = Result<(KeygenParty<R5>, KeygenMsg5), KeygenError>;

//     fn process(self, messages: Self::Input) -> Self::Output {
//         let messages = validate_input_messages(messages, self.params.n)?;
//         messages.par_iter().try_for_each(|msg| {
//             let msg4_hash = hash_msg4(
//                 &self.state.final_session_id,
//                 &msg.public_key,
//                 &msg.big_s_i,
//                 &msg.dlog_proof,
//                 &msg.enc_vsot_msgs3,
//             );

//             let verify_key = &self.params.party_pubkeys_list[msg.get_pid()].verify_key;
//             verify_signature(&msg4_hash, msg.get_signature(), verify_key)?;

//             if self.state.public_key != msg.public_key {
//                 return Err(KeygenError::PublicKeyMismatch);
//             }

//             Ok(())
//         })?;

//         let big_s_list = messages
//             .iter()
//             .map(|msg| {
//                 let party_id = msg.get_pid();
//                 let big_s_i = &msg.big_s_i;
//                 let dlog_proof = &msg.dlog_proof;

//                 let mut transcript = Transcript::new_dlog_proof(
//                     &self.state.final_session_id,
//                     party_id,
//                     DLOG_PROOF2_LABEL,
//                     DKG_LABEL,
//                 );

//                 dlog_proof
//                     .verify(big_s_i, ProjectivePoint::GENERATOR, &mut transcript)
//                     .then_some(())
//                     .ok_or(KeygenError::InvalidDLogProof)?;

//                 let rank = self.state.rank_list[party_id];
//                 let x_i = self.state.x_i_list[party_id];
//                 let coeff_multipliers = polynomial_coeff_multipliers(&x_i, rank, self.params.n);
//                 let mut expected_point = ProjectivePoint::IDENTITY;
//                 for (point, coeff) in self.state.big_f_vec.iter().zip(coeff_multipliers) {
//                     expected_point += point * &coeff;
//                 }

//                 (expected_point == msg.big_s_i)
//                     .then_some(())
//                     .ok_or(KeygenError::BigSMismatch)?;

//                 Ok(msg.big_s_i)
//             })
//             .collect::<Result<Vec<_>, KeygenError>>()?;

//         check_secret_recovery(
//             &self.state.x_i_list,
//             &self.state.rank_list,
//             &big_s_list,
//             &self.state.public_key,
//         )?;

//         let receivers = self.state.vsot_receivers.into_par_iter();

//         let (new_receivers, enc_vsot_msgs4) = process_vsot_instances(
//             receivers,
//             self.state.other_parties.par_iter(),
//             &messages,
//             self.params.party_id,
//             &self.params.party_pubkeys_list,
//             &self.params.encryption_keypair.secret_key,
//         )?;

//         let msg5_hash = hash_msg5(&self.state.final_session_id, &enc_vsot_msgs4);

//         let signature = sign_message(&self.params.signing_key, &msg5_hash)?;

//         let new_state = R5 {
//             final_session_id: self.state.final_session_id,
//             vsot_receivers: new_receivers,
//             vsot_senders: self.state.vsot_senders,
//             public_key: self.state.public_key,
//             s_i: self.state.s_i,
//             // rank_list: self.state.rank_list,
//             x_i_list: self.state.x_i_list,
//             big_s_list,
//             // other_parties: self.state.other_parties,
//         };

//         let msg5 = KeygenMsg5 {
//             from_party: self.params.party_id,
//             session_id: self.state.final_session_id,
//             enc_vsot_msgs4,
//             signature,
//         };

//         let next_state = KeygenParty {
//             rng: self.rng,
//             params: self.params,
//             state: new_state,
//         };

//         Ok((next_state, msg5))
//     }
// }

// impl Round for KeygenParty<R5> {
//     type Input = Vec<KeygenMsg5>;

//     type Output = Result<(KeygenParty<R6>, KeygenMsg6), KeygenError>;

//     fn process(self, messages: Self::Input) -> Self::Output {
//         let messages = validate_input_messages(messages, self.params.n)?;
//         messages.par_iter().try_for_each(|msg| {
//             let msg5_hash = hash_msg5(&self.state.final_session_id, &msg.enc_vsot_msgs4);

//             let verify_key = &self.params.party_pubkeys_list[msg.get_pid()].verify_key;
//             verify_signature(&msg5_hash, msg.get_signature(), verify_key)?;

//             Ok::<(), KeygenError>(())
//         })?;

//         let senders = self.state.vsot_senders.into_par_iter();

//         let (vsot_sender_outputs, enc_vsot_msgs5) = process_vsot_instances(
//             senders,
//             self.state.other_parties.par_iter(),
//             &messages,
//             self.params.party_id,
//             &self.params.party_pubkeys_list,
//             &self.params.encryption_keypair.secret_key,
//         )?;

//         let mut seed_ot_senders = vec![];
//         let enc_pprf_outputs = vsot_sender_outputs
//             .iter()
//             .zip(self.state.other_parties.iter())
//             .map(|(sender_output, receiver_party_id)| {
//                 let (all_but_one_sender_seed, pprf_output) = build_pprf(
//                     &self.state.final_session_id,
//                     sender_output,
//                     256,
//                     SOFT_SPOKEN_K,
//                 );
//                 seed_ot_senders.push(all_but_one_sender_seed);
//                 let sender_pubkey =
//                     &self.params.party_pubkeys_list[*receiver_party_id].encryption_key;

//                 let enc_pprf_output = encrypt_data(
//                     pprf_output.to_bytes().unwrap(),
//                     sender_pubkey,
//                     &self.params.encryption_keypair.secret_key,
//                     *receiver_party_id,
//                     self.params.party_id,
//                 )?;

//                 Ok(enc_pprf_output)
//             })
//             .collect::<Result<Vec<EncryptedData>, sl_mpc_mate::nacl::Error>>()?;

//         // TODO: Accept this rng as input
//         let mut rng = rand::thread_rng();
//         let mut seed_i_j_list: Vec<[u8; 32]> = vec![];
//         let mut enc_seed_i_j_list: Vec<EncryptedData> = vec![];

//         // For party id > self.params.party_id
//         for id in self
//             .state
//             .other_parties
//             .iter()
//             .filter(|id| **id > self.params.party_id)
//         {
//             let seed_i_j = rng.gen();
//             seed_i_j_list.push(seed_i_j);
//             let ek_i = &self.params.party_pubkeys_list[*id].encryption_key;
//             let enc_seed_i_j = encrypt_data(
//                 seed_i_j,
//                 ek_i,
//                 &self.params.encryption_keypair.secret_key,
//                 *id,
//                 self.params.party_id,
//             )?;
//             enc_seed_i_j_list.push(enc_seed_i_j);
//         }

//         let msg6_hash = hash_msg6(
//             &self.state.final_session_id,
//             &enc_vsot_msgs5,
//             &enc_pprf_outputs,
//             &enc_seed_i_j_list,
//         );

//         let signature = sign_message(&self.params.signing_key, &msg6_hash)?;

//         let msg6 = KeygenMsg6 {
//             from_party: self.params.party_id,
//             session_id: self.state.final_session_id,
//             enc_vsot_msgs5,
//             enc_pprf_outputs,
//             enc_seed_i_j_list,
//             signature,
//         };

//         let next_state = KeygenParty {
//             rng: self.rng,
//             params: self.params,
//             state: R6 {
//                 final_session_id: self.state.final_session_id,
//                 vsot_receivers: self.state.vsot_receivers,
//                 seed_ot_senders,
//                 public_key: self.state.public_key,
//                 s_i: self.state.s_i,
//                 // rank_list: self.state.rank_list,
//                 x_i_list: self.state.x_i_list,
//                 big_s_list: self.state.big_s_list,
//                 // other_parties: self.state.other_parties,
//                 sent_seed_list: seed_i_j_list,
//             },
//         };

//         Ok((next_state, msg6))
//     }
// }

// impl Round for KeygenParty<R6> {
//     type Input = Vec<KeygenMsg6>;

//     type Output = Result<(Keyshare, KeyGenCompleteMsg), KeygenError>;

//     fn process(self, messages: Self::Input) -> Self::Output {
//         let messages = validate_input_messages(messages, self.params.n)?;
//         messages.par_iter().try_for_each(|msg| {
//             let msg6_hash = hash_msg6(
//                 &self.state.final_session_id,
//                 &msg.enc_vsot_msgs5,
//                 &msg.enc_pprf_outputs,
//                 &msg.enc_seed_i_j_list,
//             );

//             let verify_key = &self.params.party_pubkeys_list[msg.get_pid()].verify_key;
//             verify_signature(&msg6_hash, msg.get_signature(), verify_key)?;

//             Ok::<(), KeygenError>(())
//         })?;
//         let receivers = self.state.vsot_receivers.into_par_iter();
//         let sender_ids = self.state.other_parties.par_iter();

//         let seed_ot_receivers = receivers
//             .zip(sender_ids)
//             .map(|(receiver, sender_party_id)| {
//                 // idx is the position of current parties receiver for each sender.
//                 let message = &messages[*sender_party_id];
//                 let enc_vsot_msg = message.get_vsot_msg(self.params.party_id);
//                 let sender_public_key =
//                     &self.params.party_pubkeys_list[*sender_party_id].encryption_key;
//                 let vsot_msg = enc_vsot_msg.enc_data.decrypt_to_vec(
//                     &enc_vsot_msg.nonce,
//                     sender_public_key,
//                     &self.params.encryption_keypair.secret_key,
//                 )?;
//                 let vsot_msg =
//                     VSOTMsg5::from_bytes(&vsot_msg).ok_or(KeygenError::InvalidVSOTPlaintext)?;
//                 let receiver_output = receiver.process(vsot_msg)?;
//                 let pprf_output_idx = get_idx_from_id(message.get_pid(), self.params.party_id);
//                 let enc_pprf_output = &message.enc_pprf_outputs[pprf_output_idx];

//                 let pprf_output = enc_pprf_output.enc_data.decrypt_to_vec(
//                     &enc_pprf_output.nonce,
//                     sender_public_key,
//                     &self.params.encryption_keypair.secret_key,
//                 )?;
//                 let pprf_output = Vec::<PPRFOutput>::from_bytes(&pprf_output)
//                     .ok_or(KeygenError::InvalidPPRFPlaintext)?;

//                 let all_but_one_receiver_seed = eval_pprf(
//                     &self.state.final_session_id,
//                     &receiver_output,
//                     256,
//                     SOFT_SPOKEN_K,
//                     pprf_output,
//                 )
//                 .map_err(KeygenError::PPRFError)?;

//                 Ok::<_, KeygenError>(all_but_one_receiver_seed)
//             })
//             .collect::<Result<Vec<_>, KeygenError>>()?;

//         // Get messages with party id less than current party id.
//         let rec_seed_list = messages
//             .par_iter()
//             .take(self.params.party_id)
//             .map(|message| {
//                 let ek_i = &self.params.party_pubkeys_list[message.get_pid()].encryption_key;
//                 let enc_seed_j_i =
//                     &message.enc_seed_i_j_list[self.params.party_id - message.get_pid() - 1];

//                 let seed_j_i: [u8; 32] = enc_seed_j_i
//                     .enc_data
//                     .decrypt_to_vec(
//                         &enc_seed_j_i.nonce,
//                         ek_i,
//                         &self.params.encryption_keypair.secret_key,
//                     )?
//                     .try_into()
//                     .map_err(|_| KeygenError::InvalidSeed)?;

//                 Ok(seed_j_i)
//             })
//             .collect::<Result<Vec<[u8; 32]>, KeygenError>>()?;

//         let keyshare = Keyshare {
//             public_key: self.state.public_key,
//             x_i: self.state.x_i_list[self.params.party_id],
//             big_s_list: self.state.big_s_list,
//             s_i: self.state.s_i,
//             rank_list: self.state.rank_list,
//             x_i_list: self.state.x_i_list,
//             party_id: self.params.party_id,
//             threshold: self.params.t,
//             total_parties: self.params.n,
//             rank: self.params.rank,
//             seed_ot_receivers,
//             seed_ot_senders: self.state.seed_ot_senders,
//             sent_seed_list: self.state.sent_seed_list,
//             rec_seed_list,
//         };

//         let complete_msg = KeyGenCompleteMsg {
//             from_party: self.params.party_id,
//             public_key: keyshare.public_key.to_affine(),
//         };

//         Ok((keyshare, complete_msg))
//     }
// }

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
    hasher.update(&session_id);
    hasher.update((party_id as u64).to_be_bytes());
    hasher.update((rank as u64).to_be_bytes());
    hasher.update(x_i.to_bytes());

    for point in &big_f_i_vec.coeffs {
        hasher.update(point.to_bytes());
    }

    hasher.update(r_i);

    HashBytes::new(hasher.finalize().into())
}

fn get_vsot_session_id(from_party: usize, to_party: usize, session_id: &SessionId) -> SessionId {
    SessionId::new(
        Sha256::new()
            .chain_update(DKG_LABEL)
            .chain_update(&session_id)
            .chain_update(b"from_party")
            .chain_update((from_party as u64).to_be_bytes())
            .chain_update(b"to_party")
            .chain_update((to_party as u64).to_be_bytes())
            .chain_update(b"vsot_session_id")
            .finalize()
            .into(),
    )
}

fn verfiy_dlog_proofs<'a>(
    proofs: &[DLogProof],
    points: impl Iterator<Item = &'a ProjectivePoint>,
    transcript: &mut Transcript,
) -> Result<(), KeygenError> {
    for (proof, point) in proofs.iter().zip(points) {
        proof
            .verify(point, &ProjectivePoint::GENERATOR, transcript)
            .then_some(())
            .ok_or(KeygenError::InvalidDLogProof)?;
    }

    Ok(())
}

// /// Rust voodoo to process all the senders/receivers of a party
// fn process_vsot_instances<CM, NM, M, VSOT, VSOTNEXT>(
//     vsot_instances: rayon::vec::IntoIter<VSOT>,
//     other_party_ids: rayon::slice::Iter<usize>,
//     messages: &[M],
//     party_id: usize,
//     party_pubkeys_list: &[PartyPublicKeys],
//     secret_key: &sl_mpc_mate::nacl::BoxPrivKey,
// ) -> Result<(Vec<VSOTNEXT>, Vec<EncryptedData>), KeygenError>
// where
//     VSOT: Round<Input = CM, Output = Result<(VSOTNEXT, NM), VSOTError>> + Send,
//     CM: PersistentObject,
//     VSOTNEXT: Send,
//     M: HasVsotMsg + Sync,
//     NM: PersistentObject,
// {
//     let (next_receivers, enc_vsot_msgs): (Vec<VSOTNEXT>, Vec<EncryptedData>) = vsot_instances
//         .zip(other_party_ids)
//         .map(|(receiver, sender_party_id)| {
//             // idx is the position of current parties receiver for each sender.
//             let message = &messages[*sender_party_id];

//             let enc_vsot_msg = message.get_vsot_msg(party_id);
//             let sender_public_key = &party_pubkeys_list[*sender_party_id].encryption_key;
//             let vsot_msg = enc_vsot_msg
//                 .enc_data
//                 .decrypt_to_vec(&enc_vsot_msg.nonce, sender_public_key, secret_key)
//                 .unwrap(); // FIXME ?;

//             let vsot_msg = CM::from_bytes(&vsot_msg).ok_or(KeygenError::InvalidVSOTPlaintext)?;

//             let (new_receiver, vsot_msg) = receiver.process(vsot_msg)?;

//             let enc_vsot_msg = encrypt_data(
//                 vsot_msg.to_bytes().unwrap(),
//                 sender_public_key,
//                 secret_key,
//                 *sender_party_id,
//                 party_id,
//             )
//             .unwrap(); // FiXME ?;

//             Ok::<_, KeygenError>((new_receiver, enc_vsot_msg))
//         })
//         .collect::<Result<Vec<_>, KeygenError>>()?
//         .into_iter()
//         .unzip();

//     Ok((next_receivers, enc_vsot_msgs))
// }

#[cfg(test)]
mod tests {
    use super::*;
    use std::array;

    use sl_mpc_mate::{
        coord::{Coord, Receiver, Sender},
        state::{Final, Next, Status, Step},
    };

    use crate::setup::{keygen::*, SETUP_MESSAGE_TAG};

    struct Party<S> {
        state: S,
        env: Sender,
        rx: Receiver,
    }

    impl<S: Step> Party<S> {
        async fn run(&mut self) -> S::Result {
            // println!("entr {:p} ...", self);
            loop {
                // println!("recv {:p} ...", self);
                let mut msg = self.rx.recv().await.unwrap();
                let mut msg = Message::from_buffer(&mut msg).unwrap();

                // println!("got  {:p} {:?}", self, msg.id());

                let res = self.state.step(&mut self.env, &mut msg);

                // println!("done {:p} {:?}", self, msg.id());

                match res {
                    Status::Pending => {} // println!("res  {:p} Pending", self)},
                    Status::Error(err) => {
                        panic!("res  {:p} {:?} Error {:?}", self, msg.id(), err);
                    }
                    Status::Finished => {
                        panic!("res  {:p} Finished", self);
                    }
                    Status::Fini(f) => return f,
                }
            }
        }
    }

    fn setup_keygen<const T: usize, const N: usize>(
        n_i_list: Option<[usize; N]>,
        coord: &Coord,
    ) -> Vec<(KeygenParty<R1>, Sender, Receiver)> {
        let mut rng = rand::thread_rng();

        let instance = InstanceId::from(rng.gen::<[u8; 32]>());

        // signing key to sing the setup message
        let setup_sk = SigningKey::from_bytes(&rng.gen());
        let setup_vk = setup_sk.verifying_key();
        let setup_pk = setup_vk.to_bytes();

        let setup_msg_id = MsgId::new(&instance, &setup_pk, None, SETUP_MESSAGE_TAG);

        // a signing key for each party.
        let party_sk: [SigningKey; N] = array::from_fn(|_| SigningKey::from_bytes(&rng.gen()));

        // Create a setup message. In a real world,
        // this part will be created by an intiator.
        // The setup message contail public keys of
        // all parties that will participate in this
        // protocol execution.
        let mut setup = n_i_list
            .unwrap_or([0; N])
            .into_iter()
            .enumerate()
            .fold(SetupBuilder::new(), |setup, p| {
                let vk = party_sk[p.0].verifying_key();
                setup.add_party(p.1 as u8, &vk)
            })
            .build(&setup_msg_id, 100, T as u8, &setup_sk)
            .unwrap();

        party_sk
            .into_iter()
            .map(|party_sk| {
                ValidatedSetup::decode(&mut setup, &instance, &setup_vk, party_sk, |_, _, _| true)
                    .unwrap()
            })
            .map(|setup| {
                let seed = rng.gen();

                let (mut env, rx) = coord.connect();

                (KeygenParty::new(setup, &mut env, seed), env, rx)
            })
            .collect::<Vec<_>>()
    }

    #[test]
    fn r0() {}

    // (flavor = "multi_thread")
    #[tokio::test(flavor = "multi_thread")]
    async fn r1() {
        let coord = Coord::new();

        type Proto = Next<KeygenParty<R1>, Final<KeygenParty<R2>>>;
        // type Proto = Final<KeygenParty<R1>>;

        let parties = setup_keygen::<2, 3>(None, &coord)
            .into_iter()
            .map(|(p, env, rx)| Party {
                state: Proto::create(p),
                env,
                rx,
            })
            .collect::<Vec<_>>();

        let mut tasks = tokio::task::JoinSet::new();

        parties.into_iter().for_each(|mut p| {
            tasks.spawn(async move { p.run().await });
        });

        while let Some(fini) = tasks.join_next().await {
            assert!(fini.is_ok());
        }
    }
}
