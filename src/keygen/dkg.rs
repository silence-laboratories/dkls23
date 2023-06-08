use std::fmt::Debug;

use k256::{
    elliptic_curve::{group::GroupEncoding, subtle::ConstantTimeEq, PrimeField},
    schnorr::CryptoRngCore,
    sha2::{digest, Sha256},
    FieldBytes, NonZeroScalar, ProjectivePoint, Scalar, Secp256k1,
};
use merlin::Transcript;
use rand::{rngs::OsRng, Rng, SeedableRng};
use rayon::prelude::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator, ParallelIterator,
};

use crate::{
    keygen::messages::{KeygenMsg2, KeygenMsg3, KeygenMsg5, KeygenMsg6, Keyshare},
    utils::{calculate_final_session_id, get_hash, Init},
};

use sl_oblivious::{
    soft_spoken::build_pprf,
    utils::TranscriptProtocol,
    vsot::{
        InitRec, RecR1, RecR2, SendR1, SendR2, SenderOutput, VSOTError, VSOTMsg5, VSOTReceiver,
        VSOTSender,
    },
    zkproofs::DLogProof,
};

use digest::Digest;
use sl_mpc_mate::{
    math::{birkhoff_coeffs, feldman_verify, polynomial_coeff_multipliers, GroupPolynomial},
    nacl::{encrypt_data, sign_message, verify_signature, BoxPrivKey, EncryptedData, HasSignature},
    traits::{HasFromParty, PersistentObject, Round},
    HashBytes, SessionId,
};

use super::{
    messages::{KeyGenCompleteMsg, KeygenMsg1, KeygenMsg4},
    types::KeygenParams,
    HasVsotMsg, KeyEntropy, KeygenError, KeygenPartyKeys, KeygenPartyPublicKeys,
};

/// LABEL for the keygen protocol
pub const DKG_LABEL: &[u8] = b"SilenceLaboratories-DKG-DKLS";
/// LABEL for the DLOG proof 1
pub const DLOG_PROOF1_LABEL: &[u8] = b"SilenceLaboratories-DKG-DLOG-PROOF1";
/// LABEL for the DLOG proof 2
pub const DLOG_PROOF2_LABEL: &[u8] = b"SilenceLaboratories-DKG-DLOG-PROOF2";

/// Keygen logic for a single party
pub struct KeygenParty<T> {
    params: KeygenParams,
    state: T,
}

/// State of a keygen party after receiving public keys of all parties and generating the first message.
pub struct R1 {
    big_f_i_vec: GroupPolynomial<Secp256k1>,
}

/// State of a keygen party after processing the first message.
pub struct R2 {
    final_session_id: SessionId,
    vsot_receivers: Vec<VSOTReceiver<InitRec>>,
    vsot_senders: Vec<VSOTSender<SendR1>>,
    commitment_list: Vec<HashBytes>,
    x_i_list: Vec<NonZeroScalar>,
    rank_list: Vec<usize>,
    sid_i_list: Vec<SessionId>,
    other_parties: Vec<usize>,
}

/// State of a keygen party after processing the second message.
pub struct R3 {
    final_session_id: SessionId,
    vsot_receivers: Vec<VSOTReceiver<RecR1>>,
    vsot_senders: Vec<VSOTSender<SendR1>>,
    x_i_list: Vec<NonZeroScalar>,
    rank_list: Vec<usize>,
    big_f_vec: GroupPolynomial<Secp256k1>,
    big_f_i_vecs: Vec<GroupPolynomial<Secp256k1>>,
    other_parties: Vec<usize>,
}

/// State of a keygen party after processing the third message.
pub struct R4 {
    final_session_id: SessionId,
    vsot_receivers: Vec<VSOTReceiver<RecR1>>,
    vsot_senders: Vec<VSOTSender<SendR2>>,
    s_i: Scalar,
    public_key: ProjectivePoint,
    rank_list: Vec<usize>,
    x_i_list: Vec<NonZeroScalar>,
    big_f_vec: GroupPolynomial<Secp256k1>,
    other_parties: Vec<usize>,
}

/// State of a keygen party after processing the fourth message.
pub struct R5 {
    final_session_id: SessionId,
    vsot_receivers: Vec<VSOTReceiver<RecR2>>,
    vsot_senders: Vec<VSOTSender<SendR2>>,
    s_i: Scalar,
    public_key: ProjectivePoint,
    rank_list: Vec<usize>,
    x_i_list: Vec<NonZeroScalar>,
    big_s_list: Vec<ProjectivePoint>,
    other_parties: Vec<usize>,
}
/// State of a keygen party after processing the fifth message.
pub struct R6 {
    final_session_id: SessionId,
    vsot_receivers: Vec<VSOTReceiver<RecR2>>,
    vsot_sender_outputs: Vec<SenderOutput>,
    s_i: Scalar,
    public_key: ProjectivePoint,
    rank_list: Vec<usize>,
    x_i_list: Vec<NonZeroScalar>,
    big_s_list: Vec<ProjectivePoint>,
    other_parties: Vec<usize>,
}

fn validate_input(t: usize, n: usize, party_id: usize, rank: usize) -> Result<(), KeygenError> {
    if party_id >= n {
        return Err(KeygenError::InvalidPid);
    }

    if t > n || t < 2 {
        return Err(KeygenError::InvalidT);
    }

    if rank >= t {
        return Err(KeygenError::InvalidLevel);
    }

    Ok(())
}

impl KeygenParty<Init> {
    /// Create a new keygen party.
    pub fn new(
        t: usize,
        n: usize,
        party_id: usize,
        rank: usize,
        keys: &KeygenPartyKeys,
        soft_spoken_k: u8,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self, KeygenError> {
        let rand_params = KeyEntropy::generate(rng, t, n);
        Self::new_with_context(t, n, party_id, rank, keys, soft_spoken_k, rand_params)
    }

    /// Create a new keygen protocol instance with a given context. Used for testing purposes internally.
    pub(crate) fn new_with_context(
        t: usize,
        n: usize,
        party_id: usize,
        rank: usize,
        party_keys: &KeygenPartyKeys,
        soft_spoken_k: u8,
        rand_params: KeyEntropy,
    ) -> Result<Self, KeygenError> {
        validate_input(t, n, party_id, rank)?;

        Ok(Self {
            params: KeygenParams {
                t,
                n,
                party_id,
                rank,
                party_pubkeys_list: Vec::with_capacity(n),
                verify_key: party_keys.verify_key,
                signing_key: party_keys.signing_key,
                encryption_keypair: party_keys.encryption_keypair.clone(),
                soft_spoken_k,
                rand_params,
            },
            state: Init,
        })
    }
}

impl Round for KeygenParty<Init> {
    type Input = Vec<KeygenPartyPublicKeys>;
    type Output = Result<(KeygenParty<R1>, KeygenMsg1), KeygenError>;

    fn process(self, pubkeys: Self::Input) -> Self::Output {
        if pubkeys.len() != self.params.n {
            return Err(KeygenError::InvalidMessageLength);
        }

        let params = KeygenParams {
            party_pubkeys_list: pubkeys,
            ..self.params
        };

        let big_f_i_vec = params.rand_params.polynomial.commit();
        let commitment = hash_commitment(
            params.rand_params.session_id,
            params.party_id,
            params.rank,
            params.rand_params.x_i,
            &big_f_i_vec,
            &params.rand_params.r_i,
        );

        let msg_hash = hash_msg1(
            &params.rand_params.session_id,
            params.rank,
            &params.rand_params.x_i,
            &commitment,
        );

        let signature = sign_message(&params.signing_key, &msg_hash)?;

        let msg1 = KeygenMsg1 {
            from_party: params.party_id,
            session_id: params.rand_params.session_id,
            rank: params.rank,
            x_i: params.rand_params.x_i,
            commitment,
            signature,
        };

        let next_state = KeygenParty {
            params,
            state: R1 { big_f_i_vec },
        };

        Ok((next_state, msg1))
    }
}

impl Round for KeygenParty<R1> {
    type Input = Vec<KeygenMsg1>;

    type Output = Result<(KeygenParty<R2>, KeygenMsg2), KeygenError>;

    fn process(self, messages: Self::Input) -> Self::Output {
        let messages = validate_input_messages(messages, self.params.n)?;
        let mut sid_i_list = Vec::with_capacity(self.params.n);
        let mut commitment_list = Vec::with_capacity(self.params.n);
        let mut rank_list = Vec::with_capacity(self.params.n);
        let mut x_i_list = Vec::with_capacity(self.params.n);
        let mut party_id_list = Vec::with_capacity(self.params.n);

        for message in &messages {
            let party_pubkey_idx = message.get_pid();

            let KeygenPartyPublicKeys { verify_key, .. } =
                &self.params.party_pubkeys_list[party_pubkey_idx];

            let message_hash = hash_msg1(
                &message.session_id,
                message.rank,
                &message.x_i,
                &message.commitment,
            );
            let signature = message.get_signature();

            verify_signature(&message_hash, signature, verify_key)?;

            sid_i_list.push(message.session_id);
            commitment_list.push(message.commitment);
            rank_list.push(message.rank);
            x_i_list.push(message.x_i);
            party_id_list.push(party_pubkey_idx);
        }

        if self.params.rand_params.session_id != sid_i_list[self.params.party_id] {
            return Err(KeygenError::InvalidSelfSessionId);
        }

        if self.params.party_id != party_id_list[self.params.party_id] {
            return Err(KeygenError::InvalidSelfPartyId);
        }

        // TODO: Should parties be initialized with rank_list and x_i_list? Ask Vlad.
        let final_sid =
            calculate_final_session_id(messages.iter().map(|msg| msg.get_pid()), &sid_i_list);

        // Setup transcript for DLog proofs.
        let mut dlog_transcript = Transcript::new_dlog_proof(
            &final_sid,
            self.params.party_id,
            DLOG_PROOF1_LABEL,
            DKG_LABEL,
        );

        // TODO: Accept a RNG as input to the protocol.
        let mut rng = OsRng;

        let dlog_proofs = self
            .params
            .rand_params
            .polynomial
            .iter()
            .map(|f_i| {
                DLogProof::prove(
                    f_i,
                    ProjectivePoint::GENERATOR,
                    &mut dlog_transcript,
                    &mut rng,
                )
            })
            .collect::<Vec<_>>();

        // List of party ids that are not the current party.
        let mut other_parties = party_id_list.clone();
        other_parties.remove(self.params.party_id);

        // let senders = party_id_list.iter().skip(self.params.party_id + 1);
        // Seeds for deterministic generation of VSOT receivers.
        // Used to create test vectors.
        let rec_seeds: Vec<_> = other_parties
            .iter()
            .map(|_| rng.gen::<[u8; 32]>())
            .collect();

        let vsot_receivers = other_parties
            .par_iter()
            .enumerate()
            .map(|(idx, pid)| {
                let vsot_session_id = get_vsot_session_id(*pid, self.params.party_id, &final_sid);
                let mut rng = rand::rngs::StdRng::from_seed(rec_seeds[idx]);
                VSOTReceiver::new(vsot_session_id, 256, &mut rng)
            })
            .collect::<Result<Vec<_>, VSOTError>>()?;

        // Seeds for deterministic generation of VSOT senders.
        // Used to create test vectors.
        let sender_seeds = other_parties
            .iter()
            .map(|_| rng.gen::<[u8; 32]>())
            .collect::<Vec<_>>();

        let (vsot_senders, enc_vsot_msg1): (Vec<VSOTSender<_>>, Vec<EncryptedData>) = other_parties
            .par_iter()
            .enumerate()
            .map(|(idx, pid)| {
                let enc_key = &self.params.party_pubkeys_list[*pid].encryption_key;
                let mut rng = rand::rngs::StdRng::from_seed(sender_seeds[idx]);
                let vsot_session_id = get_vsot_session_id(self.params.party_id, *pid, &final_sid);
                let (sender, msg1) = VSOTSender::new(vsot_session_id, 256, &mut rng)
                    .map(|sender| sender.process(()))?;

                let msg1_bytes = msg1.to_bytes().unwrap();
                let enc_msg1 = encrypt_data(
                    msg1_bytes,
                    enc_key,
                    &self.params.encryption_keypair.secret_key,
                    *pid,
                    self.params.party_id,
                )?;

                Ok((sender, enc_msg1))
            })
            .collect::<Result<Vec<_>, KeygenError>>()?
            .into_iter()
            .unzip();

        let hash_message_2 = hash_msg2(
            &final_sid,
            &commitment_list,
            &self.state.big_f_i_vec,
            &self.params.rand_params.r_i,
            &dlog_proofs,
            &enc_vsot_msg1,
        );

        let signature = sign_message(&self.params.signing_key, &hash_message_2)?;

        let msg2 = KeygenMsg2 {
            session_id: final_sid,
            from_party: self.params.party_id,
            big_f_i_vector: self.state.big_f_i_vec,
            r_i: self.params.rand_params.r_i,
            dlog_proofs_i: dlog_proofs,
            enc_vsot_msgs: enc_vsot_msg1,
            signature,
        };

        let next_state = KeygenParty {
            params: self.params,
            state: R2 {
                final_session_id: final_sid,
                vsot_receivers,
                vsot_senders,
                commitment_list,
                x_i_list,
                rank_list,
                sid_i_list,
                other_parties,
            },
        };

        Ok((next_state, msg2))
    }
}

impl Round for KeygenParty<R2> {
    type Input = Vec<KeygenMsg2>;

    type Output = Result<(KeygenParty<R3>, KeygenMsg3), KeygenError>;

    fn process(self, messages: Self::Input) -> Self::Output {
        let messages = validate_input_messages(messages, self.params.n)?;

        messages.par_iter().try_for_each(|msg| {
            // Verify signature.
            let message_hash = hash_msg2(
                &self.state.final_session_id,
                &self.state.commitment_list,
                &msg.big_f_i_vector,
                &msg.r_i,
                &msg.dlog_proofs_i,
                &msg.enc_vsot_msgs,
            );

            verify_signature(
                &message_hash,
                &msg.signature,
                &self.params.party_pubkeys_list[msg.get_pid()].verify_key,
            )?;

            // Verify commitments.
            let party_id = msg.get_pid();
            let rank = self.state.rank_list[party_id];
            let x_i = self.state.x_i_list[party_id];
            let sid = self.state.sid_i_list[party_id];
            let commitment = self.state.commitment_list[party_id];

            let commit_hash =
                hash_commitment(sid, party_id, rank, x_i, &msg.big_f_i_vector, &msg.r_i);

            bool::from(commit_hash.ct_eq(&commitment))
                .then_some(())
                .ok_or(KeygenError::InvalidCommitmentHash)?;

            // Verify DLog proofs.
            let mut dlog_transcript = Transcript::new_dlog_proof(
                &self.state.final_session_id,
                party_id,
                DLOG_PROOF1_LABEL,
                DKG_LABEL,
            );

            verfiy_dlog_proofs(
                &msg.dlog_proofs_i,
                &msg.big_f_i_vector,
                &mut dlog_transcript,
            )?;

            Ok::<(), KeygenError>(())
        })?;

        let empty_poly = (0..self.params.t)
            .map(|_| ProjectivePoint::IDENTITY)
            .collect();
        let mut big_f_vec = GroupPolynomial::new(empty_poly);

        let encrypted_d_i = (0..self.params.n)
            .map(|party_id| {
                // party_id is also the index of the party's data in all the lists.

                let rank = self.state.rank_list[party_id];
                let x_i = self.state.x_i_list[party_id];
                let ek_i = &self.params.party_pubkeys_list[party_id].encryption_key;

                let d_i = self.params.rand_params.polynomial.derivative_at(rank, &x_i);

                let enc_data = encrypt_data(
                    d_i.to_bytes(),
                    ek_i,
                    &self.params.encryption_keypair.secret_key,
                    party_id,
                    self.params.party_id,
                )?;

                Ok(enc_data)
            })
            .collect::<Result<Vec<_>, KeygenError>>()?;

        let receivers = self.state.vsot_receivers.into_par_iter();

        let (next_receivers, enc_vsot_msgs2) = process_vsot_instances(
            receivers,
            self.state.other_parties.par_iter(),
            &messages,
            self.params.party_id,
            &self.params.party_pubkeys_list,
            &self.params.encryption_keypair.secret_key,
        )?;

        let mut big_f_i_vecs = Vec::with_capacity(self.params.n);
        for msg in messages {
            big_f_vec.add_mut(&msg.big_f_i_vector);
            big_f_i_vecs.push(msg.big_f_i_vector);
        }

        let msg3_hash = hash_msg3(
            &self.state.final_session_id,
            &big_f_vec,
            &encrypted_d_i,
            &enc_vsot_msgs2,
        );

        let signature = sign_message(&self.params.signing_key, &msg3_hash)?;

        let msg3 = KeygenMsg3 {
            from_party: self.params.party_id,
            session_id: self.state.final_session_id,
            big_f_vec: big_f_vec.clone(),
            encrypted_d_i_vec: encrypted_d_i,
            enc_vsot_msgs2,
            signature,
        };

        let new_state = R3 {
            final_session_id: self.state.final_session_id,
            rank_list: self.state.rank_list,
            x_i_list: self.state.x_i_list,
            vsot_receivers: next_receivers,
            vsot_senders: self.state.vsot_senders,
            big_f_vec,
            big_f_i_vecs,
            other_parties: self.state.other_parties,
        };

        let next_state = KeygenParty {
            params: self.params,
            state: new_state,
        };

        Ok((next_state, msg3))
    }
}

impl Round for KeygenParty<R3> {
    type Input = Vec<KeygenMsg3>;

    type Output = Result<(KeygenParty<R4>, KeygenMsg4), KeygenError>;

    fn process(self, messages: Self::Input) -> Self::Output {
        let messages = validate_input_messages(messages, self.params.n)?;

        messages.par_iter().try_for_each(|msg| {
            let msg3_hash = hash_msg3(
                &self.state.final_session_id,
                &msg.big_f_vec,
                &msg.encrypted_d_i_vec,
                &msg.enc_vsot_msgs2,
            );

            let verify_key = &self.params.party_pubkeys_list[msg.get_pid()].verify_key;

            verify_signature(&msg3_hash, msg.get_signature(), verify_key)?;

            (msg.big_f_vec == self.state.big_f_vec)
                .then_some(())
                .ok_or(KeygenError::BigFVecMismatch)?;

            Ok::<(), KeygenError>(())
        })?;

        let f_i_vals = messages
            .iter()
            .map(|msg| {
                let encrypted_d_i = &msg.encrypted_d_i_vec[self.params.party_id];
                let nonce = &encrypted_d_i.nonce;
                let d_i_bytes = encrypted_d_i.enc_data.decrypt_to_vec(
                    nonce,
                    &self.params.party_pubkeys_list[msg.get_pid()].encryption_key,
                    &self.params.encryption_keypair.secret_key,
                )?;

                let f_i = Scalar::from_repr(*FieldBytes::from_slice(&d_i_bytes));

                if f_i.is_none().into() {
                    return Err(KeygenError::InvalidDiPlaintext);
                }
                Ok(f_i.unwrap())
            })
            .collect::<Result<Vec<_>, KeygenError>>()?;

        if f_i_vals.len() != self.params.n {
            return Err(KeygenError::InvalidFiLen);
        }

        for (big_f_i_vec, f_i_val) in self.state.big_f_i_vecs.iter().zip(f_i_vals.iter()) {
            let coeffs = big_f_i_vec.derivative_coeffs(self.params.rank);

            let valid = feldman_verify(
                &coeffs,
                &self.state.x_i_list[self.params.party_id],
                f_i_val,
                &ProjectivePoint::GENERATOR,
            )
            .expect("u_i_k cannot be empty");

            if !valid {
                return Err(KeygenError::FailedFelmanVerify);
            }
        }

        let public_key = self.state.big_f_vec[0];
        let s_i: Scalar = f_i_vals.iter().sum();
        let big_s_i = ProjectivePoint::GENERATOR * s_i;

        let mut transcript = Transcript::new_dlog_proof(
            &self.state.final_session_id,
            self.params.party_id,
            DLOG_PROOF2_LABEL,
            DKG_LABEL,
        );

        let mut rng = OsRng;
        let proof = DLogProof::prove(&s_i, ProjectivePoint::GENERATOR, &mut transcript, &mut rng);
        let senders = self.state.vsot_senders.into_par_iter();

        let (next_senders, enc_vsot_msgs3) = process_vsot_instances(
            senders,
            self.state.other_parties.par_iter(),
            &messages,
            self.params.party_id,
            &self.params.party_pubkeys_list,
            &self.params.encryption_keypair.secret_key,
        )?;

        let msg4_hash = hash_msg4(
            &self.state.final_session_id,
            &public_key,
            &big_s_i,
            &proof,
            &enc_vsot_msgs3,
        );

        let signature = sign_message(&self.params.signing_key, &msg4_hash)?;

        let new_state = R4 {
            final_session_id: self.state.final_session_id,
            vsot_receivers: self.state.vsot_receivers,
            vsot_senders: next_senders,
            public_key,
            s_i,
            rank_list: self.state.rank_list,
            x_i_list: self.state.x_i_list,
            big_f_vec: self.state.big_f_vec,
            other_parties: self.state.other_parties,
        };

        let msg4 = KeygenMsg4 {
            session_id: self.state.final_session_id,
            from_party: self.params.party_id,
            public_key,
            big_s_i,
            dlog_proof: proof,
            enc_vsot_msgs3,
            signature,
        };

        let next_state = KeygenParty {
            params: self.params,
            state: new_state,
        };

        Ok((next_state, msg4))
    }
}

impl Round for KeygenParty<R4> {
    type Input = Vec<KeygenMsg4>;

    type Output = Result<(KeygenParty<R5>, KeygenMsg5), KeygenError>;

    fn process(self, messages: Self::Input) -> Self::Output {
        let messages = validate_input_messages(messages, self.params.n)?;
        messages.par_iter().try_for_each(|msg| {
            let msg4_hash = hash_msg4(
                &self.state.final_session_id,
                &msg.public_key,
                &msg.big_s_i,
                &msg.dlog_proof,
                &msg.enc_vsot_msgs3,
            );

            let verify_key = &self.params.party_pubkeys_list[msg.get_pid()].verify_key;
            verify_signature(&msg4_hash, msg.get_signature(), verify_key)?;

            if self.state.public_key != msg.public_key {
                return Err(KeygenError::PublicKeyMismatch);
            }

            Ok(())
        })?;

        let big_s_list = messages
            .iter()
            .map(|msg| {
                let party_id = msg.get_pid();
                let big_s_i = &msg.big_s_i;
                let dlog_proof = &msg.dlog_proof;

                let mut transcript = Transcript::new_dlog_proof(
                    &self.state.final_session_id,
                    party_id,
                    DLOG_PROOF2_LABEL,
                    DKG_LABEL,
                );

                dlog_proof
                    .verify(big_s_i, ProjectivePoint::GENERATOR, &mut transcript)
                    .then_some(())
                    .ok_or(KeygenError::InvalidDLogProof)?;

                let rank = self.state.rank_list[party_id];
                let x_i = self.state.x_i_list[party_id];
                let coeff_multipliers = polynomial_coeff_multipliers(&x_i, rank, self.params.n);
                let mut expected_point = ProjectivePoint::IDENTITY;
                for (point, coeff) in self.state.big_f_vec.iter().zip(coeff_multipliers) {
                    expected_point += point * &coeff;
                }

                (expected_point == msg.big_s_i)
                    .then_some(())
                    .ok_or(KeygenError::BigSMismatch)?;

                Ok(msg.big_s_i)
            })
            .collect::<Result<Vec<_>, KeygenError>>()?;

        check_secret_recovery(
            &self.state.x_i_list,
            &self.state.rank_list,
            &big_s_list,
            &self.state.public_key,
        )?;

        let receivers = self.state.vsot_receivers.into_par_iter();

        let (new_receivers, enc_vsot_msgs4) = process_vsot_instances(
            receivers,
            self.state.other_parties.par_iter(),
            &messages,
            self.params.party_id,
            &self.params.party_pubkeys_list,
            &self.params.encryption_keypair.secret_key,
        )?;

        let msg5_hash = hash_msg5(&self.state.final_session_id, &enc_vsot_msgs4);

        let signature = sign_message(&self.params.signing_key, &msg5_hash)?;

        let new_state = R5 {
            final_session_id: self.state.final_session_id,
            vsot_receivers: new_receivers,
            vsot_senders: self.state.vsot_senders,
            public_key: self.state.public_key,
            s_i: self.state.s_i,
            rank_list: self.state.rank_list,
            x_i_list: self.state.x_i_list,
            big_s_list,
            other_parties: self.state.other_parties,
        };

        let msg5 = KeygenMsg5 {
            from_party: self.params.party_id,
            session_id: self.state.final_session_id,
            enc_vsot_msgs4,
            signature,
        };

        let next_state = KeygenParty {
            params: self.params,
            state: new_state,
        };

        Ok((next_state, msg5))
    }
}

impl Round for KeygenParty<R5> {
    type Input = Vec<KeygenMsg5>;

    type Output = Result<(KeygenParty<R6>, KeygenMsg6), KeygenError>;

    fn process(self, messages: Self::Input) -> Self::Output {
        let messages = validate_input_messages(messages, self.params.n)?;
        messages.par_iter().try_for_each(|msg| {
            let msg5_hash = hash_msg5(&self.state.final_session_id, &msg.enc_vsot_msgs4);

            let verify_key = &self.params.party_pubkeys_list[msg.get_pid()].verify_key;
            verify_signature(&msg5_hash, msg.get_signature(), verify_key)?;

            Ok::<(), KeygenError>(())
        })?;

        let senders = self.state.vsot_senders.into_par_iter();

        let (vsot_sender_outputs, enc_vsot_msgs5) = process_vsot_instances(
            senders,
            self.state.other_parties.par_iter(),
            &messages,
            self.params.party_id,
            &self.params.party_pubkeys_list,
            &self.params.encryption_keypair.secret_key,
        )?;

        // TODO: BuildPPRF here using sender outputs

        // let (all_but_one_sender_seed, pprf_output) = build_pprf(
        //     self.state.final_session_id,
        //     vsot_sender_outputs,
        //     256,
        //     self.params.soft_spoken_k,
        // );
        // let mut seed_ot_senders = vec![];
        // let enc_pprf_outputs = vsot_sender_outputs
        //     .iter()
        //     .zip(messages)
        //     .map(|(sender_output, message)| {
        //         let (all_but_one_sender_seed, pprf_output) = build_pprf(
        //             &self.state.final_session_id,
        //             sender_output,
        //             256,
        //             self.params.soft_spoken_k,
        //         );
        //         seed_ot_senders.push(all_but_one_sender_seed);
        //         let sender_pubkey =
        //             &self.params.party_pubkeys_list[message.get_pid()].encryption_key;

        //         let sender_party_id = message.get_pid();
        //         // Convert to bytes
        //         // TODO: This is a hack, we should be able to convert to bytes directly
        //         let pprf_output_data = pprf_output.iter().fold(vec![], |mut acc, x| {
        //             acc.extend_from_slice(&x.to_bytes().unwrap());
        //             acc
        //         });
        //         let enc_pprf_output = encrypt_data(
        //             pprf_output_data,
        //             sender_pubkey,
        //             &self.params.encryption_keypair.secret_key,
        //             sender_party_id,
        //             self.params.party_id,
        //         )?;

        //         Ok(enc_pprf_output)
        //     })
        //     .collect::<Result<Vec<EncryptedData>, sl_mpc_mate::nacl::Error>>()?;

        // TODO: COME BACK TO THIS
        // let seed_i_j_list = vec![];
        // let enc_seed_i_j_list = vec![];

        let msg6_hash = hash_msg5(&self.state.final_session_id, &enc_vsot_msgs5);

        let signature = sign_message(&self.params.signing_key, &msg6_hash)?;

        let msg6 = KeygenMsg6 {
            from_party: self.params.party_id,
            session_id: self.state.final_session_id,
            enc_vsot_msgs5,
            signature,
        };

        let next_state = KeygenParty {
            params: self.params,
            state: R6 {
                final_session_id: self.state.final_session_id,
                vsot_receivers: self.state.vsot_receivers,
                vsot_sender_outputs,
                public_key: self.state.public_key,
                s_i: self.state.s_i,
                rank_list: self.state.rank_list,
                x_i_list: self.state.x_i_list,
                big_s_list: self.state.big_s_list,
                other_parties: self.state.other_parties,
            },
        };

        Ok((next_state, msg6))
    }
}

impl Round for KeygenParty<R6> {
    type Input = Vec<KeygenMsg6>;

    type Output = Result<(Keyshare, KeyGenCompleteMsg), KeygenError>;

    fn process(self, messages: Self::Input) -> Self::Output {
        let messages = validate_input_messages(messages, self.params.n)?;
        messages.par_iter().try_for_each(|msg| {
            let msg6_hash = hash_msg5(&self.state.final_session_id, &msg.enc_vsot_msgs5);

            let verify_key = &self.params.party_pubkeys_list[msg.get_pid()].verify_key;
            verify_signature(&msg6_hash, msg.get_signature(), verify_key)?;

            Ok::<(), KeygenError>(())
        })?;
        let receivers = self.state.vsot_receivers.into_par_iter();
        let sender_ids = self.state.other_parties.par_iter();

        let seed_ot_receivers = receivers
            .zip(sender_ids)
            .map(|(receiver, sender_party_id)| {
                // idx is the position of current parties receiver for each sender.
                let message = &messages[*sender_party_id];
                let enc_vsot_msg = message.get_vsot_msg(self.params.party_id);
                let sender_public_key =
                    &self.params.party_pubkeys_list[*sender_party_id].encryption_key;
                let vsot_msg = enc_vsot_msg.enc_data.decrypt_to_vec(
                    &enc_vsot_msg.nonce,
                    sender_public_key,
                    &self.params.encryption_keypair.secret_key,
                )?;
                let vsot_msg =
                    VSOTMsg5::from_bytes(&vsot_msg).ok_or(KeygenError::InvalidVSOTPlaintext)?;
                let receiver_output = receiver.process(vsot_msg)?;
                Ok::<_, KeygenError>(receiver_output)
            })
            .collect::<Result<Vec<_>, KeygenError>>()?;

        let keyshare = Keyshare {
            public_key: self.state.public_key,
            x_i: self.state.x_i_list[self.params.party_id],
            big_s_list: self.state.big_s_list,
            s_i: self.state.s_i,
            rank_list: self.state.rank_list,
            x_i_list: self.state.x_i_list,
            party_id: self.params.party_id,
            threshold: self.params.t,
            total_parties: self.params.n,
            rank: self.params.rank,
            seed_ot_receivers,
            seed_ot_senders: self.state.vsot_sender_outputs,
        };

        let complete_msg = KeyGenCompleteMsg {
            from_party: self.params.party_id,
            public_key: keyshare.public_key.to_affine(),
        };

        Ok((keyshare, complete_msg))
    }
}

fn hash_commitment(
    session_id: SessionId,
    party_id: usize,
    rank: usize,
    x_i: NonZeroScalar,
    big_f_i_vec: &GroupPolynomial<Secp256k1>,
    r_i: &[u8; 32],
) -> HashBytes {
    let mut hasher = Sha256::new();

    hasher.update(b"SilenceLaboratories-Keygen-Commitment");
    hasher.update(session_id.as_ref());
    hasher.update((party_id as u64).to_be_bytes());
    hasher.update((rank as u64).to_be_bytes());
    hasher.update(x_i.to_bytes());

    for point in big_f_i_vec.iter() {
        hasher.update(point.to_bytes());
    }

    hasher.update(r_i);

    HashBytes(hasher.finalize().into())
}

fn get_vsot_session_id(from_party: usize, to_party: usize, session_id: &SessionId) -> SessionId {
    let mut hasher = Sha256::new();

    hasher.update(DKG_LABEL);
    hasher.update(session_id.as_ref());
    hasher.update(b"from_party");
    hasher.update((from_party as u64).to_be_bytes());
    hasher.update(b"to_party");
    hasher.update((to_party as u64).to_be_bytes());
    hasher.update(b"vsot_session_id");

    SessionId(hasher.finalize().into())
}

fn verfiy_dlog_proofs(
    proofs: &[DLogProof],
    points: &[ProjectivePoint],
    transcript: &mut Transcript,
) -> Result<(), KeygenError> {
    for (proof, point) in proofs.iter().zip(points) {
        proof
            .verify(point, ProjectivePoint::GENERATOR, transcript)
            .then_some(())
            .ok_or(KeygenError::InvalidDLogProof)?;
    }

    Ok(())
}

fn hash_msg1(
    session_id: &SessionId,
    rank: usize,
    x_i: &NonZeroScalar,
    commitment: &HashBytes,
) -> HashBytes {
    get_hash(&[
        DKG_LABEL,
        b"KeygenMsg1",
        session_id.as_ref(),
        (rank as u64).to_be_bytes().as_ref(),
        x_i.to_bytes().as_ref(),
        commitment.as_ref(),
    ])
    .into()
}
fn hash_msg2(
    session_id: &SessionId,
    commitment_i_list: &[HashBytes],
    big_f_i_vec: &[ProjectivePoint],
    r_i: &[u8; 32],
    dlog_proofs: &[DLogProof],
    enc_vsot_msg1: &[EncryptedData],
) -> HashBytes {
    let mut hasher = Sha256::new();

    hasher.update(DKG_LABEL);
    hasher.update(b"KeygenMsg2");
    hasher.update(session_id.as_ref());

    for commitment in commitment_i_list {
        hasher.update(commitment.as_ref());
    }

    for point in big_f_i_vec {
        hasher.update(point.to_bytes());
    }

    hasher.update(r_i);

    for proof in dlog_proofs {
        hasher.update(proof.to_bytes().unwrap());
    }

    for enc_msg1 in enc_vsot_msg1 {
        hasher.update(enc_msg1.to_bytes().unwrap());
    }

    HashBytes(hasher.finalize().into())
}

fn hash_msg3(
    session_id: &SessionId,
    big_f_i_vec: &[ProjectivePoint],
    enc_d_i_vec: &[EncryptedData],
    enc_vsot_msg2: &[EncryptedData],
) -> HashBytes {
    let mut hasher = Sha256::new();

    hasher.update(DKG_LABEL);
    hasher.update(b"KeygenMsg3");
    hasher.update(session_id.as_ref());

    for point in big_f_i_vec {
        hasher.update(point.to_bytes());
    }

    for data in enc_d_i_vec {
        hasher.update(data.to_bytes().unwrap());
    }

    for data in enc_vsot_msg2 {
        hasher.update(data.to_bytes().unwrap());
    }

    HashBytes(hasher.finalize().into())
}

fn hash_msg4(
    session_id: &SessionId,
    public_key: &ProjectivePoint,
    big_s_i: &ProjectivePoint,
    proof: &DLogProof,
    enc_vsot_msgs3: &[EncryptedData],
) -> HashBytes {
    let mut hasher = Sha256::new();

    hasher.update(DKG_LABEL);
    hasher.update(b"KeygenMsg4");
    hasher.update(session_id.as_ref());
    hasher.update(public_key.to_bytes());
    hasher.update(big_s_i.to_bytes());
    hasher.update(proof.to_bytes().unwrap());

    for data in enc_vsot_msgs3 {
        hasher.update(data.to_bytes().unwrap());
    }

    HashBytes(hasher.finalize().into())
}

fn hash_msg5(session_id: &SessionId, enc_vsot_msgs4: &[EncryptedData]) -> HashBytes {
    let mut hasher = Sha256::new();

    hasher.update(DKG_LABEL);
    hasher.update(b"KeygenMsg5");
    hasher.update(session_id.as_ref());

    for data in enc_vsot_msgs4 {
        hasher.update(data.to_bytes().unwrap());
    }

    HashBytes(hasher.finalize().into())
}
fn validate_input_messages<M: HasFromParty>(
    mut messages: Vec<M>,
    n: usize,
) -> Result<Vec<M>, KeygenError> {
    // TODO: should we check session id too?
    if messages.len() != n {
        return Err(KeygenError::InvalidMessageLength);
    }

    messages.sort_by_key(|msg| msg.get_pid());

    messages
        .iter()
        .enumerate()
        .all(|(pid, msg)| msg.get_pid() == pid)
        .then_some(messages)
        .ok_or(KeygenError::InvalidParticipantSet)
}

/// Rust voodoo to process all the receivers of a party
fn process_vsot_instances<CM, NM, M, VSOT, VSOTNEXT>(
    vsot_instances: rayon::vec::IntoIter<VSOT>,
    other_party_ids: rayon::slice::Iter<usize>,
    messages: &[M],
    party_id: usize,
    party_pubkeys_list: &[KeygenPartyPublicKeys],
    secret_key: &sl_mpc_mate::nacl::BoxPrivKey,
) -> Result<(Vec<VSOTNEXT>, Vec<EncryptedData>), KeygenError>
where
    VSOT: Round<Input = CM, Output = Result<(VSOTNEXT, NM), VSOTError>> + Send,
    CM: PersistentObject,
    VSOTNEXT: Send,
    M: HasVsotMsg + Sync,
    NM: PersistentObject,
{
    let (next_receivers, enc_vsot_msgs): (Vec<VSOTNEXT>, Vec<EncryptedData>) = vsot_instances
        .zip(other_party_ids)
        .map(|(receiver, sender_party_id)| {
            // idx is the position of current parties receiver for each sender.
            let message = &messages[*sender_party_id];

            let enc_vsot_msg = message.get_vsot_msg(party_id);
            let sender_public_key = &party_pubkeys_list[*sender_party_id].encryption_key;
            let vsot_msg = enc_vsot_msg.enc_data.decrypt_to_vec(
                &enc_vsot_msg.nonce,
                sender_public_key,
                secret_key,
            )?;

            let vsot_msg = CM::from_bytes(&vsot_msg).ok_or(KeygenError::InvalidVSOTPlaintext)?;
            let (new_receiver, vsot_msg) = receiver.process(vsot_msg)?;

            let enc_vsot_msg = encrypt_data(
                vsot_msg.to_bytes().unwrap(),
                sender_public_key,
                secret_key,
                *sender_party_id,
                party_id,
            )?;

            Ok::<_, KeygenError>((new_receiver, enc_vsot_msg))
        })
        .collect::<Result<Vec<_>, KeygenError>>()?
        .into_iter()
        .unzip();

    Ok((next_receivers, enc_vsot_msgs))
}

/// Rust voodoo to process all the senders of a party
fn process_senders<CR, CM, NR, NM, M>(
    senders: rayon::vec::IntoIter<VSOTSender<CR>>,
    receiver_ids: rayon::iter::Take<rayon::range::Iter<usize>>,
    messages: &[M],
    party_id: usize,
    party_pubkeys_list: &[KeygenPartyPublicKeys],
    secret_key: &BoxPrivKey,
) -> Result<(Vec<NR>, Vec<EncryptedData>), KeygenError>
where
    VSOTSender<CR>: Round<Input = CM, Output = Result<(NR, NM), VSOTError>>,
    CM: PersistentObject,
    CR: Send,
    NR: Send,
    NM: PersistentObject,
    M: Debug + Sync + HasVsotMsg,
{
    let (next_senders, enc_vsot_msgs): (Vec<NR>, Vec<EncryptedData>) = senders
        .zip(receiver_ids)
        .map(|(sender, receiver_party_id)| {
            // TODO: Abstract common code out as functions to reduce monomorphization size.
            // idx is the position of current parties receiver for each sender.
            let message = &messages[receiver_party_id];

            let enc_vsot_msg = message.get_vsot_msg(party_id - receiver_party_id - 1);
            let nonce = &enc_vsot_msg.nonce;
            let sender_public_key = &party_pubkeys_list[receiver_party_id].encryption_key;

            let vsot_msg =
                enc_vsot_msg
                    .enc_data
                    .decrypt_to_vec(nonce, sender_public_key, secret_key)?;

            let vsot_msg = CM::from_bytes(&vsot_msg).ok_or(KeygenError::InvalidVSOTPlaintext)?;

            let (new_receiver, vsot_msg) = sender.process(vsot_msg)?;

            let enc_vsot_msg = encrypt_data(
                vsot_msg.to_bytes().unwrap(),
                sender_public_key,
                secret_key,
                receiver_party_id,
                party_id,
            )?;

            Ok::<_, KeygenError>((new_receiver, enc_vsot_msg))
        })
        .collect::<Result<Vec<_>, KeygenError>>()?
        .into_iter()
        .unzip();

    Ok((next_senders, enc_vsot_msgs))
}

fn check_secret_recovery(
    x_i_list: &[NonZeroScalar],
    rank_list: &[usize],
    big_s_list: &[ProjectivePoint],
    public_key: &ProjectivePoint,
) -> Result<(), KeygenError> {
    // Checking if secret recovery works
    let mut party_params_list = x_i_list
        .iter()
        .zip(rank_list)
        .zip(big_s_list)
        .collect::<Vec<((&NonZeroScalar, &usize), &ProjectivePoint)>>();

    party_params_list.sort_by_key(|((_, n_i), _)| *n_i);

    let params = party_params_list
        .iter()
        .map(|((x_i, n_i), _)| (x_i.to_owned().to_owned(), **n_i))
        .collect::<Vec<_>>();

    let sorted_big_s_list = party_params_list
        .iter()
        .map(|((_, _), big_s_i)| *big_s_i)
        .collect::<Vec<_>>();

    let betta_vector = birkhoff_coeffs(params.as_slice());
    let public_key_point = sorted_big_s_list
        .iter()
        .zip(betta_vector.iter())
        .fold(ProjectivePoint::IDENTITY, |acc, (point, betta_i)| {
            acc + *point * betta_i
        });

    (public_key == &public_key_point)
        .then_some(())
        .ok_or(KeygenError::PublicKeyMismatch)
}
