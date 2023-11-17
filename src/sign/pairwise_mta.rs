use k256::{
    elliptic_curve::{
        bigint::Encoding,
        generic_array::GenericArray,
        ops::Reduce,
        subtle::{Choice, ConditionallySelectable, ConstantTimeEq},
    },
    schnorr::CryptoRngCore,
    Scalar, U256,
};

use zeroize::{Zeroize, ZeroizeOnDrop};

use sl_mpc_mate::{message::*, SessionId};

use sl_oblivious::{
    soft_spoken::{ReceiverOTSeed, SenderOTSeed},
    soft_spoken_mod::{
        RecR0, RecR1, Round1Output, Round2Output, SoftSpokenOTRec, SoftSpokenOTSender,
        COT_BLOCK_SIZE_BYTES, ETA, KAPPA, KAPPA_BYTES, KAPPA_DIV_SOFT_SPOKEN_K, L,
    },
    utils::{ExtractBit, Hasher},
};

fn generate_gadget_vec() -> Box<[Scalar; L]> {
    let mut gadget_vec = [Scalar::ZERO; L];

    gadget_vec
        .iter_mut()
        .enumerate()
        .take(KAPPA)
        .for_each(|(i, g)| {
            *g = Scalar::reduce(U256::ONE << i);
        });

    let mut h = Hasher::new();
    h.update(b"SL-GADGET-VECTOR");

    gadget_vec
        .iter_mut()
        .enumerate()
        .take(L)
        .skip(KAPPA)
        .for_each(|(i, g)| {
            h.update((i as u16).to_be_bytes().as_ref());
            let digest = h.finalize();
            let digest = GenericArray::from_slice(digest.as_bytes());
            *g = Reduce::<U256>::reduce_bytes(digest);
        });

    Box::new(gadget_vec)
}

///
pub struct PairwiseMtaRec<T> {
    session_id: SessionId,
    state: T,
}

/// Initial state of the Pairwise MTA receiver
///
// TODO: Standard names for state
pub struct MtaRecR0 {
    cot_receiver: SoftSpokenOTRec<RecR0>,
    gadget_vector: Box<[Scalar; L]>,
    output: [u8; COT_BLOCK_SIZE_BYTES],
}

/// State of Mta receiver after processing Round 1 output
pub struct MtaRecR1 {
    cot_receiver: SoftSpokenOTRec<RecR1>,
    gadget_vector: Box<[Scalar; L]>,
    omega: [u8; COT_BLOCK_SIZE_BYTES],
    temp_digest: [u8; 32],
}

///
impl PairwiseMtaRec<MtaRecR0> {
    /// Create a new Pairwise MTA receiver
    pub fn new<R: CryptoRngCore>(
        session_id: SessionId,
        seed_ot_results: &SenderOTSeed,
        rng: &mut R,
    ) -> Self {
        let cot_receiver = SoftSpokenOTRec::new(session_id, seed_ot_results, rng);
        let gadget_vector = generate_gadget_vec();
        let mut output = [0u8; COT_BLOCK_SIZE_BYTES];

        rng.fill_bytes(&mut output[KAPPA_BYTES..]);

        Self {
            session_id,
            state: MtaRecR0 {
                cot_receiver,
                gadget_vector,
                output,
            },
        }
    }

    fn encode(&self, beta: &Scalar) -> [u8; COT_BLOCK_SIZE_BYTES] {
        let mut beta_minus_dot_product_bytes = beta.to_owned();

        for i in KAPPA..L {
            let i_bit = self.state.output.extract_bit(i);
            let option_0 = &beta_minus_dot_product_bytes;
            let option_1 = option_0 - &self.state.gadget_vector[i];
            let chosen = Scalar::conditional_select(option_0, &option_1, Choice::from(i_bit as u8));
            beta_minus_dot_product_bytes = chosen;
        }

        let mut beta_bytes = beta_minus_dot_product_bytes.to_bytes();
        beta_bytes.reverse();

        let mut new_output = self.state.output;

        new_output[..KAPPA_BYTES].copy_from_slice(&beta_bytes);

        new_output
    }
}

impl PairwiseMtaRec<MtaRecR0> {
    ///
    pub fn process(self, beta: &Scalar) -> (PairwiseMtaRec<MtaRecR1>, Round1Output) {
        let omega = self.encode(beta);

        let (cot_receiver, round1_output) = self.state.cot_receiver.process(&omega);

        let mut hasher = Hasher::new();
        hasher.update(b"SL-DKLS-MTA");
        hasher.update(self.session_id.as_ref());

        for i in 0..KAPPA_DIV_SOFT_SPOKEN_K {
            hasher.update(format!("row_{}_of_matrix_u", i).as_bytes());
            hasher.update(round1_output.u[i].as_ref());
        }

        hasher.update(b"w_prime");
        hasher.update(round1_output.w_prime.as_ref());
        hasher.update(b"v_prime");
        for elem in &round1_output.v_prime {
            hasher.update(elem.as_ref());
        }

        let temp_digest: [u8; 32] = hasher.finalize().into();

        let next = PairwiseMtaRec {
            session_id: self.session_id,
            state: MtaRecR1 {
                omega,
                temp_digest,
                cot_receiver,
                gadget_vector: self.state.gadget_vector,
            },
        };

        (next, round1_output)
    }
}

impl PairwiseMtaRec<MtaRecR1> {
    ///
    pub fn process(self, round2_output: &MtaRound2Output) -> Result<[Scalar; 2], &'static str> {
        let cot_additive_shares = self
            .state
            .cot_receiver
            .process(&round2_output.cot_round_2_output);

        let mut chi = [Scalar::ZERO; 2];

        let mut h = Hasher::new();

        h.update(self.state.temp_digest.as_ref());

        for (j, scalars) in round2_output.cot_round_2_output.tau.iter().enumerate() {
            for (k, b) in scalars.iter().enumerate() {
                h.update(format!("row_{}_{}_of_tau", j, k).as_bytes());
                h.update(&b.to_bytes());
            }
        }

        chi.iter_mut().enumerate().for_each(|(k, chi_k)| {
            h.update(format!("chi_{}", k).as_bytes());
            let digest: [u8; 32] = h.finalize().into();
            *chi_k = Scalar::reduce(U256::from_be_slice(&digest));
        });

        let mut output_additive_shares = [Scalar::ZERO; 2];

        let mut r_hash = Hasher::new();
        r_hash.update(b"SL-DKLS-MTA");
        r_hash.update(self.session_id.as_ref());
        r_hash.update(b"r_list");

        for j in 0..ETA {
            let sum_chi_mul_tb = cot_additive_shares[j][0]
                + chi[0] * cot_additive_shares[j][1]
                + chi[1] * cot_additive_shares[j][2];

            // let mut value_to_hash = -sum_chi_mul_tb;
            let j_bit = self.state.omega.extract_bit(j);
            let option0 = -sum_chi_mul_tb;
            let option1 = option0 + *round2_output.u;

            let value_to_hash =
                Scalar::conditional_select(&option0, &option1, Choice::from(j_bit as u8));

            r_hash.update(value_to_hash.to_bytes().as_ref());

            for (i, share) in output_additive_shares.iter_mut().enumerate() {
                *share += self.state.gadget_vector[j] * cot_additive_shares[j][i];
            }
        }

        let r_hash_digest: [u8; 32] = r_hash.finalize().into();

        if round2_output.r.ct_ne(&r_hash_digest).into() {
            Err("Consistency check failed")
        } else {
            Ok(output_additive_shares)
        }
    }
}

///
pub struct PairwiseMtaSender<T> {
    session_id: SessionId,
    gadget_vec: Box<[Scalar; L]>,
    state: T,
}

///
pub struct MtaSendR0 {
    a_hat: Scalar,
    cot_sender: SoftSpokenOTSender,
}

///
impl PairwiseMtaSender<MtaSendR0> {
    ///
    pub fn new<R: CryptoRngCore>(
        session_id: SessionId,
        seed_ot_results: &ReceiverOTSeed,
        rng: &mut R,
    ) -> Self {
        // TODO: Remove clone?
        let cot_sender = SoftSpokenOTSender::new(session_id, seed_ot_results.clone());
        let gadget_vec = generate_gadget_vec();
        let a_hat = Scalar::generate_biased(rng);
        Self {
            // seed_ot_results: seed_ot_results.clone(),
            session_id,
            gadget_vec,
            state: MtaSendR0 { a_hat, cot_sender },
        }
    }
}

impl PairwiseMtaSender<MtaSendR0> {
    ///
    pub fn process(
        self,
        alpha1: Scalar,
        alpha2: Scalar,
        round1_output: &Round1Output,
    ) -> ([Scalar; 2], MtaRound2Output) {
        let mut alice_input = [[Scalar::ZERO; 3]; ETA];

        alice_input.iter_mut().for_each(|input| {
            input[0] = alpha1;
            input[1] = alpha2;
            input[2] = self.state.a_hat;
        });

        let (cot_sender_shares, round2_output) = self
            .state
            .cot_sender
            .process((&round1_output, &alice_input))
            .expect("error while processing soft_spoken ot message round 1");

        let mut hasher = Hasher::new();
        hasher.update(b"SL-DKLS-MTA");
        hasher.update(self.session_id.as_ref());
        for i in 0..KAPPA_DIV_SOFT_SPOKEN_K {
            hasher.update(format!("row_{}_of_matrix_u", i).as_bytes());
            hasher.update(round1_output.u[i].as_ref());
        }

        hasher.update(b"w_prime");
        hasher.update(round1_output.w_prime.as_ref());
        hasher.update(b"v_prime");
        for elem in round1_output.v_prime {
            hasher.update(elem.as_ref());
        }

        let temp_digest: [u8; 32] = hasher.finalize().into();
        let mut chi = [Scalar::ZERO; 2];

        hasher.reset();
        hasher.update(&temp_digest);
        for (j, scalars) in round2_output.tau.iter().enumerate() {
            for (k, b) in scalars.iter().enumerate() {
                hasher.update(format!("row_{}_{}_of_tau", j, k).as_bytes());
                hasher.update(&b.to_bytes());
            }
        }

        chi.iter_mut().enumerate().for_each(|(k, chi_k)| {
            hasher.update(format!("chi_{}", k).as_bytes());
            let digest: [u8; 32] = hasher.finalize().into();
            *chi_k = Scalar::reduce(U256::from_be_bytes(digest));
        });

        let mut sender_additive_shares = [Scalar::ZERO; 2];

        hasher.reset();

        hasher.update(b"SL-DKLS-MTA");
        hasher.update(self.session_id.as_ref());
        hasher.update(b"r_list");

        for j in 0..ETA {
            let mut r_j = cot_sender_shares[j][0];
            r_j += chi[0] * cot_sender_shares[j][1];
            r_j += chi[1] * cot_sender_shares[j][2];
            hasher.update(r_j.to_bytes().as_ref());

            sender_additive_shares
                .iter_mut()
                .enumerate()
                .for_each(|(i, share)| *share += self.gadget_vec[j] * cot_sender_shares[j][i])
        }

        let u = alpha1 + chi[0] * alpha2 + chi[1] * self.state.a_hat;
        let r: [u8; 32] = hasher.finalize().into();

        let output = MtaRound2Output {
            r,
            cot_round_2_output: round2_output,
            u: Opaque::from(u),
        };

        (sender_additive_shares, output)
    }
}

/// Round 2 output in Pairwise Mta protocol
#[derive(Debug, bincode::Encode, bincode::Decode, Zeroize, ZeroizeOnDrop)]
pub struct MtaRound2Output {
    cot_round_2_output: Box<Round2Output>,
    r: [u8; 32],
    u: Opaque<Scalar, PF>,
}

#[cfg(test)]
mod tests {
    use super::*;

    use sl_mpc_mate::SessionId;
    use sl_oblivious::soft_spoken_mod::generate_all_but_one_seed_ot;

    use super::{PairwiseMtaRec, PairwiseMtaSender};

    #[test]
    fn test_pairwise() {
        let mut rng = rand::thread_rng();

        let (sender_ot_seed, receiver_ot_seed) = generate_all_but_one_seed_ot(&mut rng);

        let session_id = SessionId::random(&mut rng);

        let sender = PairwiseMtaSender::new(session_id, &receiver_ot_seed, &mut rng);

        let receiver = PairwiseMtaRec::new(session_id, &sender_ot_seed, &mut rng);

        let (alpha1, alpha2, beta) = (
            Scalar::generate_biased(&mut rng),
            Scalar::generate_biased(&mut rng),
            Scalar::generate_biased(&mut rng),
        );

        let (receiver, round1_output) = receiver.process(&beta);

        let (sender_shares, round2_output) = sender.process(alpha1, alpha2, &round1_output);

        let receiver_shares = receiver.process(&round2_output).unwrap();

        let t_0 = receiver_shares[0] + sender_shares[0];
        let t_1 = receiver_shares[1] + sender_shares[1];

        assert_eq!(t_0, alpha1 * beta);
        assert_eq!(t_1, alpha2 * beta);
    }
}
