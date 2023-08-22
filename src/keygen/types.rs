use k256::Secp256k1;
use rand::{CryptoRng, Rng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use sl_mpc_mate::{
    math::Polynomial,
    message::InvalidMessage,
    nacl::{crypto_sign_seed_keypair, KeyPair, SignPrivKey, SignPubkey},
    traits::PersistentObject,
    bincode::error::{EncodeError, DecodeError},
};

use sl_oblivious::vsot;

use crate::setup::keygen::ValidatedSetup;

/// Parameters for the keygen protocol. Constant across all rounds.
pub struct KeygenParams {
    /// Instance of RNG for entire execution of the protocol
    pub rng: ChaCha20Rng,

    ///
    pub setup: ValidatedSetup,

    // Encryption keypair
    // pub(crate) encryption_keypair: sl_mpc_mate::message::ReusableSecret,
    // pub(crate) polynomial: Polynomial<Secp256k1>, // u_i_k in dkg.py
    // pub(crate) r_i: [u8; 32],
}

/// Set of a party's keys that can be reused
/// for independent execution of DKG
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PartyKeys {
    /// Public key for verifying signatures.
    pub verify_key: SignPubkey,

    #[serde(with = "serde_arrays")]
    pub(crate) signing_key: SignPrivKey,

    pub(crate) encryption_keypair: KeyPair,
}

impl PersistentObject for PartyKeys {}

/// Datatype for all of the participants public keys (verification, encryption)
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct PartyPublicKeys {
    /// The public key for signature verification.
    pub verify_key: SignPubkey,

    /// Public key for encryption
    pub encryption_key: sl_mpc_mate::nacl::BoxPubkey,
}

impl PersistentObject for PartyPublicKeys {}

impl PartyKeys {
    /// Create a new set of party keys
    #[allow(clippy::new_without_default)]
    pub fn new(rng: &mut (impl CryptoRng + Rng)) -> Self {
        // TODO: Is rng needed here?
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);

        let (verify_key, signing_key) = crypto_sign_seed_keypair(&seed);

        rng.fill_bytes(&mut seed);

        let encryption_keypair = KeyPair::from_seed(&seed);

        Self {
            signing_key,
            verify_key,
            encryption_keypair,
        }
    }

    /// Extract public keys
    pub fn public_keys(&self) -> PartyPublicKeys {
        PartyPublicKeys {
            verify_key: self.verify_key,
            encryption_key: self.encryption_keypair.public_key.clone(),
        }
    }
}

#[derive(Debug, Error)]
/// Distributed key generation errors
pub enum KeygenError {
    // /// Invalid Pid value
    // #[error("Invalid pid, it must be in the range [1,n]")]
    // InvalidPid,

    // /// Invalid threshold t value
    // #[error("Invalid t, must be less than n")]
    // InvalidT,

    // /// Invalid hierarchical level n_i value
    // #[error("Invalid hierarchical level n_i, must be in the range [0,t-1]")]
    // InvalidLevel,

    /// error while serializing or deserializing
    #[error("Error while deserializing message")]
    InvalidMessage,

    // /// Invalid length of messages list
    // #[error("Provided messages list has invalid length")]
    // InvalidMessageLength,

    /// Given message list pid's do not match with the expected pid's.
    #[error("Incorrect participant pid's in the message list")]
    InvalidParticipantSet,

    // /// Libsodium errors (signing, verifying, encryption etc.)
    // #[error("Libsodium error: {0})")]
    // LibsodiumError(#[from] sl_mpc_mate::nacl::Error),

    // /// Current party's session id is not in the session id list
    // #[error("Invalid session id of the current party in session id list")]
    // InvalidSelfSessionId,

    // /// Current party's party id is not in the party id list
    // #[error("Invalid party id of the current party in party id list")]
    // InvalidSelfPartyId,

    /// VSOT errors
    #[error("VSOT error: {0}")]
    VSOTError(#[from] vsot::VSOTError),

    /// Invalid commitment hash
    #[error("Invalid commitment hash")]
    InvalidCommitmentHash,

    #[error("Invalid DLog proof")]
    /// Invalid DLog proof
    InvalidDLogProof,

    /// Decrypted VSOT message cannot be deserialized
    #[error("Decrypted VSOT message cannot be deserialized")]
    InvalidVSOTPlaintext,

    /// Big F vec mismatch
    #[error("Big F vec mismatch")]
    BigFVecMismatch,

    /// Decrypted d_i scalar cannot be deserialized
    #[error("Decrypted d_i scalar cannot be deserialized")]
    InvalidDiPlaintext,

    /// Invalid length of decrypted f_i values
    #[error("Invalid length decrypted f_i values")]
    InvalidFiLen,

    /// Failed felman verify
    #[error("Failed felman verify")]
    FailedFelmanVerify,

    /// Public key mismatch between the message and the party
    #[error("Public key mismatch between the message and the party")]
    PublicKeyMismatch,

    /// Big S value mismatch
    #[error("Big S value mismatch")]
    BigSMismatch,

    /// Invalid PPRF plaintext
    #[error("Invalid PPRF plaintext")]
    InvalidPPRFPlaintext,

    #[error("PPRF error")]
    /// PPRF error
    PPRFError(&'static str),

    /// Invalid seed
    #[error("Invalid Seed")]
    InvalidSeed,

    /// We have internal state as pairs of (PairtyID, datum)
    /// This error is returned when we unable to find a datum
    /// corresponding to the party-id
    #[error("Missing piece of state")]
    InvalidParty(u8),
}

impl From<InvalidMessage> for KeygenError {
    fn from(_err: InvalidMessage) -> Self {
        KeygenError::InvalidMessage
    }
}

impl From<EncodeError> for KeygenError {
    fn from(_err: EncodeError) -> Self {
        KeygenError::InvalidMessage
    }
}

impl From<DecodeError> for KeygenError {
    fn from(_err: DecodeError) -> Self {
        KeygenError::InvalidMessage
    }
}

#[cfg(test)]
mod tests {
    use k256::{
        elliptic_curve::{scalar::FromUintUnchecked, Curve},
        ProjectivePoint, Scalar, Secp256k1, U256,
    };
    use sl_mpc_mate::math::{GroupPolynomial, Polynomial};

    #[test]
    fn test_derivative_large() {
        // order of the curve
        let order = Secp256k1::ORDER;
        // f(x) = 1 + 2x + (p-1)x^2
        // p is the curve order
        let u_i_k = vec![
            Scalar::from(1_u64),
            Scalar::from(2_u64),
            Scalar::from_uint_unchecked(order.wrapping_sub(&U256::ONE)),
        ];

        // f'(x) = 2 + 2(p-1)x
        // f'(2) = (4p-2) mod p => p - 2
        let poly = Polynomial::<Secp256k1>::new(u_i_k);
        let n = 1;

        let result = poly.derivative_at(n, &Scalar::from(2_u64));

        assert_eq!(
            result,
            Scalar::from_uint_unchecked(order.wrapping_sub(&U256::from(2_u64)))
        );
    }

    #[test]
    fn test_derivative_normal() {
        // f(x) = 1 + 2x + 3x^2 + 4x^3
        let u_i_k = vec![
            Scalar::from(1_u64),
            Scalar::from(2_u64),
            Scalar::from(3_u64),
            Scalar::from(4_u64),
        ];

        let poly = Polynomial::<Secp256k1>::new(u_i_k);

        // f''(x) = 6 + 24x
        let n = 2;
        // f''(2) = 6 + 24(2) = 54
        let result = poly.derivative_at(n, &Scalar::from(2_u64));

        assert_eq!(result, Scalar::from(54_u64));
    }

    #[test]
    fn test_derivative_coeffs() {
        // f(x) = 1 + 2x + 3x^2 + 4x^3
        let g = ProjectivePoint::GENERATOR;
        let u_i_k = vec![
            (g * Scalar::from(1_u64)).into(),
            (g * Scalar::from(2_u64)).into(),
            (g * Scalar::from(3_u64)).into(),
            (g * Scalar::from(4_u64)).into(),
        ];

        let poly = GroupPolynomial::<Secp256k1>::new(u_i_k);

        // f''(x) = 6 + 24x
        let n = 2;
        let coeffs = poly.derivative_coeffs(n);

        assert_eq!(coeffs.len(), 2);
        assert_eq!(coeffs[0], g * Scalar::from(6_u64));
        assert_eq!(coeffs[1], g * Scalar::from(24_u64));

        // f'(x) = 2 + 6x + 12x^2
        let coeffs = poly.derivative_coeffs(1);

        assert_eq!(coeffs.len(), 3);
        assert_eq!(coeffs[0], g * Scalar::from(2_u64));
        assert_eq!(coeffs[1], g * Scalar::from(6_u64));
        assert_eq!(coeffs[2], g * Scalar::from(12_u64));
    }
}
