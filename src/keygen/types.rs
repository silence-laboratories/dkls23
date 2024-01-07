use thiserror::Error;

use sl_mpc_mate::{
    bincode::error::{DecodeError, EncodeError},
    message::InvalidMessage,
};

use crate::BadPartyIndex;

#[derive(Debug, Error)]
/// Distributed key generation errors
pub enum KeygenError {
    /// error while serializing or deserializing or invalid message data length
    #[error("Error while deserializing message or invalid message data length")]
    InvalidMessage,

    /// Invalid commitment hash
    #[error("Invalid commitment hash")]
    InvalidCommitmentHash,

    #[error("Invalid DLog proof")]
    /// Invalid DLog proof
    InvalidDLogProof,

    #[error("Invalid Polynomial Point")]
    /// Invalid Polynomial Point
    InvalidPolynomialPoint,

    #[error("Invalid key refresh")]
    /// Invalid key refresh
    InvalidKeyRefresh,

    /// Not unique x_i values
    #[error("Not unique x_i values")]
    NotUniqueXiValues,

    /// Big F vec mismatch
    #[error("Big F vec mismatch")]
    BigFVecMismatch,

    /// Failed felman verify
    #[error("Failed felman verify")]
    FailedFelmanVerify,

    /// Public key mismatch between the message and the party
    #[error("Public key mismatch between the message and the party")]
    PublicKeyMismatch,

    ///
    #[error("DKG failed before generating PK")]
    NoPublicKey,

    /// Big S value mismatch
    #[error("Big S value mismatch")]
    BigSMismatch,

    #[error("PPRF error")]
    /// PPRF error
    PPRFError(&'static str),

    /// We have internal state as pairs of (PairtyID, datum)
    /// This error is returned when we unable to find a datum
    /// corresponding to the party-id
    #[error("Missing piece of state")]
    InvalidParty,

    ///
    #[error("Missing message")]
    MissingMessage,

    /// We can't a send message
    #[error("Send message")]
    SendMessage,

    /// Some party decided to not participate in the protocol.
    #[error("Abort protocol by party {0}")]
    AbortProtocol(u8),
}

impl From<InvalidMessage> for KeygenError {
    fn from(_err: InvalidMessage) -> Self {
        println!("inv msg {:?}", _err);
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

impl From<BadPartyIndex> for KeygenError {
    fn from(_err: BadPartyIndex) -> Self {
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
        let coeffs = poly.derivative_coeffs(n).collect::<Vec<_>>();

        assert_eq!(coeffs.len(), 2);
        assert_eq!(coeffs[0], g * Scalar::from(6_u64));
        assert_eq!(coeffs[1], g * Scalar::from(24_u64));

        // f'(x) = 2 + 6x + 12x^2
        let coeffs = poly.derivative_coeffs(1).collect::<Vec<_>>();

        assert_eq!(coeffs.len(), 3);
        assert_eq!(coeffs[0], g * Scalar::from(2_u64));
        assert_eq!(coeffs[1], g * Scalar::from(6_u64));
        assert_eq!(coeffs[2], g * Scalar::from(12_u64));
    }
}
