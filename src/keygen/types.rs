// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! Common Types and Error Definitions
//!
//! This module defines the error types and common types used throughout the DKG protocol.
//! It includes error handling for various protocol operations and test utilities for
//! polynomial operations used in the protocol.

use crate::proto::tags::Error;
use sl_mpc_mate::coord::MessageSendError;

/// Error type for distributed key generation protocol operations.
///
/// This enum defines all possible errors that can occur during the execution of the
/// DKG protocol, including message handling, cryptographic operations, and protocol
/// state management.
#[derive(Debug, thiserror::Error)]
pub enum KeygenError {
    /// Error while serializing or deserializing message data, or invalid message length
    #[error("Error while deserializing message or invalid message data length")]
    InvalidMessage,

    /// The commitment hash provided does not match the expected value
    #[error("Invalid commitment hash")]
    InvalidCommitmentHash,

    /// The discrete logarithm proof provided is invalid
    #[error("Invalid DLog proof")]
    InvalidDLogProof,

    /// The polynomial point provided is invalid
    #[error("Invalid Polynomial Point")]
    InvalidPolynomialPoint,

    /// The key refresh operation failed
    #[error("Invalid key refresh")]
    InvalidKeyRefresh,

    /// The quorum change operation failed
    #[error("Invalid Quorum Change")]
    InvalidQuorumChange,

    /// The x_i values provided are not unique
    #[error("Not unique x_i values")]
    NotUniqueXiValues,

    /// The Big F vector does not match the expected value
    #[error("Big F vec mismatch")]
    BigFVecMismatch,

    /// The Feldman verification failed
    #[error("Failed felman verify")]
    FailedFelmanVerify,

    /// The public key in the message does not match the party's public key
    #[error("Public key mismatch between the message and the party")]
    PublicKeyMismatch,

    /// The Big S value does not match the expected value
    #[error("Big S value mismatch")]
    BigSMismatch,

    /// An error occurred in the PPRF (Pseudorandom Function) operation
    #[error("PPRF error")]
    PPRFError(&'static str),

    /// A required message is missing
    #[error("Missing message")]
    MissingMessage,

    /// Failed to send a message
    #[error("Send message")]
    SendMessage,

    /// A party has decided to abort the protocol
    #[error("Abort protocol by party {0}")]
    AbortProtocol(usize),
}

impl From<MessageSendError> for KeygenError {
    fn from(_err: MessageSendError) -> Self {
        KeygenError::SendMessage
    }
}

impl From<Error> for KeygenError {
    fn from(err: Error) -> Self {
        match err {
            Error::Abort(p) => KeygenError::AbortProtocol(p as _),
            Error::Recv => KeygenError::MissingMessage,
            Error::Send => KeygenError::SendMessage,
            Error::InvalidMessage => KeygenError::InvalidMessage,
        }
    }
}

#[cfg(test)]
mod tests {
    use k256::{
        elliptic_curve::{scalar::FromUintUnchecked, Curve},
        ProjectivePoint, Scalar, Secp256k1, U256,
    };
    use sl_mpc_mate::math::{GroupPolynomial, Polynomial};

    /// Test the derivative calculation for large values
    ///
    /// This test verifies that the derivative calculation works correctly with values
    /// close to the curve order. It tests the polynomial f(x) = 1 + 2x + (p-1)x^2
    /// where p is the curve order.
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
        let poly = Polynomial::<ProjectivePoint>::new(u_i_k);
        let n = 1;

        let result = poly.derivative_at(n, &Scalar::from(2_u64));

        assert_eq!(
            result,
            Scalar::from_uint_unchecked(order.wrapping_sub(&U256::from(2_u64)))
        );
    }

    /// Test the derivative calculation for normal values
    ///
    /// This test verifies that the derivative calculation works correctly with normal
    /// polynomial coefficients. It tests the polynomial f(x) = 1 + 2x + 3x^2 + 4x^3.
    #[test]
    fn test_derivative_normal() {
        // f(x) = 1 + 2x + 3x^2 + 4x^3
        let u_i_k = vec![
            Scalar::from(1_u64),
            Scalar::from(2_u64),
            Scalar::from(3_u64),
            Scalar::from(4_u64),
        ];

        let poly = Polynomial::<ProjectivePoint>::new(u_i_k);

        // f''(x) = 6 + 24x
        let n = 2;
        // f''(2) = 6 + 24(2) = 54
        let result = poly.derivative_at(n, &Scalar::from(2_u64));

        assert_eq!(result, Scalar::from(54_u64));
    }

    /// Test the derivative coefficients calculation
    ///
    /// This test verifies that the derivative coefficients are calculated correctly
    /// for both first and second derivatives of a polynomial with group elements.
    #[test]
    fn test_derivative_coeffs() {
        // f(x) = 1 + 2x + 3x^2 + 4x^3
        let g = ProjectivePoint::GENERATOR;
        let u_i_k = vec![
            (g * Scalar::from(1_u64)),
            (g * Scalar::from(2_u64)),
            (g * Scalar::from(3_u64)),
            (g * Scalar::from(4_u64)),
        ];

        let poly = GroupPolynomial::<ProjectivePoint>::new(u_i_k);

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
