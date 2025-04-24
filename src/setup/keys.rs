// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

#![allow(missing_docs)]

use std::sync::Arc;

use signature::{Keypair, SignatureEncoding, Signer, Verifier};

/// A zero-sized type representing an empty signature.
/// This type is used when no actual signature is needed, but the type system
/// requires a signature type. It implements `SignatureEncoding` with an empty
/// byte array representation.
#[derive(Clone)]
pub struct NoSignature;

impl SignatureEncoding for NoSignature {
    type Repr = [u8; 0];
}

impl<'a> TryFrom<&'a [u8]> for NoSignature {
    type Error = ();

    /// Attempts to create a `NoSignature` from a byte slice.
    ///
    /// # Arguments
    /// * `value` - The byte slice to convert
    ///
    /// # Returns
    /// * `Ok(NoSignature)` if the slice is empty
    /// * `Err(())` if the slice contains any bytes
    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        if !value.is_empty() {
            return Err(());
        }
        Ok(NoSignature)
    }
}

impl TryInto<[u8; 0]> for NoSignature {
    type Error = ();

    /// Converts a `NoSignature` into an empty byte array.
    ///
    /// # Returns
    /// * `Ok([0; 0])` - An empty byte array
    fn try_into(self) -> Result<[u8; 0], Self::Error> {
        Ok([0; 0])
    }
}

/// A zero-sized type representing a signing key that produces no signatures.
/// This type is used when no actual signing is needed, but the type system
/// requires a signing key type. It implements `Signer<NoSignature>` and always
/// returns `NoSignature` when signing.
pub struct NoSigningKey;

impl Signer<NoSignature> for NoSigningKey {
    /// Attempts to sign a message, always returning `NoSignature`.
    ///
    /// # Arguments
    /// * `_msg` - The message to sign (ignored)
    ///
    /// # Returns
    /// * `Ok(NoSignature)` - Always succeeds
    fn try_sign(&self, _msg: &[u8]) -> Result<NoSignature, signature::Error> {
        Ok(NoSignature)
    }
}

/// A wrapper around an `Arc<T>` that implements `Signer` for the inner type.
///
/// This allows passing `Arc<SK>` where `SK: Signer` is expected.
///
/// # Type Parameters
/// * `T` - The type being wrapped in an `Arc`
pub struct ArcSigner<T>(pub Arc<T>);

impl<S, T: Signer<S>> Signer<S> for ArcSigner<T> {
    /// Signs a message using the inner signer.
    ///
    /// # Arguments
    /// * `msg` - The message to sign
    ///
    /// # Returns
    /// The signature produced by the inner signer
    fn sign(&self, msg: &[u8]) -> S {
        self.0.sign(msg)
    }

    /// Attempts to sign a message using the inner signer.
    ///
    /// # Arguments
    /// * `msg` - The message to sign
    ///
    /// # Returns
    /// The signature produced by the inner signer, or an error if signing fails
    fn try_sign(&self, msg: &[u8]) -> Result<S, signature::Error> {
        self.0.try_sign(msg)
    }
}

impl<T: Keypair> Keypair for ArcSigner<T> {
    type VerifyingKey = T::VerifyingKey;

    /// Returns the verifying key associated with the inner keypair.
    fn verifying_key(&self) -> Self::VerifyingKey {
        self.0.verifying_key()
    }
}

/// A verifying key that always succeeds verification.
/// This type is used when no actual verification is needed, but the type system
/// requires a verifying key type. It's typically used when secure transport is
/// already in place and message authenticity doesn't need to be verified.
/// The inner `Vec<u8>` is used as an identity ID.
#[derive(Clone)]
pub struct NoVerifyingKey(Vec<u8>);

impl NoVerifyingKey {
    /// Creates a new `NoVerifyingKey` from a participant ID.
    ///
    /// # Arguments
    /// * `id` - The participant ID to use as the identity
    ///
    /// # Returns
    /// A new `NoVerifyingKey` with the ID encoded as big-endian bytes
    pub fn new(id: usize) -> Self {
        NoVerifyingKey((id as u64).to_be_bytes().into())
    }
}

impl<T: Into<Vec<u8>>> From<T> for NoVerifyingKey {
    /// Creates a `NoVerifyingKey` from any type that can be converted into a `Vec<u8>`.
    ///
    /// # Arguments
    /// * `value` - The value to convert into a verifying key
    fn from(value: T) -> Self {
        NoVerifyingKey(value.into())
    }
}

impl AsRef<[u8]> for NoVerifyingKey {
    /// Returns a reference to the inner byte vector.
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Verifier<NoSignature> for NoVerifyingKey {
    /// Verifies a signature, always succeeding.
    ///
    /// # Arguments
    /// * `_` - The message (ignored)
    /// * `_` - The signature (ignored)
    ///
    /// # Returns
    /// * `Ok(())` - Always succeeds
    fn verify(
        &self,
        _: &[u8],
        _: &NoSignature,
    ) -> Result<(), signature::Error> {
        Ok(())
    }
}
