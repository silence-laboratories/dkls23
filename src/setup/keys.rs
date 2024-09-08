// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

#![allow(missing_docs)]

use std::sync::Arc;

use signature::{Keypair, SignatureEncoding, Signer, Verifier};

/// Type of empty signature.
#[derive(Clone)]
pub struct NoSignature;

impl SignatureEncoding for NoSignature {
    type Repr = [u8; 0];
}

impl<'a> TryFrom<&'a [u8]> for NoSignature {
    type Error = ();

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        if !value.is_empty() {
            return Err(());
        }
        Ok(NoSignature)
    }
}

impl TryInto<[u8; 0]> for NoSignature {
    type Error = ();

    fn try_into(self) -> Result<[u8; 0], Self::Error> {
        Ok([0; 0])
    }
}

pub struct NoSigningKey;

impl Signer<NoSignature> for NoSigningKey {
    fn try_sign(&self, _msg: &[u8]) -> Result<NoSignature, signature::Error> {
        Ok(NoSignature)
    }
}

/// Allow to pass Arc<SK> where expected SK: Signer
///
pub struct ArcSigner<T>(pub Arc<T>);

impl<S, T: Signer<S>> Signer<S> for ArcSigner<T> {
    fn sign(&self, msg: &[u8]) -> S {
        self.0.sign(msg)
    }

    fn try_sign(&self, msg: &[u8]) -> Result<S, signature::Error> {
        self.0.try_sign(msg)
    }
}

impl<T: Keypair> Keypair for ArcSigner<T> {
    type VerifyingKey = T::VerifyingKey;

    fn verifying_key(&self) -> Self::VerifyingKey {
        self.0.verifying_key()
    }
}

/// A verifying key for NoSignature. Verification always succeeds. In
/// this case verifying key used as an idenitity ID and communication
/// uses a secure transport and there is no need to verify
/// authenticity of the messages.
#[derive(Clone)]
pub struct NoVerifyingKey(Vec<u8>);

impl NoVerifyingKey {
    pub fn new(id: usize) -> Self {
        NoVerifyingKey((id as u64).to_be_bytes().into())
    }
}

impl<T: Into<Vec<u8>>> From<T> for NoVerifyingKey {
    fn from(value: T) -> Self {
        NoVerifyingKey(value.into())
    }
}

impl AsRef<[u8]> for NoVerifyingKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Verifier<NoSignature> for NoVerifyingKey {
    fn verify(
        &self,
        _: &[u8],
        _: &NoSignature,
    ) -> Result<(), signature::Error> {
        Ok(())
    }
}
