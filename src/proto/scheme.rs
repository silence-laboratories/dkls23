// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! Cryptographic Scheme Implementation for Secure Communication
//!
//! This module provides the core cryptographic primitives and protocols
//! for secure communication between parties in the DKLS23 protocol.
//! It implements an encryption scheme that combines:
//! - Authenticated Encryption with Associated Data (AEAD)
//! - Key exchange using X25519
//! - Secure key derivation
//!
//! # Security Properties
//!
//! - Forward secrecy through ephemeral key exchange
//! - Message authentication and integrity
//! - Nonce reuse prevention
//! - Secure key derivation using SHA-256
//!
//! # Implementation Details
//!
//! The module provides:
//! - `EncryptionScheme` trait defining the interface for secure communication
//! - `AeadX25519` implementation using ChaCha20-Poly1305 for AEAD
//! - Secure nonce generation and management
//! - Key pair management for multiple parties

#![allow(unused_imports, dead_code, unused_variables)]

use std::marker::PhantomData;

use aead::{
    consts::{U10, U32},
    generic_array::{typenum::Unsigned, GenericArray},
    AeadCore, AeadInPlace, Key, KeyInit, KeySizeUser, Nonce, Tag,
};
use chacha20::hchacha;
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, ReusableSecret};
use zeroize::Zeroizing;

use crate::pairs::Pairs;

/// Error indicating invalid public key format or operation
#[derive(Debug)]
pub struct PublicKeyError;

/// Error indicating encryption or decryption failure
#[derive(Debug)]
pub struct EncryptionError;

/// Type alias for a shared key used in encryption
type SharedKey = Zeroizing<GenericArray<u8, U32>>;

/// Represents an encryption scheme interface for in-place AEAD and
/// managing key exchange.
///
/// A type implementing EncryptionScheme encapsulates two
/// functionalities:
///
/// - An AEAD algorithm such as ChaCha20 or AES-GCM and its
///   implementation details, such as nonce generation.
///
/// - The derivation of encryption keys for one or more pairs of parties.
///   The concrete type of public/private key pair and key exchange is
///   an implementation detail.
///
/// # Security Considerations
///
/// Implementations must ensure:
/// - Forward secrecy through proper key exchange
/// - Nonce uniqueness for each encryption
/// - Secure key derivation
/// - Proper authentication of messages
pub trait EncryptionScheme: Send {
    /// Return external representation of own public key
    fn public_key(&self) -> &[u8];

    /// Sets or updates the public key for a specified receiver index.
    ///
    /// This function is used to associate a public key with a designated
    /// receiver identified by an index. It facilitates secure communication
    /// setup by ensuring that messages can be encrypted such that only the
    /// receiver with the corresponding private key can decrypt them.
    ///
    /// # Parameters
    ///
    /// - `receiver_index`: An integer value that uniquely identifies the
    ///   receiver within the system. This index is used to specify which
    ///   receiver the public key is associated with.
    ///
    /// - `public_key`: A byte slice representing the public key of the receiver.
    ///   This key is used in cryptographic operations to ensure that only
    ///   the intended receiver can decrypt messages encrypted with this key.
    ///
    /// # Errors
    ///
    /// - `PublicKeyError`: An error is returned if the public key cannot be
    ///   set due to invalid formatting, an invalid receiver index, or any
    ///   other issue encountered in the operation.
    fn receiver_public_key(
        &mut self,
        receiver_index: usize,
        public_key: &[u8],
    ) -> Result<(), PublicKeyError>;

    /// Encrypts the provided data buffer using associated data and
    /// manages an associated tail segment.
    ///
    /// # Parameters
    ///
    /// - `associated_data`: A byte slice containing additional
    ///   authenticated data (AAD) that will be used to ensure the
    ///   integrity and authenticity of the encrypted data. This data is
    ///   not encrypted but is included in the integrity check.
    ///
    /// - `buffer`: A mutable byte slice containing the plaintext data
    ///   that will be encrypted in place. Upon successful encryption,
    ///   this buffer will contain the ciphertext data.
    ///
    /// - `tail`: A mutable byte slice representing the trailing
    ///   segment of the data buffer that may be used to store for
    ///   trailing portion of the data that should be considered during
    ///   decryption.
    ///
    /// - `receive`: An index or identifier associated with the
    ///   receiver of the message. This may be used for deriving
    ///   encryption keys.
    ///
    /// # Errors
    ///
    ///   `EncryptionError` if issues arise such as missing keys,
    ///   incorrect buffer lengths, or any other problems during the
    ///   encryption process.
    fn encrypt(
        &mut self,
        associated_data: &[u8],
        buffer: &mut [u8],
        tail: &mut [u8],
        receive: usize,
    ) -> Result<(), EncryptionError>;

    /// Decrypts the provided data buffer using associated data and a
    /// tail segment.
    ///
    /// # Parameters
    ///
    /// - `associated_data`: A byte slice containing additional
    ///   authenticated data (AAD) that will be used along with the
    ///   buffer to ensure the integrity and authenticity of the
    ///   decryption process.
    ///
    /// - `buffer`: A mutable byte slice holding the encrypted data
    ///   that will be decrypted in place. Upon successful decryption,
    ///   this buffer will contain the plaintext data.
    ///
    /// - `tail`: A byte slice representing the trailing portion of
    ///   the data that should be considered during decryption. This is
    ///   typically used nonce and/or authentication tag.
    ///
    /// - `sender`: An index or identifier representing the sender of
    ///   the message. This might be used to retrieve or derive
    ///   encryption keys.
    ///
    /// # Errors
    ///
    /// - `EncryptionError`: This function may return an
    ///   `EncryptionError` in several situations such as when the
    ///   decryption key is not found, when the input data is tampered
    ///   with or if the cryptographic verification of the AAD fails.
    fn decrypt(
        &self,
        associated_data: &[u8],
        buffer: &mut [u8],
        tail: &[u8],
        sender: usize,
    ) -> Result<(), EncryptionError>;

    /// Return size of trailing segment. See method `encrypt()` and `decrypt()`.
    fn overhead(&self) -> usize;
}

/// Counter to create a unique nonce for encryption operations.
///
/// This struct maintains a counter that is used to generate unique nonces
/// for each encryption operation. The counter is incremented for each
/// encryption to ensure nonce uniqueness.
///
/// # Security Considerations
///
/// - The counter is 32-bit and will panic on overflow
/// - Nonces are derived from the counter value
/// - Each encryption operation must use a unique nonce
#[derive(Default)]
pub struct NonceCounter(u32);

impl NonceCounter {
    /// Creates a new counter initialized to 0.
    pub fn new() -> Self {
        Self(0)
    }

    /// Increments the counter and returns a new nonce.
    ///
    /// # Type Parameters
    ///
    /// * `S`: The AEAD scheme type that determines the nonce size
    ///
    /// # Returns
    ///
    /// A new nonce derived from the incremented counter value
    ///
    /// # Panics
    ///
    /// Panics if the counter overflows (exceeds u32::MAX)
    pub fn next_nonce<S: AeadCore>(&mut self) -> Nonce<S> {
        self.0 = self.0.checked_add(1).expect("nonce overflow");

        let mut nonce = Nonce::<S>::default();
        nonce[..4].copy_from_slice(&self.0.to_le_bytes());

        nonce
    }
}

/// Implementation of EncryptionScheme using X25519 for key exchange
/// and any AEAD scheme for encryption.
///
/// This struct combines:
/// - X25519 for key exchange
/// - A configurable AEAD scheme for encryption
/// - Secure nonce generation
/// - Key pair management for multiple parties
///
/// # Type Parameters
///
/// * `S`: The AEAD scheme to use for encryption (e.g., ChaCha20Poly1305)
pub struct AeadX25519<S> {
    secret: ReusableSecret,
    public_key: PublicKey,
    counter: NonceCounter,
    pk: Pairs<(SharedKey, PublicKey), usize>,
    marker: PhantomData<S>,
}

impl<S> AeadX25519<S> {
    /// Generate a new [`AeadX25519`] with the supplied RNG.
    ///
    /// # Arguments
    ///
    /// * `rng`: A cryptographically secure random number generator
    ///
    /// # Returns
    ///
    /// A new `AeadX25519` instance with:
    /// - A randomly generated X25519 key pair
    /// - An initialized nonce counter
    /// - An empty key pair store
    pub fn new(rng: &mut impl CryptoRngCore) -> Self {
        let secret = ReusableSecret::random_from_rng(rng);
        let public_key = PublicKey::from(&secret);

        Self {
            secret,
            public_key,
            counter: NonceCounter::new(),
            pk: Pairs::new(),
            marker: PhantomData,
        }
    }

    /// Create a new [`AeadX25519`] from a provided `ReusableSecret`.
    ///
    /// # Arguments
    ///
    /// * `secret`: A pre-existing X25519 secret key
    ///
    /// # Returns
    ///
    /// A new `AeadX25519` instance with:
    /// - The provided secret key and its corresponding public key
    /// - An initialized nonce counter
    /// - An empty key pair store
    pub fn from_secret(secret: ReusableSecret) -> Self {
        let public_key = PublicKey::from(&secret);

        Self {
            secret,
            public_key,
            counter: NonceCounter::new(),
            pk: Pairs::new(),
            marker: PhantomData,
        }
    }
}

impl<S> EncryptionScheme for AeadX25519<S>
where
    S: AeadInPlace + KeyInit + Send,
{
    fn overhead(&self) -> usize {
        S::TagSize::USIZE + S::NonceSize::USIZE
    }

    fn encrypt(
        &mut self,
        associated_data: &[u8],
        buffer: &mut [u8],
        tail: &mut [u8],
        receive: usize,
    ) -> Result<(), EncryptionError> {
        if tail.len() != self.overhead() {
            return Err(EncryptionError);
        }

        let (key, public_key) =
            self.pk.find_pair_or_err(receive, EncryptionError)?;

        let key = Zeroizing::new(
            Sha256::new_with_prefix(public_key)
                .chain_update(key)
                .finalize(),
        );

        let key = Key::<S>::from_slice(key.as_slice());

        let nonce = self.counter.next_nonce::<S>();
        let tag = S::new(key)
            .encrypt_in_place_detached(&nonce, associated_data, buffer)
            .map_err(|_| EncryptionError)?;

        tail[..S::TagSize::USIZE].copy_from_slice(&tag);
        tail[S::TagSize::USIZE..].copy_from_slice(&nonce);

        Ok(())
    }

    fn decrypt(
        &self,
        associated_data: &[u8],
        buffer: &mut [u8],
        tail: &[u8],
        sender: usize,
    ) -> Result<(), EncryptionError> {
        if tail.len() != self.overhead() {
            return Err(EncryptionError);
        }

        let (key, public_key) =
            self.pk.find_pair_or_err(sender, EncryptionError)?;

        let key = Zeroizing::new(
            Sha256::new_with_prefix(self.public_key)
                .chain_update(key)
                .finalize(),
        );

        let key = Key::<S>::from_slice(key.as_slice());

        let nonce = Nonce::<S>::from_slice(&tail[S::TagSize::USIZE..]);
        let tag = Tag::<S>::from_slice(&tail[..S::TagSize::USIZE]);

        S::new(key)
            .decrypt_in_place_detached(nonce, associated_data, buffer, tag)
            .map_err(|_| EncryptionError)?;

        Ok(())
    }

    fn public_key(&self) -> &[u8] {
        self.public_key.as_bytes()
    }

    fn receiver_public_key(
        &mut self,
        receiver_index: usize,
        pk: &[u8],
    ) -> Result<(), PublicKeyError> {
        let pk: [u8; 32] = pk.try_into().map_err(|_| PublicKeyError)?;
        let pk = PublicKey::from(pk);

        let shared_secret = self.secret.diffie_hellman(&pk);

        if !shared_secret.was_contributory() {
            return Err(PublicKeyError);
        }

        let shared_key = Zeroizing::new(hchacha::<U10>(
            GenericArray::from_slice(shared_secret.as_bytes()),
            &GenericArray::default(),
        ));

        self.pk.push(receiver_index, (shared_key, pk));

        Ok(())
    }
}
