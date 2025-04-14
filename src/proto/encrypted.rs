// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! Module for handling encrypted messages in the protocol.
//! This module provides functionality for encrypting and decrypting messages
//! with support for additional data and trailers. It uses a pluggable encryption
//! scheme interface to allow for different encryption implementations.

use std::marker::PhantomData;

use bytemuck::{AnyBitPattern, NoUninit};
use chacha20poly1305::ChaCha20Poly1305;

use sl_mpc_mate::message::*;

pub use crate::proto::scheme::EncryptionScheme;

/// Default encryption scheme using X25519 key exchange and ChaCha20Poly1305 for encryption.
pub type Scheme = crate::proto::scheme::AeadX25519<ChaCha20Poly1305>;

/// A wrapper for a message of type T with support for in-place encryption/decryption.
///
/// This struct provides functionality for encrypting and decrypting messages while
/// maintaining a specific format:
///
/// ```text
/// [ msg-hdr | additional-data | payload | trailer | tag + nonce ]
/// ```
///
/// Where:
/// - `msg-hdr`: Message header containing ID, TTL, and flags
/// - `additional-data`: Optional unencrypted data
/// - `payload`: The encrypted external representation of type T
/// - `trailer`: Optional encrypted variable-sized data
/// - `tag + nonce`: Authentication tag and nonce for the encryption scheme
///
/// The `payload` and `trailer` sections are encrypted, while the header and
/// additional data remain in plaintext.
pub struct EncryptedMessage<T> {
    buffer: Vec<u8>,
    additional_data: usize, // size of additional-data
    marker: PhantomData<T>,
}

impl<T: AnyBitPattern + NoUninit> EncryptedMessage<T> {
    const T_SIZE: usize = core::mem::size_of::<T>();

    /// Calculates the total size of an encrypted message.
    ///
    /// # Arguments
    /// * `ad` - Size of additional data in bytes
    /// * `trailer` - Size of trailer data in bytes
    /// * `scheme` - The encryption scheme to use
    ///
    /// # Returns
    /// The total size in bytes needed for the encrypted message
    pub fn size(
        ad: usize,
        trailer: usize,
        scheme: &dyn EncryptionScheme,
    ) -> usize {
        MESSAGE_HEADER_SIZE + ad + Self::T_SIZE + trailer + scheme.overhead()
    }

    /// Creates a new encrypted message with the specified parameters.
    ///
    /// # Arguments
    /// * `id` - Message identifier
    /// * `ttl` - Time-to-live value
    /// * `flags` - Message flags
    /// * `trailer` - Size of trailer data in bytes
    /// * `scheme` - The encryption scheme to use
    ///
    /// # Returns
    /// A new `EncryptedMessage` instance
    pub fn new(
        id: &MsgId,
        ttl: u32,
        flags: u16,
        trailer: usize,
        scheme: &dyn EncryptionScheme,
    ) -> Self {
        let buffer = vec![0u8; Self::size(0, trailer, scheme)];

        Self::from_buffer(buffer, id, ttl, flags, 0, trailer, scheme)
    }

    /// Creates a new encrypted message with additional data.
    ///
    /// # Arguments
    /// * `id` - Message identifier
    /// * `ttl` - Time-to-live value
    /// * `flags` - Message flags
    /// * `additional_data` - Size of additional data in bytes
    /// * `trailer` - Size of trailer data in bytes
    /// * `scheme` - The encryption scheme to use
    ///
    /// # Returns
    /// A new `EncryptedMessage` instance with space for additional data
    pub fn new_with_ad(
        id: &MsgId,
        ttl: u32,
        flags: u16,
        additional_data: usize,
        trailer: usize,
        scheme: &dyn EncryptionScheme,
    ) -> Self {
        let buffer = vec![0u8; Self::size(additional_data, trailer, scheme)];

        Self::from_buffer(
            buffer,
            id,
            ttl,
            flags,
            additional_data,
            trailer,
            scheme,
        )
    }

    /// Creates an encrypted message from an existing buffer.
    ///
    /// # Arguments
    /// * `buffer` - Existing buffer to use
    /// * `id` - Message identifier
    /// * `ttl` - Time-to-live value
    /// * `flags` - Message flags
    /// * `additional_data` - Size of additional data in bytes
    /// * `trailer` - Size of trailer data in bytes
    /// * `scheme` - The encryption scheme to use
    ///
    /// # Returns
    /// A new `EncryptedMessage` instance using the provided buffer
    pub fn from_buffer(
        mut buffer: Vec<u8>,
        id: &MsgId,
        ttl: u32,
        flags: u16,
        additional_data: usize,
        trailer: usize,
        scheme: &dyn EncryptionScheme,
    ) -> Self {
        buffer.resize(Self::size(additional_data, trailer, scheme), 0);

        if let Some(hdr) = buffer.first_chunk_mut::<MESSAGE_HEADER_SIZE>() {
            MsgHdr::encode(hdr, id, ttl, flags);
        }

        Self {
            buffer,
            additional_data,
            marker: PhantomData,
        }
    }

    /// Returns mutable references to the message payload, trailer, and additional data.
    ///
    /// # Arguments
    /// * `scheme` - The encryption scheme to use
    ///
    /// # Returns
    /// A tuple containing:
    /// - Mutable reference to the payload object
    /// - Mutable reference to the trailer bytes
    /// - Mutable reference to the additional data bytes
    pub fn payload_with_ad(
        &mut self,
        scheme: &dyn EncryptionScheme,
    ) -> (&mut T, &mut [u8], &mut [u8]) {
        let tag_offset = self.buffer.len() - scheme.overhead();

        // body = ad | payload | trailer
        let body = &mut self.buffer[MESSAGE_HEADER_SIZE..tag_offset];

        let (additional_data, msg_and_trailer) =
            body.split_at_mut(self.additional_data);

        let (msg, trailer) = msg_and_trailer.split_at_mut(Self::T_SIZE);

        (bytemuck::from_bytes_mut(msg), trailer, additional_data)
    }

    /// Returns mutable references to the message payload and trailer.
    ///
    /// # Arguments
    /// * `scheme` - The encryption scheme to use
    ///
    /// # Returns
    /// A tuple containing:
    /// - Mutable reference to the payload object
    /// - Mutable reference to the trailer bytes
    pub fn payload(
        &mut self,
        scheme: &dyn EncryptionScheme,
    ) -> (&mut T, &mut [u8]) {
        let (msg, trailer, _) = self.payload_with_ad(scheme);

        (msg, trailer)
    }

    /// Encrypts the message using the provided encryption scheme.
    ///
    /// # Arguments
    /// * `scheme` - The encryption scheme to use
    /// * `receiver` - The ID of the intended receiver
    ///
    /// # Returns
    /// The encrypted message as a byte vector, or `None` if encryption failed
    pub fn encrypt(
        self,
        scheme: &mut dyn EncryptionScheme,
        receiver: usize,
    ) -> Option<Vec<u8>> {
        let mut buffer = self.buffer;

        let last = buffer.len() - scheme.overhead();
        let (msg, tail) = buffer.split_at_mut(last);

        let (associated_data, plaintext) =
            msg.split_at_mut(MESSAGE_HEADER_SIZE + self.additional_data);

        scheme
            .encrypt(associated_data, plaintext, tail, receiver)
            .ok()?;

        Some(buffer)
    }

    /// Decrypts a message and returns references to the payload, trailer, and additional data.
    ///
    /// # Arguments
    /// * `buffer` - The encrypted message buffer
    /// * `additional_data` - Size of additional data in bytes
    /// * `trailer` - Size of trailer data in bytes
    /// * `scheme` - The encryption scheme to use
    /// * `sender` - The ID of the message sender
    ///
    /// # Returns
    /// A tuple containing references to the decrypted payload, trailer, and additional data,
    /// or `None` if decryption failed
    pub fn decrypt_with_ad<'msg>(
        buffer: &'msg mut [u8],
        additional_data: usize,
        trailer: usize,
        scheme: &dyn EncryptionScheme,
        sender: usize,
    ) -> Option<(&'msg T, &'msg [u8], &'msg [u8])> {
        if buffer.len() != Self::size(additional_data, trailer, scheme) {
            return None;
        }

        let (associated_data, body) =
            buffer.split_at_mut(MESSAGE_HEADER_SIZE + additional_data);

        let (ciphertext, tail) =
            body.split_at_mut(body.len() - scheme.overhead());

        scheme
            .decrypt(associated_data, ciphertext, tail, sender)
            .ok()?;

        let (msg, trailer) = ciphertext.split_at_mut(Self::T_SIZE);

        Some((
            bytemuck::from_bytes_mut(msg),
            trailer,
            &associated_data[MESSAGE_HEADER_SIZE..],
        ))
    }

    /// Decrypts a message and returns references to the payload and trailer.
    ///
    /// # Arguments
    /// * `buffer` - The encrypted message buffer
    /// * `trailer` - Size of trailer data in bytes
    /// * `scheme` - The encryption scheme to use
    /// * `sender` - The ID of the message sender
    ///
    /// # Returns
    /// A tuple containing references to the decrypted payload and trailer,
    /// or `None` if decryption failed
    pub fn decrypt<'msg>(
        buffer: &'msg mut [u8],
        trailer: usize,
        scheme: &dyn EncryptionScheme,
        sender: usize,
    ) -> Option<(&'msg T, &'msg [u8])> {
        Self::decrypt_with_ad(buffer, 0, trailer, scheme, sender)
            .map(|(msg, trailer, _)| (msg, trailer))
    }
}
