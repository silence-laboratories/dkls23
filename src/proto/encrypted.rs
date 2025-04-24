// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::marker::PhantomData;

use bytemuck::{AnyBitPattern, NoUninit};
use chacha20poly1305::ChaCha20Poly1305;

use sl_mpc_mate::message::*;

pub use crate::proto::scheme::EncryptionScheme;

/// Default encryption scheme
pub type Scheme = crate::proto::scheme::AeadX25519<ChaCha20Poly1305>;

/// A wrapper for a message of type T with support for in-place
/// encryption/decryption with additional data.
///
/// Format of encrypted message:
///
/// [ msg-hdr | additional-data | payload | trailer | tag + nonce ]
///
/// `payload | trailer` are encrypted.
///
/// `trailer` is a variable-sized part of the message.
///
/// `payload` is the external representation of `T`.
///
pub struct EncryptedMessage<T> {
    buffer: Vec<u8>,
    additional_data: usize, // size of additional-data
    marker: PhantomData<T>,
}

impl<T: AnyBitPattern + NoUninit> EncryptedMessage<T> {
    const T_SIZE: usize = core::mem::size_of::<T>();

    /// Size of the whole message with additional data and trailer bytes.
    pub fn size(ad: usize, trailer: usize, scheme: &dyn EncryptionScheme) -> usize {
        MESSAGE_HEADER_SIZE + ad + Self::T_SIZE + trailer + scheme.overhead()
    }

    /// Allocate a message with passed ID and TTL and additional
    /// trailer bytes.
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

    /// Allocate a message with passed ID and TTL and additional data
    /// and trailer bytes.
    pub fn new_with_ad(
        id: &MsgId,
        ttl: u32,
        flags: u16,
        additional_data: usize,
        trailer: usize,
        scheme: &dyn EncryptionScheme,
    ) -> Self {
        let buffer = vec![0u8; Self::size(additional_data, trailer, scheme)];

        Self::from_buffer(buffer, id, ttl, flags, additional_data, trailer, scheme)
    }

    /// Use existing buffer but make sure it has the right size.
    ///
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

    /// Return a mutable references to message payload object, trailer
    /// and additional data byte slices.
    pub fn payload_with_ad(
        &mut self,
        scheme: &dyn EncryptionScheme,
    ) -> (&mut T, &mut [u8], &mut [u8]) {
        let tag_offset = self.buffer.len() - scheme.overhead();

        // body = ad | payload | trailer
        let body = &mut self.buffer[MESSAGE_HEADER_SIZE..tag_offset];

        let (additional_data, msg_and_trailer) = body.split_at_mut(self.additional_data);

        let (msg, trailer) = msg_and_trailer.split_at_mut(Self::T_SIZE);

        (bytemuck::from_bytes_mut(msg), trailer, additional_data)
    }

    /// Return a mutable reference to message payload object and trailer byte slice.
    pub fn payload(&mut self, scheme: &dyn EncryptionScheme) -> (&mut T, &mut [u8]) {
        let (msg, trailer, _) = self.payload_with_ad(scheme);

        (msg, trailer)
    }

    /// Encrypt message.
    pub fn encrypt(self, scheme: &mut dyn EncryptionScheme, receiver: usize) -> Option<Vec<u8>> {
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

    /// Decrypt message and return references to the payload, trailer
    /// and additional data bytes.
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

        let (associated_data, body) = buffer.split_at_mut(MESSAGE_HEADER_SIZE + additional_data);

        let (ciphertext, tail) = body.split_at_mut(body.len() - scheme.overhead());

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

    /// Decrypte message and return reference to the payload and trailer bytes.
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
