// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! Module for handling signed messages in the protocol.
//!
//! This module provides functionality for creating and verifying signed messages
//! with support for additional data and trailers. It uses a pluggable signature
//! scheme interface to allow for different signature implementations.

use std::marker::PhantomData;
use std::ops::Range;

use bytemuck::{AnyBitPattern, NoUninit};
use signature::{SignatureEncoding, Signer, Verifier};

use sl_mpc_mate::message::*;

/// A wrapper for a message of type T with support for in-place signing and verifying.
///
/// This struct provides functionality for creating and verifying signed messages
/// with the following format:
///
/// ```text
/// [ msg-hdr | payload | trailer | signature ]
/// ```
///
/// Where:
/// - `msg-hdr`: Message header containing ID, TTL, and flags
/// - `payload`: The message payload of type T
/// - `trailer`: Optional additional data
/// - `signature`: The cryptographic signature
///
/// # Type Parameters
/// * `T` - The type of the message payload
/// * `S` - The type of signature encoding used
pub struct SignedMessage<T, S: SignatureEncoding> {
    buffer: Vec<u8>,
    marker: PhantomData<(T, <S as SignatureEncoding>::Repr)>,
}

impl<S: SignatureEncoding, T: AnyBitPattern + NoUninit> SignedMessage<T, S> {
    /// Size of the message header in bytes.
    pub const HEADER_SIZE: usize = MESSAGE_HEADER_SIZE;

    const T_SIZE: usize = core::mem::size_of::<T>();
    const S_SIZE: usize = core::mem::size_of::<S::Repr>();

    /// Calculates the total size of a signed message.
    ///
    /// # Arguments
    /// * `trailer` - Size of the trailer data in bytes
    ///
    /// # Returns
    /// The total size in bytes needed for the signed message
    pub const fn size(trailer: usize) -> usize {
        MESSAGE_HEADER_SIZE + Self::T_SIZE + trailer + Self::S_SIZE
    }

    /// Creates a new signed message with the specified parameters.
    ///
    /// # Arguments
    /// * `id` - Message identifier
    /// * `ttl` - Time-to-live value
    /// * `flags` - Message flags
    /// * `trailer` - Size of trailer data in bytes
    ///
    /// # Returns
    /// A new `SignedMessage` instance
    pub fn new(id: &MsgId, ttl: u32, flags: u16, trailer: usize) -> Self {
        let buffer = vec![0u8; Self::size(trailer)];

        Self::from_buffer(buffer, id, ttl, flags, trailer)
    }

    /// Creates a signed message from an existing buffer.
    ///
    /// # Arguments
    /// * `buffer` - Existing buffer to use
    /// * `id` - Message identifier
    /// * `ttl` - Time-to-live value
    /// * `flags` - Message flags
    /// * `trailer` - Size of trailer data in bytes
    ///
    /// # Returns
    /// A new `SignedMessage` instance using the provided buffer
    pub fn from_buffer(
        mut buffer: Vec<u8>,
        id: &MsgId,
        ttl: u32,
        flags: u16,
        trailer: usize,
    ) -> Self {
        buffer.resize(Self::size(trailer), 0);

        if let Some(hdr) = buffer.first_chunk_mut::<MESSAGE_HEADER_SIZE>() {
            MsgHdr::encode(hdr, id, ttl, flags);
        }

        Self {
            buffer,
            marker: PhantomData,
        }
    }

    /// Returns mutable references to the message payload and trailer.
    ///
    /// # Returns
    /// A tuple containing:
    /// - Mutable reference to the payload object
    /// - Mutable reference to the trailer bytes
    pub fn payload(&mut self) -> (&mut T, &mut [u8]) {
        let end = self.buffer.len() - Self::S_SIZE;

        let body = &mut self.buffer[MESSAGE_HEADER_SIZE..end];
        let (msg, trailer) = body.split_at_mut(Self::T_SIZE);

        (bytemuck::from_bytes_mut(msg), trailer)
    }

    /// Signs the message and returns the underlying byte vector.
    ///
    /// # Arguments
    /// * `signing_key` - The key used to sign the message
    ///
    /// # Returns
    /// The signed message as a byte vector
    pub fn sign<K: Signer<S>>(self, signing_key: &K) -> Vec<u8> {
        let mut buffer = self.buffer;

        let last = buffer.len() - Self::S_SIZE;
        let (msg, tail) = buffer.split_at_mut(last);

        let sign = signing_key.sign(msg).to_bytes();

        tail.copy_from_slice(sign.as_ref());

        buffer
    }

    /// Builds and signs a message using a closure to set the payload.
    ///
    /// # Arguments
    /// * `id` - Message identifier
    /// * `ttl` - Time-to-live value
    /// * `trailer` - Size of trailer data in bytes
    /// * `signing_key` - The key used to sign the message
    /// * `f` - Closure that sets the payload and trailer content
    ///
    /// # Returns
    /// The signed message as a byte vector
    pub fn build<F, K: Signer<S>>(
        id: &MsgId,
        ttl: u32,
        trailer: usize,
        signing_key: &K,
        f: F,
    ) -> Vec<u8>
    where
        F: FnOnce(&mut T, &mut [u8]),
    {
        let mut msg = Self::new(id, ttl, 0, trailer);
        let (payload, trailer) = msg.payload();
        f(payload, trailer);
        msg.sign(signing_key)
    }

    /// Verifies a signed message and returns references to the payload and trailer.
    ///
    /// # Arguments
    /// * `buffer` - The signed message buffer
    /// * `trailer` - Size of trailer data in bytes
    /// * `verify_key` - The key used to verify the signature
    ///
    /// # Returns
    /// A tuple containing references to the payload and trailer,
    /// or `None` if verification fails
    pub fn verify_with_trailer<'msg, V: Verifier<S>>(
        buffer: &'msg [u8],
        trailer: usize,
        verify_key: &V,
    ) -> Option<(&'msg T, &'msg [u8])> {
        // Make sure that buffer is exactly right size
        if buffer.len() != Self::size(trailer) {
            return None;
        }

        let sign_offset = buffer.len() - Self::S_SIZE;
        let (msg, sign) = buffer.split_at(sign_offset);
        let sign = S::try_from(sign).ok()?;

        verify_key.verify(msg, &sign).ok()?;

        let body = &msg[MESSAGE_HEADER_SIZE..];
        let (payload, trailer) = body.split_at(Self::T_SIZE);
        Some((bytemuck::from_bytes(payload), trailer))
    }

    /// Verifies a signed message and returns a reference to the payload.
    ///
    /// # Arguments
    /// * `buffer` - The signed message buffer
    /// * `verify_key` - The key used to verify the signature
    ///
    /// # Returns
    /// A reference to the payload, or `None` if verification fails
    pub fn verify<'msg, V: Verifier<S>>(buffer: &'msg [u8], verify_key: &V) -> Option<&'msg T> {
        Self::verify_with_trailer(buffer, 0, verify_key).map(|(m, _)| m)
    }
}

impl<S: SignatureEncoding> SignedMessage<(), S> {
    /// Verifies a message in the buffer and returns the range containing the payload.
    ///
    /// # Arguments
    /// * `buffer` - The signed message buffer
    /// * `verify_key` - The key used to verify the signature
    ///
    /// # Returns
    /// The range of bytes containing the payload, or `None` if verification fails
    pub fn verify_buffer<V: Verifier<S>>(buffer: &[u8], verify_key: &V) -> Option<Range<usize>> {
        let overhead = MESSAGE_HEADER_SIZE + Self::S_SIZE;

        if buffer.len() > overhead {
            let trailer = buffer.len() - overhead;

            Self::verify_with_trailer(buffer, trailer, verify_key)?;

            Some(MESSAGE_HEADER_SIZE..buffer.len() - Self::S_SIZE)
        } else {
            None
        }
    }
}
