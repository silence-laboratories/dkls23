// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::marker::PhantomData;
use std::ops::Range;

use bytemuck::{AnyBitPattern, NoUninit};
use signature::{SignatureEncoding, Signer, Verifier};

use sl_mpc_mate::message::*;

/// A wrapper for a message of type T with support inplace
/// signing and verifying
pub struct SignedMessage<T, S: SignatureEncoding> {
    buffer: Vec<u8>,
    marker: PhantomData<(T, <S as SignatureEncoding>::Repr)>,
}

impl<S: SignatureEncoding, T: AnyBitPattern + NoUninit> SignedMessage<T, S> {
    /// Size of the message header.
    pub const HEADER_SIZE: usize = MESSAGE_HEADER_SIZE;

    const T_SIZE: usize = core::mem::size_of::<T>();
    const S_SIZE: usize = core::mem::size_of::<S::Repr>();

    /// Size of the whole message with additional trailer bytes.
    pub const fn size(trailer: usize) -> usize {
        MESSAGE_HEADER_SIZE + Self::T_SIZE + trailer + Self::S_SIZE
    }

    /// Allocate a message with passed ID and TTL and additional
    /// trailer bytes.
    pub fn new(id: &MsgId, ttl: u32, flags: u16, trailer: usize) -> Self {
        let buffer = vec![0u8; Self::size(trailer)];

        Self::from_buffer(buffer, id, ttl, flags, trailer)
    }

    /// Use existing buffer but make sure it has the right size.
    ///
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

    /// Return a mutable reference to message payload object and trailer byte slice.
    pub fn payload(&mut self) -> (&mut T, &mut [u8]) {
        let end = self.buffer.len() - Self::S_SIZE;

        let body = &mut self.buffer[MESSAGE_HEADER_SIZE..end];
        let (msg, trailer) = body.split_at_mut(Self::T_SIZE);

        (bytemuck::from_bytes_mut(msg), trailer)
    }

    /// Sing the message and return underlying byte vector.
    pub fn sign<K: Signer<S>>(self, signing_key: &K) -> Vec<u8> {
        let mut buffer = self.buffer;

        let last = buffer.len() - Self::S_SIZE;
        let (msg, tail) = buffer.split_at_mut(last);

        let sign = signing_key.sign(msg).to_bytes();

        tail.copy_from_slice(sign.as_ref());

        buffer
    }

    /// Call a passed closure with a mutable reference to a message payload
    /// and sign message and return it as a byte vector after that.
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

    /// Verify signed message and return a payload reference.
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

    /// Verify signed message and return a payload reference.
    pub fn verify<'msg, V: Verifier<S>>(
        buffer: &'msg [u8],
        verify_key: &V,
    ) -> Option<&'msg T> {
        Self::verify_with_trailer(buffer, 0, verify_key).map(|(m, _)| m)
    }
}

impl<S: SignatureEncoding> SignedMessage<(), S> {
    /// Verify message in the passed buffer and return range
    /// containing message payload.
    pub fn verify_buffer<V: Verifier<S>>(
        buffer: &[u8],
        verify_key: &V,
    ) -> Option<Range<usize>> {
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
