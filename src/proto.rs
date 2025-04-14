// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::mem;

use k256::{
    elliptic_curve::{group::GroupEncoding, PrimeField},
    AffinePoint, NonZeroScalar, ProjectivePoint, Scalar,
};
use x25519_dalek::PublicKey;

use sl_mpc_mate::{math::GroupPolynomial, message::*, ByteArray};
use sl_oblivious::zkproofs::DLogProof;

use crate::setup::{ProtocolParticipant, ABORT_MESSAGE_TAG};

mod encrypted;
mod scheme;
mod signed;

/// tags
pub mod tags;

pub use encrypted::{EncryptedMessage, EncryptionScheme, Scheme};
pub use signed::SignedMessage;
pub use tags::{FilteredMsgRelay, Round};

/// External representation of a point on a curve
pub type PointBytes = [u8; 33];

/// External Scalar representation
pub type ScalarBytes = [u8; 32]; // KAPPA_BYTES

pub use sl_mpc_mate::{
    coord::Relay,
    message::{MessageTag, MsgHdr},
};

/// Encode AffinePoint
pub fn encode_affine(&a: &AffinePoint) -> PointBytes {
    a.to_bytes().into()
}

/// Encode AffinePoint
pub fn decode_affine(bytes: &PointBytes) -> Option<AffinePoint> {
    let mut repr = <AffinePoint as GroupEncoding>::Repr::default();
    AsMut::<[u8]>::as_mut(&mut repr).copy_from_slice(bytes);

    AffinePoint::from_bytes(&repr).into()
}

/// Encode ProjectivePoint
pub fn encode_point(p: &ProjectivePoint) -> PointBytes {
    encode_affine(&p.to_affine())
}

/// Decode ProjectivePoint
pub fn decode_point(bytes: &PointBytes) -> Option<ProjectivePoint> {
    let mut repr = <ProjectivePoint as GroupEncoding>::Repr::default();
    AsMut::<[u8]>::as_mut(&mut repr).copy_from_slice(bytes);

    ProjectivePoint::from_bytes(&repr).into()
}

/// Encode a scalar
pub fn encode_scalar(s: &Scalar) -> ScalarBytes {
    s.to_bytes().into()
}

/// Decode a scalar
pub fn decode_scalar(bytes: &ScalarBytes) -> Option<Scalar> {
    let mut repr = <Scalar as PrimeField>::Repr::default();
    AsMut::<[u8]>::as_mut(&mut repr).copy_from_slice(bytes);

    Scalar::from_repr(repr).into()
}

/// Decode a NonZeroScalar
pub fn decode_nonzero(bytes: &ScalarBytes) -> Option<NonZeroScalar> {
    NonZeroScalar::new(decode_scalar(bytes)?).into()
}

/// Create an Abort Message.
pub fn create_abort_message<P>(setup: &P) -> Vec<u8>
where
    P: ProtocolParticipant,
{
    SignedMessage::<(), _>::new(
        &setup.msg_id(None, ABORT_MESSAGE_TAG),
        setup.message_ttl().as_secs() as _,
        0,
        0,
    )
    .sign(setup.signer())
}

/// Returns passed error if msg is a vaild abort message.
pub fn check_abort<P: ProtocolParticipant, E>(
    setup: &P,
    msg: &[u8],
    party_id: usize,
    err: impl FnOnce(usize) -> E,
) -> Result<(), E> {
    SignedMessage::<(), _>::verify(msg, setup.verifier(party_id))
        .map_or(Ok(()), |_| Err(err(party_id)))
}

/// A type with some external represention.
pub trait Wrap: Sized {
    /// Size of external representation in bytes
    fn external_size(&self) -> usize;

    /// Serialize a value into passed buffer
    fn write(&self, buffer: &mut [u8]);

    /// Deserialize value from given buffer
    fn read(buffer: &[u8]) -> Option<Self>;

    /// Encode a value into passed buffer and return remaining bytes.
    fn encode<'a>(&self, buf: &'a mut [u8]) -> &'a mut [u8] {
        let (buf, rest) = buf.split_at_mut(self.external_size());
        self.write(buf);
        rest
    }

    /// Decode a value from `input` buffer using `size` bytes.
    /// Return remaining bytes and decoded value.
    fn decode(input: &[u8], size: usize) -> Option<(&[u8], Self)> {
        if input.len() < size {
            return None;
        }
        let (input, rest) = input.split_at(size);
        Some((rest, Self::read(input)?))
    }
}

/// A type with fixed size of external representation.
pub trait FixedExternalSize: Sized {
    /// Size of an external representation of Self
    const SIZE: usize;
}

impl Wrap for () {
    fn external_size(&self) -> usize {
        0
    }

    fn write(&self, _buffer: &mut [u8]) {}

    fn read(_buffer: &[u8]) -> Option<Self> {
        Some(())
    }
}

impl FixedExternalSize for () {
    const SIZE: usize = 0;
}

impl<const N: usize> FixedExternalSize for ByteArray<N> {
    const SIZE: usize = N;
}

impl<const N: usize> Wrap for ByteArray<N> {
    fn external_size(&self) -> usize {
        self.len()
    }

    fn write(&self, buffer: &mut [u8]) {
        buffer.copy_from_slice(self);
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        let mut value = Self::default();
        value.copy_from_slice(buffer);
        Some(value)
    }
}

impl Wrap for Scalar {
    fn external_size(&self) -> usize {
        mem::size_of::<ScalarBytes>()
    }

    fn write(&self, buffer: &mut [u8]) {
        let s = encode_scalar(self);
        buffer.copy_from_slice(&s);
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        decode_scalar(buffer.try_into().ok()?)
    }
}

impl Wrap for NonZeroScalar {
    fn external_size(&self) -> usize {
        mem::size_of::<ScalarBytes>()
    }

    fn write(&self, buffer: &mut [u8]) {
        let s = encode_scalar(self);
        buffer.copy_from_slice(&s);
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        decode_scalar(buffer.try_into().ok()?)
            .and_then(|s| NonZeroScalar::new(s).into())
    }
}

impl Wrap for AffinePoint {
    fn external_size(&self) -> usize {
        mem::size_of::<PointBytes>()
    }

    fn write(&self, buffer: &mut [u8]) {
        let p = encode_affine(self);
        buffer.copy_from_slice(&p);
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        decode_affine(buffer.try_into().ok()?)
    }
}

impl Wrap for ProjectivePoint {
    fn external_size(&self) -> usize {
        mem::size_of::<PointBytes>()
    }

    fn write(&self, buffer: &mut [u8]) {
        let p = encode_point(self);
        buffer.copy_from_slice(&p);
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        decode_point(buffer.try_into().ok()?)
    }
}

impl<const N: usize> Wrap for [u8; N] {
    fn external_size(&self) -> usize {
        N
    }

    fn write(&self, buffer: &mut [u8]) {
        buffer.copy_from_slice(self);
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        let mut value = [0u8; N];
        value.copy_from_slice(buffer);
        Some(value)
    }
}

impl Wrap for PublicKey {
    fn external_size(&self) -> usize {
        32
    }

    fn write(&self, buffer: &mut [u8]) {
        buffer.copy_from_slice(self.as_bytes());
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        let mut value = [0u8; 32];
        value.copy_from_slice(buffer);
        Some(PublicKey::from(value))
    }
}

impl Wrap for GroupPolynomial<ProjectivePoint> {
    fn external_size(&self) -> usize {
        self.coeffs.len() * mem::size_of::<PointBytes>()
    }

    fn write(&self, buffer: &mut [u8]) {
        for (p, b) in self
            .points()
            .zip(buffer.chunks_exact_mut(mem::size_of::<PointBytes>()))
        {
            b.copy_from_slice(&encode_point(p));
        }
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        buffer
            .chunks_exact(mem::size_of::<PointBytes>())
            .map(|p| decode_point(p.try_into().ok()?))
            .collect::<Option<Vec<ProjectivePoint>>>()
            .map(GroupPolynomial::new)
    }
}

impl FixedExternalSize for DLogProof {
    const SIZE: usize =
        mem::size_of::<PointBytes>() + mem::size_of::<ScalarBytes>();
}

impl Wrap for DLogProof {
    fn external_size(&self) -> usize {
        Self::SIZE
    }

    fn write(&self, buffer: &mut [u8]) {
        let (t, s) = buffer.split_at_mut(mem::size_of::<PointBytes>());

        self.t.write(t);
        self.s.write(s);
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        let (t, s) = buffer.split_at(mem::size_of::<PointBytes>());

        let t = AffinePoint::read(t)?;
        let s = Scalar::read(s)?;

        Some(DLogProof { t, s })
    }
}

impl Wrap for Vec<u8> {
    fn external_size(&self) -> usize {
        self.len()
    }

    fn write(&self, buffer: &mut [u8]) {
        buffer.copy_from_slice(self)
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        Some(buffer.to_vec())
    }
}

impl<T: Wrap + FixedExternalSize> Wrap for Vec<T> {
    fn external_size(&self) -> usize {
        self.len() * T::SIZE
    }

    fn write(&self, buffer: &mut [u8]) {
        for (v, b) in self.iter().zip(buffer.chunks_exact_mut(T::SIZE)) {
            v.write(b);
        }
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        buffer
            .chunks_exact(T::SIZE)
            .map(T::read)
            .collect::<Option<Vec<T>>>()
    }
}

impl Wrap for u8 {
    fn external_size(&self) -> usize {
        1
    }

    fn write(&self, buffer: &mut [u8]) {
        buffer[0] = *self;
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        buffer.first().copied()
    }
}

impl Wrap for u16 {
    fn external_size(&self) -> usize {
        2
    }

    fn write(&self, buffer: &mut [u8]) {
        buffer[..2].copy_from_slice(&self.to_le_bytes());
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        Some(u16::from_le_bytes(buffer.get(..2)?.try_into().unwrap()))
    }
}
