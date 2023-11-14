use std::time::Duration;

use k256::{
    elliptic_curve::{group::GroupEncoding, CurveArithmetic},
    NonZeroScalar, ProjectivePoint, Scalar,
};

use sl_mpc_mate::{math::GroupPolynomial, message::*, ByteArray};
use sl_oblivious::zkproofs::DLogProof;

use crate::setup::ABORT_MESSAGE_TAG;

fn abort_message_id(instance: &InstanceId, sender_vk: &VerifyingKey) -> MsgId {
    MsgId::new(instance, sender_vk.as_bytes(), None, ABORT_MESSAGE_TAG)
}

/// Create an Abort Message.
pub fn create_abort_message(
    instance: &InstanceId,
    ttl: Duration,
    signing_key: &SigningKey,
) -> Vec<u8> {
    let sender_vk = signing_key.verifying_key();

    let msg_id = abort_message_id(instance, &sender_vk);

    Builder::<Signed>::encode(
        &msg_id,
        ttl,
        signing_key,
        &(), // emoty message
    )
    .unwrap() // can't fail, because &() is always encodable
}

/// A type with some external represention, encodable/decodable by
/// bincode crate.
pub trait Wrap {
    /// External representation
    type Wrapped: bincode::Encode + bincode::Decode;

    /// Convert a value into external repr
    fn wrap(self) -> Self::Wrapped;

    /// Convert from an external  repr into Self
    fn unwrap(value: Self::Wrapped) -> Self;
}

impl<const N: usize> Wrap for ByteArray<N> {
    type Wrapped = Opaque<Self>;

    fn wrap(self) -> Self::Wrapped {
        Opaque::from(self)
    }

    fn unwrap(value: Self::Wrapped) -> Self {
        value.0
    }
}

impl Wrap for Scalar {
    type Wrapped = Opaque<Self, PF>;

    fn wrap(self) -> Self::Wrapped {
        Opaque::from(self)
    }

    fn unwrap(value: Self::Wrapped) -> Self {
        value.0
    }
}

impl Wrap for NonZeroScalar {
    type Wrapped = Opaque<Self, NZ>;

    fn wrap(self) -> Self::Wrapped {
        Opaque::from(self)
    }

    fn unwrap(value: Self::Wrapped) -> Self {
        value.0
    }
}

impl Wrap for ProjectivePoint {
    type Wrapped = Opaque<Self, GR>;

    fn wrap(self) -> Self::Wrapped {
        Opaque::from(self)
    }

    fn unwrap(value: Self::Wrapped) -> Self {
        value.0
    }
}

impl<const N: usize> Wrap for [u8; N] {
    type Wrapped = Opaque<Self>;

    fn wrap(self) -> Self::Wrapped {
        Opaque::from(self)
    }

    fn unwrap(value: Self::Wrapped) -> Self {
        value.0
    }
}

impl Wrap for PublicKey {
    type Wrapped = Opaque<[u8; 32]>;

    fn wrap(self) -> Self::Wrapped {
        Opaque::from(self.to_bytes())
    }

    fn unwrap(value: Self::Wrapped) -> Self {
        From::from(value.0)
    }
}

impl<C> Wrap for GroupPolynomial<C>
where
    C: CurveArithmetic,
    C::ProjectivePoint: GroupEncoding,
{
    type Wrapped = Vec<Opaque<C::ProjectivePoint, GR>>;

    fn wrap(self) -> Self::Wrapped {
        self.coeffs
    }

    fn unwrap(coeffs: Self::Wrapped) -> Self {
        Self { coeffs }
    }
}

impl Wrap for DLogProof {
    type Wrapped = Self;

    fn wrap(self) -> Self::Wrapped {
        self
    }

    fn unwrap(value: Self::Wrapped) -> Self {
        value
    }
}

impl<T: Wrap + 'static> Wrap for Vec<T> {
    type Wrapped = Vec<T::Wrapped>;

    fn wrap(self) -> Self::Wrapped {
        self.into_iter().map(T::wrap).collect()
    }

    fn unwrap(values: Self::Wrapped) -> Self {
        values.into_iter().map(T::unwrap).collect()
    }
}
