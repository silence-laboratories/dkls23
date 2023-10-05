use k256::{
    elliptic_curve::{group::GroupEncoding, CurveArithmetic},
    AffinePoint, NonZeroScalar, ProjectivePoint, Scalar, Secp256k1,
};

use sl_mpc_mate::{math::GroupPolynomial, message::*, HashBytes, SessionId};

use sl_oblivious::{
    soft_spoken::{PPRFOutput, ReceiverOTSeed, SenderOTSeed},
    endemic_ot::EndemicOTMsg2,
    zkproofs::DLogProof,
};

/// Type for the key generation protocol's message 1.
#[derive(bincode::Encode, bincode::Decode)]
pub struct KeygenMsg1 {
    /// Sesssion id
    pub session_id: Opaque<SessionId>,

    /// Participant point x_i
    pub x_i: Opaque<Scalar, PF>, // FIXME: NonZeroScalar,

    /// Participants commitment
    pub commitment: Opaque<HashBytes>,

    /// Participant encryption public key
    pub enc_pk: Opaque<[u8; 32]>,
}

/// Type for the key generation protocol's message 2.
#[derive(bincode::Encode, bincode::Decode)]
#[bincode(
    bounds = "C: CurveArithmetic, C::ProjectivePoint: GroupEncoding",
    // borrow_decode_bounds = "'__de: 'a, C: CurveArithmetic, C::ProjectivePoint: GroupEncoding"
)]
pub struct KeygenMsg2<C = Secp256k1>
where
    C: CurveArithmetic,
    C::ProjectivePoint: GroupEncoding,
{
    /// Sesssion id
    pub session_id: Opaque<SessionId>,

    /// Random 32 bytes
    pub r_i: Opaque<[u8; 32]>,

    /// Participants Fik values
    pub big_f_i_vector: GroupPolynomial<C>,

    /// Participants dlog proof
    pub dlog_proofs_i: Vec<DLogProof>,
}

/// Type for the key generation protocol's message 3.
#[derive(Clone, Debug, bincode::Encode, bincode::Decode)]
pub struct KeygenMsg3 {
    /// Session id
    pub session_id: Opaque<SessionId>,

    /// Participants Fi values
    pub big_f_vec: GroupPolynomial<Secp256k1>,

    ///
    pub d_i: Opaque<Scalar, PF>,

    /// base OT msg 2
    pub base_ot_msg2: EndemicOTMsg2,

    /// pprf outputs
    pub pprf_output: Vec<PPRFOutput>,

    /// seed_i_j values
    pub seed_i_j: Option<[u8; 32]>,
}

/// Type for the key generation protocol's message 4.
#[derive(Clone, Debug, bincode::Encode, bincode::Decode)]
pub struct KeygenMsg4 {
    /// Session id
    pub session_id: Opaque<SessionId>,

    /// Big s_i value
    pub big_s_i: Opaque<ProjectivePoint, GR>,

    /// Public key
    pub public_key: Opaque<ProjectivePoint, GR>,

    /// dlog proof
    pub dlog_proof: DLogProof,
}

#[derive(Clone, bincode::Encode, bincode::Decode)]
/// Final message of the key generation protocol.
pub struct KeyGenCompleteMsg {
    /// Public key of the generated key.
    pub public_key: Opaque<AffinePoint, GR>,
}

/// Keyshare of a party.
#[allow(unused)]
#[derive(Clone, bincode::Encode, bincode::Decode)]
pub struct Keyshare {
    /// A marker
    pub magic: u32,

    /// Total number of parties
    pub total_parties: u8,

    /// Threshold value
    pub threshold: u8,

    /// Rank of each party
    pub rank_list: Vec<u8>,

    /// Party Id of the sender
    pub party_id: u8,

    /// Public key of the generated key.
    pub public_key: Opaque<ProjectivePoint, GR>,

    ///
    pub seed_ot_receivers: Vec<ReceiverOTSeed>,

    ///
    pub seed_ot_senders: Vec<SenderOTSeed>,

    /// Seed values sent to the other parties
    pub sent_seed_list: Vec<[u8; 32]>,

    /// Seed values received from the other parties
    pub rec_seed_list: Vec<[u8; 32]>,

    pub(crate) s_i: Opaque<Scalar, PF>,
    pub(crate) big_s_list: Vec<Opaque<ProjectivePoint, GR>>,
    pub(crate) x_i_list: Vec<Opaque<NonZeroScalar, NZ>>,
}

impl Keyshare {
    /// Identified of key share data
    pub const MAGIC: u32 = 1u32;
}
