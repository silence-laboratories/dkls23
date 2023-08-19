use k256::{
    elliptic_curve::{group::GroupEncoding, CurveArithmetic},
    AffinePoint, NonZeroScalar, ProjectivePoint, Scalar, Secp256k1,
};

use sl_mpc_mate::{
    math::GroupPolynomial,
    message::*,
    HashBytes,
    SessionId,
};

use sl_oblivious::{
    soft_spoken::{ReceiverOTSeed, SenderOTSeed},
    vsot::VSOTMsg2,
    zkproofs::DLogProof,
};

/// Type for the key generation protocol's message 1.
#[derive(bincode::Encode, bincode::BorrowDecode)]
pub struct KeygenMsg1<'a> {
    /// Sesssion id
    pub session_id: Opaque<&'a SessionId>,

    /// Participant point x_i
    pub x_i: Opaque<Scalar, PF>, // FIXME: NonZeroScalar,

    /// Participants commitment
    pub commitment: Opaque<&'a HashBytes>,

    /// Participant encryption public key
    pub enc_pk: Opaque<[u8; 32]>,
}

/// Type for the key generation protocol's message 2.
#[derive(bincode::Encode, bincode::BorrowDecode)]
#[bincode(
    bounds = "C: CurveArithmetic, C::ProjectivePoint: GroupEncoding",
    borrow_decode_bounds = "'__de: 'a, C: CurveArithmetic, C::ProjectivePoint: GroupEncoding"
)]
pub struct KeygenMsg2<'a, C = Secp256k1>
where
    C: CurveArithmetic,
    C::ProjectivePoint: GroupEncoding,
{
    /// Sesssion id
    pub session_id: Opaque<&'a SessionId>,

    /// Random 32 bytes
    pub r_i: Opaque<&'a [u8; 32]>,

    /// Participants Fik values
    pub big_f_i_vector: GroupPolynomial<C>,

    /// Participants dlog proof
    pub dlog_proofs_i: Vec<DLogProof>,
}

/// Type for the key generation protocol's message 3.
#[derive(Clone, Debug, bincode::Encode, bincode::BorrowDecode)]
pub struct KeygenMsg3<'a> {
    /// Session id
    pub session_id: Opaque<&'a SessionId>,

    /// Participants Fi values
    pub big_f_vec: GroupPolynomial<Secp256k1>,

    ///
    pub d_i: Opaque<Scalar, PF>,

    /// VSOT msg 2
    pub vsot_msg2: VSOTMsg2,
}

/// Type for the key generation protocol's message 4.
#[derive(Clone, Debug, bincode::Encode, bincode::BorrowDecode)]
pub struct KeygenMsg4<'a> {
    /// Session id
    pub session_id: Opaque<&'a SessionId>,

    /// Big s_i value
    pub big_s_i: Opaque<ProjectivePoint, GR>,

    /// Public key
    pub public_key: Opaque<ProjectivePoint, GR>,

    /// dlog proof
    pub dlog_proof: DLogProof,

    // /// Encrypted VSOT msg 3
    // pub enc_vsot_msgs3: Vec<EncryptedData>,
}

/// Type for the key generation protocol's message 5.
#[derive(Clone, Debug)]
pub struct KeygenMsg5 {
    /// Session id
    pub session_id: SessionId,

    // /// Encrypted VSOT msg 3
    // pub enc_vsot_msgs4: Vec<EncryptedData>,
}

/// Type for the key generation protocol's message 5.
#[derive(Clone)]
pub struct KeygenMsg6 {
    /// Session id
    pub session_id: SessionId,

    // /// Encrypted VSOT msg 3
    // pub enc_vsot_msgs5: Vec<EncryptedData>,

    // /// Encrypted pprf outputs
    // pub enc_pprf_outputs: Vec<EncryptedData>,

    // /// Encrypted seed_i_j values
    // pub enc_seed_i_j_list: Vec<EncryptedData>,
}

/// Keyshare of a party.
#[allow(unused)]
// #[derive(Clone, bincode::Encode, bincode::Decode)]
pub struct Keyshare {
    /// Threshold value
    pub threshold: u8,

    /// Total number of parties
    pub total_parties: u8,

    /// Party Id of the sender
    pub party_id: u8,

    /// Participants rank
    pub rank: u8,

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

    pub(crate) x_i: NonZeroScalar,
    pub(crate) s_i: Scalar,
    pub(crate) big_s_list: Vec<ProjectivePoint>,
    pub(crate) x_i_list: Vec<NonZeroScalar>,
    pub(crate) rank_list: Vec<u8>,
}

// #[derive(Serialize, Deserialize, Debug)]
/// Final message of the key generation protocol.
pub struct KeyGenCompleteMsg {
    /// Public key of the generated key.
    pub public_key: AffinePoint,
}
