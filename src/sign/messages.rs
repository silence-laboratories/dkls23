use k256::{ProjectivePoint, Scalar};

use sl_mpc_mate::{message::*, HashBytes, SessionId};

use zeroize::{Zeroize, ZeroizeOnDrop};

use super::pairwise_mta::MtaRound2Output;

/// Type for the sign gen message 1.
#[derive(bincode::Encode, bincode::Decode)]
pub struct SignMsg1 {
    /// Sesssion id
    pub session_id: Opaque<SessionId>,

    /// Commitment hash
    pub commitment_r_i: Opaque<HashBytes>,

    /// Participant encryption public key
    pub enc_pk: Opaque<[u8; 32]>,

    /// Party Id (form Keyshare)
    pub party_id: u8,
}

/// Type for the sign gen message 3. P2P
#[derive(Debug, bincode::Encode, bincode::Decode)]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SignMsg3 {
    /// encrypted data
    pub mta_msg2: MtaRound2Output,

    /// Encrypted data
    pub digest_i: Opaque<HashBytes>,

    /// Encrypted data
    pub big_x_i: Opaque<ProjectivePoint, GR>,

    /// Encrypted data
    pub big_r_i: Opaque<ProjectivePoint, GR>,

    /// encrypted data
    pub blind_factor: Opaque<[u8; 32]>,

    /// Encrypted data
    pub gamma0: Opaque<ProjectivePoint, GR>,

    /// Encrypted data
    pub gamma1: Opaque<ProjectivePoint, GR>,

    /// Encrypted psi scalar
    pub psi: Opaque<Scalar, PF>,
}

/// Type for the sign gen message 4.
#[derive(Debug, bincode::Encode, bincode::Decode)]
pub struct SignMsg4 {
    /// Sesssion id
    pub session_id: Opaque<SessionId>,

    /// s_0 Scalar
    pub s_0: Opaque<Scalar, PF>,

    /// s_1 Scalar
    pub s_1: Opaque<Scalar, PF>,
}

/// Result after pre-signature of party_i
#[derive(bincode::Encode, bincode::Decode)]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PreSignResult {
    /// final_session_id
    pub final_session_id: Opaque<SessionId>,

    /// public_key
    pub public_key: Opaque<ProjectivePoint, GR>,

    /// s_0 Scalar
    pub s_0: Opaque<Scalar, PF>,

    /// s_1 Scalar
    pub s_1: Opaque<Scalar, PF>,

    /// R point
    pub r: Opaque<ProjectivePoint, GR>,

    /// phi_i Scalar
    pub phi_i: Opaque<Scalar, PF>,
}

/// Partial signature of party_i
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PartialSignature {
    /// final_session_id
    pub final_session_id: SessionId,

    /// public_key
    pub public_key: ProjectivePoint,

    /// 32 bytes message_hash
    pub message_hash: HashBytes,

    /// s_0 Scalar
    pub s_0: Scalar,

    /// s_1 Scalar
    pub s_1: Scalar,

    /// R point
    pub r: ProjectivePoint,
}
