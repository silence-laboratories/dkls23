use k256::{ProjectivePoint, Scalar};

use sl_mpc_mate::{message::*, HashBytes, SessionId};

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

/// Type for the sign gen message 3.
#[derive(Debug, bincode::Encode, bincode::Decode)]
pub struct SignMsg3 {
    /// Sesssion id
    pub session_id: Opaque<SessionId>,

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
#[derive(Clone, Debug, bincode::Encode, bincode::Decode)]
pub struct SignMsg4 {
    /// Sesssion id
    pub session_id: Opaque<SessionId>,

    /// s_0 Scalar
    pub s_0: Opaque<Scalar, PF>,

    /// s_1 Scalar
    pub s_1: Opaque<Scalar, PF>,
}
