use k256::{AffinePoint, NonZeroScalar, ProjectivePoint, Scalar, Secp256k1};
use serde::{Deserialize, Serialize};
use sl_mpc_mate::{
    impl_basemessage,
    math::GroupPolynomial,
    nacl::{EncryptedData, Signature},
    traits::{HasFromParty, PersistentObject},
    HashBytes, SessionId,
};
use sl_oblivious::{
    serialization::serde_projective_point,
    soft_spoken::{ReceiverOTSeed, SenderOTSeed},
    zkproofs::DLogProof,
};

use super::{get_idx_from_id, HasVsotMsg};

// TODO: Change all usizes to u32 or u64

/// Type for the key generation protocol's message 1.
#[derive(Serialize, Deserialize, Clone)]
pub struct KeygenMsg1 {
    /// Participant Id of the sender
    pub from_party: usize,

    /// Sesssion id
    pub session_id: SessionId,

    /// Participant point x_i
    pub x_i: NonZeroScalar,

    /// Hierarchical level of the participant. In the range `[0, t-1]`.
    pub rank: usize,

    /// Participants commitment
    pub commitment: HashBytes,

    /// Participants signature of the message
    #[serde(with = "serde_arrays")]
    pub signature: Signature,
}

/// Type for the key generation protocol's message 2.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KeygenMsg2 {
    /// Participant Id of the sender
    pub from_party: usize,

    /// Participants signature of the message
    #[serde(with = "serde_arrays")]
    pub signature: Signature,

    /// Sesssion id
    pub session_id: SessionId,

    /// Random 32 bytes
    pub r_i: [u8; 32],

    /// Participants Fik values
    pub big_f_i_vector: GroupPolynomial<Secp256k1>,

    /// Encrypted VSOT msg 1
    pub enc_vsot_msgs1: Vec<EncryptedData>,

    /// Participants dlog proof
    pub dlog_proofs_i: Vec<DLogProof>,
}

/// Type for the key generation protocol's message 3.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KeygenMsg3 {
    /// Participant Id of the sender
    pub from_party: usize,

    /// Session id
    pub session_id: SessionId,

    /// Participants Fi values
    pub big_f_vec: GroupPolynomial<Secp256k1>,

    /// Encrypted fi values
    pub encrypted_d_i_vec: Vec<EncryptedData>,

    /// Encrypted VSOT msg 2
    pub enc_vsot_msgs2: Vec<EncryptedData>,

    /// Participants signature of the message
    #[serde(with = "serde_arrays")]
    pub signature: Signature,
}

impl HasVsotMsg for KeygenMsg2 {
    fn get_vsot_msg(&self, party_id: usize) -> &EncryptedData {
        &self.enc_vsot_msgs1[get_idx_from_id(self.get_pid(), party_id)]
    }
}

// TODO: Remove multiple impls?
impl HasVsotMsg for KeygenMsg3 {
    fn get_vsot_msg(&self, party_id: usize) -> &EncryptedData {
        &self.enc_vsot_msgs2[get_idx_from_id(self.get_pid(), party_id)]
    }
}

impl HasVsotMsg for KeygenMsg4 {
    fn get_vsot_msg(&self, party_id: usize) -> &EncryptedData {
        &self.enc_vsot_msgs3[get_idx_from_id(self.get_pid(), party_id)]
    }
}

impl HasVsotMsg for KeygenMsg5 {
    fn get_vsot_msg(&self, party_id: usize) -> &EncryptedData {
        &self.enc_vsot_msgs4[get_idx_from_id(self.get_pid(), party_id)]
    }
}

impl HasVsotMsg for KeygenMsg6 {
    fn get_vsot_msg(&self, party_id: usize) -> &EncryptedData {
        &self.enc_vsot_msgs5[get_idx_from_id(self.get_pid(), party_id)]
    }
}

/// Type for the key generation protocol's message 4.
#[derive(Serialize, Deserialize, Clone)]
pub struct KeygenMsg4 {
    /// Participant Id of the sender
    pub from_party: usize,

    /// Session id
    pub session_id: SessionId,

    /// Big s_i value
    #[serde(with = "serde_projective_point")]
    pub big_s_i: ProjectivePoint,

    /// Public key
    #[serde(with = "serde_projective_point")]
    pub public_key: ProjectivePoint,

    /// dlog proof
    pub dlog_proof: DLogProof,

    /// Encrypted VSOT msg 3
    pub enc_vsot_msgs3: Vec<EncryptedData>,

    /// Participants signature of the message
    #[serde(with = "serde_arrays")]
    pub signature: Signature,
}

/// Type for the key generation protocol's message 5.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KeygenMsg5 {
    /// Participant Id of the sender
    pub from_party: usize,

    /// Session id
    pub session_id: SessionId,

    /// Encrypted VSOT msg 3
    pub enc_vsot_msgs4: Vec<EncryptedData>,

    /// Participants signature of the message
    #[serde(with = "serde_arrays")]
    pub signature: Signature,
}
/// Type for the key generation protocol's message 5.
#[derive(Serialize, Deserialize, Clone)]
pub struct KeygenMsg6 {
    /// Participant Id of the sender
    pub from_party: usize,

    /// Session id
    pub session_id: SessionId,

    /// Encrypted VSOT msg 3
    pub enc_vsot_msgs5: Vec<EncryptedData>,

    /// Encrypted pprf outputs
    pub enc_pprf_outputs: Vec<EncryptedData>,

    /// Encrypted seed_i_j values
    pub enc_seed_i_j_list: Vec<EncryptedData>,

    /// Participants signature of the message
    #[serde(with = "serde_arrays")]
    pub signature: Signature,
}

/// Keyshare of a party.
#[allow(unused)]
pub struct Keyshare {
    /// Threshold value
    pub threshold: usize,
    /// Total number of parties
    pub total_parties: usize,
    /// Party Id of the sender
    pub party_id: usize,
    pub(crate) x_i: NonZeroScalar,
    /// Participants rank
    pub rank: usize,
    pub(crate) s_i: Scalar,
    /// Public key of the generated key.
    pub public_key: ProjectivePoint,
    pub(crate) big_s_list: Vec<ProjectivePoint>,
    pub(crate) x_i_list: Vec<NonZeroScalar>,
    pub(crate) rank_list: Vec<usize>,
    ///
    pub seed_ot_receivers: Vec<ReceiverOTSeed>,
    ///
    pub seed_ot_senders: Vec<SenderOTSeed>,
    /// Seed values sent to the other parties
    pub sent_seed_list: Vec<[u8; 32]>,
    /// Seed values received from the other parties
    pub rec_seed_list: Vec<[u8; 32]>,
}

#[derive(Serialize, Deserialize, Debug)]
/// Final message of the key generation protocol.
pub struct KeyGenCompleteMsg {
    /// Participant Id of the sender
    pub from_party: usize,

    /// Public key of the generated key.
    pub public_key: AffinePoint,
}

impl PersistentObject for KeygenMsg1 {}
impl PersistentObject for KeygenMsg2 {}
impl PersistentObject for KeygenMsg3 {}
impl PersistentObject for KeygenMsg4 {}
impl PersistentObject for KeygenMsg5 {}
impl PersistentObject for KeygenMsg6 {}
impl PersistentObject for KeyGenCompleteMsg {}

impl_basemessage!(KeygenMsg1, KeygenMsg2, KeygenMsg3, KeygenMsg4, KeygenMsg5, KeygenMsg6);
