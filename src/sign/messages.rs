use k256::Scalar;
use serde::{Deserialize, Serialize};
use sl_mpc_mate::{
    impl_basemessage,
    nacl::{EncryptedData, Signature},
    traits::{HasToParty, PersistentObject},
    HashBytes, SessionId,
};

/// Type for the sign gen message 1.
#[derive(Serialize, Deserialize, Clone)]
pub struct SignMsg1 {
    /// Participant Id of the sender
    pub from_party: usize,
    /// Signature
    #[serde(with = "serde_arrays")]
    pub signature: Signature,
    /// Sesssion id
    pub session_id: SessionId,
    /// Commitment hash
    pub commitment_r_i: HashBytes,
}

/// Type for the sign gen message 2.
#[derive(Serialize, Deserialize, Clone)]
pub struct SignMsg2 {
    /// Participant Id of the sender
    pub from_party: usize,
    /// Participant Id of the receiver
    pub to_party: usize,
    /// Signature
    #[serde(with = "serde_arrays")]
    pub signature: Signature,
    /// Sesssion id
    pub session_id: SessionId,
    /// Encrypted mta message
    pub enc_mta_msg1: EncryptedData,
}

/// Type for the sign gen message 3.
#[derive(Serialize, Deserialize, Clone)]
pub struct SignMsg3 {
    /// Participant Id of the sender
    pub from_party: usize,
    /// Participant Id of the receiver
    pub to_party: usize,
    /// Signature
    #[serde(with = "serde_arrays")]
    pub signature: Signature,
    /// Sesssion id
    pub session_id: SessionId,
    /// Encrypted data
    pub enc_mta_msg2: EncryptedData,
    /// Encrypted data
    pub enc_digest_i: EncryptedData,
    /// Encrypted data
    pub enc_big_x_i: EncryptedData,
    /// Encrypted data
    pub enc_big_r_i: EncryptedData,
    /// Encrypted data
    pub enc_blind_factor: EncryptedData,
    /// Encrypted data
    pub enc_gamma0: EncryptedData,
    /// Encrypted data
    pub enc_gamma1: EncryptedData,
}

impl HasToParty for SignMsg2 {
    fn get_receiver(&self) -> usize {
        self.to_party
    }
}

impl HasToParty for SignMsg3 {
    fn get_receiver(&self) -> usize {
        self.to_party
    }
}

/// Type for the sign gen message 4.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SignMsg4 {
    /// Sesssion id
    pub session_id: SessionId,
    /// s_0 Scalar
    pub s_0: Scalar,
    /// s_1 Scalar
    pub s_1: Scalar,
    /// Participant Id of the sender
    pub from_party: usize,
    /// Signature
    #[serde(with = "serde_arrays")]
    pub signature: Signature,
}

// /// Type for the sign gen message 5.
// #[derive(Serialize, Deserialize, Clone, Debug)]
// pub struct Msg5 {
//     /// Participant Id of the sender
//     pub from_party: usize,
//     /// Signature
//     #[serde(with = "serde_arrays")]
//     pub signature: Signature,
//     /// Sesssion id
//     pub session_id: SessionId,
//     /// r_i
//     pub r_i: [u8; 32],
//     /// Big A hat i
//     pub big_a_hat_i: Point<Secp256k1>,
//     /// Discrete log proof of a_i
//     pub dlog_proof_a_i: CustomDLogProof,
// }

// /// Type for the sign gen message 6.
// #[derive(Serialize, Deserialize, Clone)]
// pub struct Msg6 {
//     /// Participant Id of the sender
//     pub from_party: usize,
//     #[serde(with = "serde_arrays")]
//     /// Signature
//     pub signature: Signature,
//     /// Sesssion id
//     pub session_id: SessionId,
//     /// Commitment 2 hash
//     pub commitment2_i: [u8; 32],
// }

// /// Type for the sign gen message 7.
// #[derive(Serialize, Deserialize, Clone)]
// pub struct Msg7 {
//     /// Participant Id of the sender
//     pub from_party: usize,
//     /// Signature
//     #[serde(with = "serde_arrays")]
//     pub signature: Signature,
//     /// Sesssion id
//     pub session_id: SessionId,
//     /// r2_i
//     pub r2_i: [u8; 32],
//     /// Big rho i
//     pub big_rho_i: Point<Secp256k1>,
//     /// Discrete log proof of rho i
//     pub dlog_proof_rho_i: CustomDLogProof,
//     /// Big V i
//     pub big_v_i: Point<Secp256k1>,
//     /// Discrete log proof of big V i
//     pub dlog_proof_big_v_i: DLogProof5b,
// }
// /// Type for the sign gen message 8.
// #[derive(Serialize, Deserialize, Clone)]
// pub struct Msg8 {
//     /// Participant Id of the sender
//     pub from_party: usize,
//     /// Signature
//     #[serde(with = "serde_arrays")]
//     pub signature: Signature,
//     /// Sesssion id
//     pub session_id: SessionId,
//     /// Commitment 3 hash
//     pub commitment3_i: [u8; 32],
// }

// /// Type for the sign gen message 9.
// #[derive(Serialize, Deserialize, Clone)]
// pub struct Msg9 {
//     /// Participant Id of the sender
//     pub from_party: usize,
//     /// Signature
//     #[serde(with = "serde_arrays")]
//     pub signature: Signature,
//     /// Sesssion id
//     pub session_id: SessionId,
//     /// r3_i
//     pub r3_i: [u8; 32],
//     /// U_i
//     pub big_u_i: Point<Secp256k1>,
//     /// T_i
//     pub big_t_i: Point<Secp256k1>,
// }
// /// Type for the sign gen message 10.
// #[derive(Serialize, Deserialize, Clone)]
// pub struct Msg10 {
//     /// Participant Id of the sender
//     pub from_party: usize,
//     /// Signature
//     #[serde(with = "serde_arrays")]
//     pub signature: Signature,
//     /// Sesssion id
//     pub session_id: SessionId,
//     /// S bar i
//     pub s_bar_i: Scalar<Secp256k1>,
// }

// /// Sign generation complete message
// #[derive(Serialize, Deserialize, Clone, Debug)]
// pub struct SignCompleteMsg {
//     /// Participant Id of the sender
//     pub from_party: usize,
//     /// Final signature of the message to be signed
//     pub signature: Vec<u8>,
// }

impl PersistentObject for SignMsg1 {}
impl PersistentObject for SignMsg2 {}
impl PersistentObject for SignMsg3 {}
impl PersistentObject for SignMsg4 {}
// impl PersistentObject for Msg5 {}
// impl PersistentObject for Msg6 {}
// impl PersistentObject for Msg7 {}
// impl PersistentObject for Msg8 {}
// impl PersistentObject for Msg9 {}
// impl PersistentObject for Msg10 {}

// impl PersistentObject for SignCompleteMsg {}

// impl_basemessage!(Msg1, Msg2, Msg3, Msg4, Msg5, Msg6, Msg7, Msg8, Msg9, Msg10);

impl_basemessage!(SignMsg1, SignMsg2, SignMsg3, SignMsg4);
