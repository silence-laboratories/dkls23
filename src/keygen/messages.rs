use k256::{NonZeroScalar, ProjectivePoint, Scalar, Secp256k1};

use sl_mpc_mate::{math::GroupPolynomial, message::*, SessionId};

use sl_oblivious::{
    endemic_ot::EndemicOTMsg2,
    soft_spoken::{PPRFOutput, ReceiverOTSeed, SenderOTSeed},
};

use sl_mpc_mate::bip32::{
    derive_child_pubkey, derive_xpub, get_finger_print, BIP32Error, KeyFingerPrint, Prefix, XPubKey,
};

use zeroize::{Zeroize, ZeroizeOnDrop};

use derivation_path::DerivationPath;

/// Type for the key generation protocol's message 3. P2P
#[derive(Debug, bincode::Encode, bincode::Decode, Zeroize, ZeroizeOnDrop)]
pub struct KeygenMsg3 {
    /// Participants Fi values
    #[zeroize(skip)]
    pub big_f_vec: GroupPolynomial<Secp256k1>, // == t-1, FIXME:

    ///
    pub d_i: Opaque<Scalar, PF>,

    /// base OT msg 2
    pub base_ot_msg2: EndemicOTMsg2,

    /// pprf outputs
    pub pprf_output: Vec<PPRFOutput>, // 256 / SOFT_SPOKEN_K

    /// seed_i_j values
    pub seed_i_j: Option<[u8; 32]>,

    /// chain_code_sid
    pub chain_code_sid: Opaque<SessionId>,

    /// Random 32 bytes
    pub r_i_2: Opaque<[u8; 32]>,
}

/// Keyshare of a party.
#[derive(Clone, bincode::Encode, bincode::Decode, Zeroize, ZeroizeOnDrop)]
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

    /// Root chain code (used to derive child public keys)
    pub root_chain_code: [u8; 32],

    ///
    pub seed_ot_receivers: Vec<ReceiverOTSeed>, // N-1

    ///
    pub seed_ot_senders: Vec<SenderOTSeed>, // N-1

    /// Seed values sent to the other parties
    pub sent_seed_list: Vec<[u8; 32]>, // [0..N-1]

    /// Seed values received from the other parties
    pub rec_seed_list: Vec<[u8; 32]>, // [0..N-1]

    /// Final session ID
    pub final_session_id: Opaque<SessionId>,

    pub(crate) s_i: Opaque<Scalar, PF>,
    pub(crate) big_s_list: Vec<Opaque<ProjectivePoint, GR>>, // N
    pub(crate) x_i_list: Vec<Opaque<NonZeroScalar, NZ>>,     // N
}

impl Keyshare {
    /// Identified of key share data
    pub const MAGIC: u32 = 1u32;
}

// Separate impl for BIP32 related functions
impl Keyshare {
    /// Get the fingerprint of the root public key
    pub fn get_finger_print(&self) -> KeyFingerPrint {
        get_finger_print(&self.public_key)
    }

    /// Get the additive offset of a key share for a given derivation path
    pub fn derive_with_offset(
        &self,
        chain_path: &DerivationPath,
    ) -> Result<(Scalar, ProjectivePoint), BIP32Error> {
        let mut pubkey = self.public_key.0;
        let mut chain_code = self.root_chain_code;
        let mut additive_offset = Scalar::ZERO;
        for child_num in chain_path.into_iter() {
            let (il_int, child_pubkey, child_chain_code) =
                derive_child_pubkey(&pubkey, chain_code, child_num)?;
            pubkey = child_pubkey;
            chain_code = child_chain_code;
            additive_offset += il_int;
        }

        // Perform the mod q operation to get the additive offset
        Ok((additive_offset, pubkey))
    }

    /// Derive the child public key for a given derivation path
    pub fn derive_child_pubkey(
        &self,
        chain_path: &DerivationPath,
    ) -> Result<ProjectivePoint, BIP32Error> {
        let (_, child_pubkey) = self.derive_with_offset(chain_path)?;

        Ok(child_pubkey)
    }

    /// Derive the extended public key for a given derivation path and prefix
    /// # Arguments
    /// * `prefix` - Prefix for the extended public key (`Prefix` has commonly used prefixes)
    /// * `chain_path` - Derivation path
    ///
    /// # Returns
    /// * `XPubKey` - Extended public key
    pub fn derive_xpub(
        &self,
        prefix: Prefix,
        chain_path: DerivationPath,
    ) -> Result<XPubKey, BIP32Error> {
        derive_xpub(prefix, &self.public_key, self.root_chain_code, chain_path)
    }
}
