// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use core::{mem, ops::Deref};

use derivation_path::DerivationPath;
use k256::{NonZeroScalar, ProjectivePoint, Scalar};
use zeroize::ZeroizeOnDrop;

use sl_oblivious::soft_spoken::{ReceiverOTSeed, SenderOTSeed};

use sl_mpc_mate::bip32::{
    derive_child_pubkey, derive_xpub, get_finger_print, BIP32Error,
    KeyFingerPrint, Prefix, XPubKey,
};

use crate::proto::*;

use self::details::KeyshareInfo;

mod details;

/// Key share of a party.
#[derive(Clone, ZeroizeOnDrop)]
pub struct Keyshare {
    buffer: Vec<u8>,
}

impl Keyshare {
    /// Identified of key share data
    pub const MAGIC: [u8; 4] = [0, 0, 0, 1];
}

impl Keyshare {
    const INFO: usize = mem::size_of::<details::KeyshareInfo>();
    const OTHER: usize = mem::size_of::<details::OtherParty>();
    const EACH: usize = mem::size_of::<details::EachParty>();

    // Calculate size of memory buffer to hold a Keyshare for `n`
    // participants with `extra` additional bytes.
    fn calculate_size(n: u8, extra: usize) -> usize {
        assert!(n > 1);

        Self::INFO
            + (n as usize) * Self::EACH
            + (n as usize - 1) * Self::OTHER
            + extra
    }

    /// Allocate an instance of a key share with given parameters.
    pub fn new(n: u8, t: u8, id: u8, extra: &[u8]) -> Keyshare {
        let size = Self::calculate_size(n, extra.len());
        let mut buffer = vec![0u8; size];

        buffer[size - extra.len()..].copy_from_slice(extra);

        let mut share = Self { buffer };

        let info = share.info_mut();

        info.magic = Self::MAGIC;
        info.total_parties = n;
        info.threshold = t;
        info.party_id = id;
        info.extra = (extra.len() as u32).to_be_bytes();

        share
    }

    fn is_valid_buffer(buffer: &[u8]) -> bool {
        if buffer.len() <= Self::INFO {
            return false;
        }

        let info = match bytemuck::try_from_bytes::<KeyshareInfo>(
            &buffer[..Self::INFO],
        )
        .ok()
        {
            Some(info) => info,
            _ => return false,
        };

        // the only magic we could proces at the moment.
        if info.magic != Self::MAGIC {
            return false;
        }

        if info.threshold < 2 || info.threshold > info.total_parties {
            return false;
        }

        if decode_point(&info.public_key).is_none() {
            return false;
        }

        if decode_scalar(&info.s_i).is_none() {
            return false;
        }

        let extra: usize = u32::from_be_bytes(info.extra) as usize;
        let size = Self::calculate_size(info.total_parties, extra);

        if size != buffer.len() {
            return false;
        }

        true
    }

    /// Create a key share from slice of bytes.
    pub fn from_bytes(buffer: &[u8]) -> Option<Self> {
        if Self::is_valid_buffer(buffer) {
            Some(Self {
                buffer: buffer.to_vec(),
            })
        } else {
            None
        }
    }

    /// Create a key share from a given vector. Returns a passed
    /// vector in case of an error.
    pub fn from_vec(buffer: Vec<u8>) -> Result<Self, Vec<u8>> {
        if Self::is_valid_buffer(&buffer) {
            Ok(Self { buffer })
        } else {
            Err(buffer)
        }
    }

    /// Return underlying byte slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.buffer
    }

    /// Return public key as ProjectiveProint.
    pub fn public_key(&self) -> ProjectivePoint {
        decode_point(&self.info().public_key).unwrap()
    }

    /// Return vector of ranks
    pub fn rank_list(&self) -> Vec<u8> {
        (0..self.info().total_parties)
            .map(|p| self.each(p).rank)
            .collect()
    }

    /// x_i_list
    pub fn x_i_list(&self) -> Vec<NonZeroScalar> {
        (0..self.info().total_parties)
            .map(|p| decode_nonzero(&self.each(p).x_i).unwrap())
            .collect()
    }

    pub(crate) fn get_x_i(&self, party_id: u8) -> NonZeroScalar {
        NonZeroScalar::new(decode_scalar(&self.each(party_id).x_i).unwrap())
            .unwrap()
    }

    /// Return true if all parties has rank zero.
    pub fn zero_ranks(&self) -> bool {
        for p in 0..self.info().total_parties {
            if self.each(p).rank != 0 {
                return false;
            }
        }

        true
    }

    /// Return rank of a party.
    pub fn get_rank(&self, party_id: u8) -> u8 {
        self.each(party_id).rank
    }

    /// Return the secret scalar s_i.
    pub fn s_i(&self) -> Scalar {
        decode_scalar(&self.info().s_i).unwrap()
    }

    /// Return user defined data embedded into the key share. The data
    /// is passed via setup message at time of key generation and are
    /// immutable.
    pub fn extra_data(&self) -> &[u8] {
        let n = self.info().total_parties as usize;
        let offset = Self::INFO + Self::OTHER * (n - 1) + Self::EACH * n;

        &self.buffer[offset..]
    }

    pub(crate) fn info(&self) -> &details::KeyshareInfo {
        let bytes = &self.buffer[..Self::INFO];
        bytemuck::from_bytes(bytes)
    }

    pub(crate) fn info_mut(&mut self) -> &mut details::KeyshareInfo {
        let bytes = &mut self.buffer[..Self::INFO];

        bytemuck::from_bytes_mut(bytes)
    }

    pub(crate) fn other_mut(
        &mut self,
        party_id: u8,
    ) -> &mut details::OtherParty {
        assert!(party_id < self.info().total_parties);

        let n = self.info().total_parties as usize;
        let offset = Self::INFO + Self::EACH * n;

        let idx = self.get_idx_from_id(party_id);
        let bytes = &mut self.buffer[offset..][..Self::OTHER * (n - 1)];

        let others: &mut [details::OtherParty] =
            bytemuck::cast_slice_mut(bytes);

        &mut others[idx]
    }

    pub(crate) fn other(&self, party_id: u8) -> &details::OtherParty {
        assert!(party_id < self.info().total_parties);

        let n = self.info().total_parties as usize;
        let offset = Self::INFO + Self::EACH * n;

        let bytes = &self.buffer[offset..][..Self::OTHER * (n - 1)];

        let others: &[details::OtherParty] = bytemuck::cast_slice(bytes);

        &others[self.get_idx_from_id(party_id)]
    }

    pub(crate) fn each_mut(
        &mut self,
        party_id: u8,
    ) -> &mut details::EachParty {
        assert!(party_id < self.info().total_parties);

        let n = self.info().total_parties as usize;

        let bytes = &mut self.buffer[Self::INFO..][..Self::EACH * n];
        let each: &mut [details::EachParty] = bytemuck::cast_slice_mut(bytes);

        &mut each[party_id as usize]
    }

    pub(crate) fn each(&self, party_id: u8) -> &details::EachParty {
        assert!(party_id < self.info().total_parties);

        let n = self.info().total_parties as usize;

        let bytes = &self.buffer[Self::INFO..][..Self::EACH * n];
        let each: &[details::EachParty] = bytemuck::cast_slice(bytes);

        &each[party_id as usize]
    }

    /// Get the big S value of another party
    pub fn big_s(&self, party_id: u8) -> ProjectivePoint {
        decode_point(&self.each(party_id).big_s).unwrap()
    }

    fn get_idx_from_id(&self, party_id: u8) -> usize {
        assert!(self.info().party_id != party_id);
        let idx = if party_id > self.info().party_id {
            party_id - 1
        } else {
            party_id
        };

        idx as _
    }

    pub(crate) fn sender_seed(&self, party_id: u8) -> &SenderOTSeed {
        &self.other(party_id).send_ot_seed
    }

    pub(crate) fn receiver_seed(&self, party_id: u8) -> &ReceiverOTSeed {
        &self.other(party_id).recv_ot_seed
    }
}

impl Deref for Keyshare {
    type Target = details::KeyshareInfo;

    fn deref(&self) -> &Self::Target {
        let bytes = &self.buffer[..Self::INFO];

        bytemuck::from_bytes(bytes)
    }
}

impl Keyshare {
    /// Returns root chain code
    pub fn root_chain_code(&self) -> [u8; 32] {
        self.info().root_chain_code
    }

    /// Returns public key as ProjectivePoint
    pub fn root_public_key(&self) -> ProjectivePoint {
        self.public_key()
    }
}

// Separate impl for BIP32 related functions
impl Keyshare {
    /// Get the fingerprint of the root public key
    pub fn get_finger_print(&self) -> KeyFingerPrint {
        get_finger_print(&self.root_public_key())
    }

    /// Get the additive offset of a key share for a given derivation path
    pub fn derive_with_offset(
        &self,
        chain_path: &DerivationPath,
    ) -> Result<(Scalar, ProjectivePoint), BIP32Error> {
        let mut pubkey = self.root_public_key();
        let mut chain_code = self.root_chain_code();
        let mut additive_offset = Scalar::ZERO;
        for child_num in chain_path {
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
        derive_xpub(
            prefix,
            &self.root_public_key(),
            self.root_chain_code(),
            chain_path,
        )
    }
}
