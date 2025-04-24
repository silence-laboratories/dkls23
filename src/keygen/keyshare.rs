// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! Key share management for distributed key generation.
//!
//! This module provides functionality for managing key shares in a distributed key generation protocol.
//! A key share represents a party's portion of a distributed secret key, along with associated metadata
//! and cryptographic material needed for protocol operations.
//!
//! The `Keyshare` struct is the main type in this module, providing methods for:
//! - Creating and validating key shares
//! - Accessing key share components (public keys, ranks, etc.)
//! - Deriving child keys and extended public keys
//! - Managing oblivious transfer seeds for protocol operations

use core::{mem, ops::Deref};

use derivation_path::DerivationPath;
use k256::{NonZeroScalar, ProjectivePoint, Scalar};
use zeroize::ZeroizeOnDrop;

use sl_oblivious::soft_spoken::{ReceiverOTSeed, SenderOTSeed};

use sl_mpc_mate::bip32::{
    derive_child_pubkey, derive_xpub, get_finger_print, BIP32Error, KeyFingerPrint, Prefix, XPubKey,
};

use crate::proto::*;

use self::details::KeyshareInfo;

mod details;

/// A key share representing a party's portion of a distributed secret key.
///
/// This struct encapsulates all the information needed for a party to participate in
/// distributed key generation and signing protocols. It includes:
/// - The party's secret share
/// - Public key components
/// - Party ranks and identifiers
/// - Oblivious transfer seeds
/// - Additional protocol-specific data
///
/// The key share is stored in a compact binary format and provides methods for
/// accessing its components and deriving child keys.
#[derive(Clone, ZeroizeOnDrop)]
pub struct Keyshare {
    buffer: Vec<u8>,
}

impl Keyshare {
    /// Magic number identifying valid key share data.
    ///
    /// This constant is used to validate that a byte buffer contains a valid key share.
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

        Self::INFO + (n as usize) * Self::EACH + (n as usize - 1) * Self::OTHER + extra
    }

    /// Creates a new key share with the specified parameters.
    ///
    /// # Arguments
    /// * `n` - Total number of parties in the protocol
    /// * `t` - Threshold value for the protocol
    /// * `id` - ID of this party
    /// * `extra` - Additional data to be embedded in the key share
    ///
    /// # Panics
    /// Panics if `n` is less than 2.
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

        let info = match bytemuck::try_from_bytes::<KeyshareInfo>(&buffer[..Self::INFO]).ok() {
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

    /// Creates a key share from a byte slice.
    ///
    /// # Arguments
    /// * `buffer` - Byte slice containing the key share data
    ///
    /// # Returns
    /// `Some(Keyshare)` if the buffer contains valid key share data, `None` otherwise.
    pub fn from_bytes(buffer: &[u8]) -> Option<Self> {
        if Self::is_valid_buffer(buffer) {
            Some(Self {
                buffer: buffer.to_vec(),
            })
        } else {
            None
        }
    }

    /// Creates a key share from a vector of bytes.
    ///
    /// # Arguments
    /// * `buffer` - Vector containing the key share data
    ///
    /// # Returns
    /// `Ok(Keyshare)` if the vector contains valid key share data, `Err(buffer)` otherwise.
    pub fn from_vec(buffer: Vec<u8>) -> Result<Self, Vec<u8>> {
        if Self::is_valid_buffer(&buffer) {
            Ok(Self { buffer })
        } else {
            Err(buffer)
        }
    }

    /// Returns the underlying byte slice of the key share.
    pub fn as_slice(&self) -> &[u8] {
        &self.buffer
    }

    /// Returns the public key as a `ProjectivePoint`.
    pub fn public_key(&self) -> ProjectivePoint {
        decode_point(&self.info().public_key).unwrap()
    }

    /// Returns a vector of ranks for all parties.
    pub fn rank_list(&self) -> Vec<u8> {
        (0..self.info().total_parties)
            .map(|p| self.each(p).rank)
            .collect()
    }

    /// Returns a vector of x-coordinates for all parties.
    pub fn x_i_list(&self) -> Vec<NonZeroScalar> {
        (0..self.info().total_parties)
            .map(|p| decode_nonzero(&self.each(p).x_i).unwrap())
            .collect()
    }

    pub(crate) fn get_x_i(&self, party_id: u8) -> NonZeroScalar {
        NonZeroScalar::new(decode_scalar(&self.each(party_id).x_i).unwrap()).unwrap()
    }

    /// Returns true if all parties have rank zero.
    pub fn zero_ranks(&self) -> bool {
        for p in 0..self.info().total_parties {
            if self.each(p).rank != 0 {
                return false;
            }
        }

        true
    }

    /// Returns the rank of a specific party.
    ///
    /// # Arguments
    /// * `party_id` - ID of the party
    pub fn get_rank(&self, party_id: u8) -> u8 {
        self.each(party_id).rank
    }

    /// Returns the secret scalar s_i for this party.
    pub fn s_i(&self) -> Scalar {
        decode_scalar(&self.info().s_i).unwrap()
    }

    /// Returns the user-defined data embedded in the key share.
    ///
    /// This data is passed via the setup message during key generation and is immutable.
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

    pub(crate) fn other_mut(&mut self, party_id: u8) -> &mut details::OtherParty {
        assert!(party_id < self.info().total_parties);

        let n = self.info().total_parties as usize;
        let offset = Self::INFO + Self::EACH * n;

        let idx = self.get_idx_from_id(party_id);
        let bytes = &mut self.buffer[offset..][..Self::OTHER * (n - 1)];

        let others: &mut [details::OtherParty] = bytemuck::cast_slice_mut(bytes);

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

    pub(crate) fn each_mut(&mut self, party_id: u8) -> &mut details::EachParty {
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

    /// Returns the public key component for a specific party.
    ///
    /// # Arguments
    /// * `party_id` - ID of the party
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
    /// Returns the root chain code.
    pub fn root_chain_code(&self) -> [u8; 32] {
        self.info().root_chain_code
    }

    /// Returns the root public key.
    pub fn root_public_key(&self) -> ProjectivePoint {
        self.public_key()
    }
}

impl Keyshare {
    /// Returns the key fingerprint.
    pub fn get_finger_print(&self) -> KeyFingerPrint {
        get_finger_print(&self.root_public_key())
    }

    /// Derives a child key with the given chain path and offset.
    ///
    /// # Arguments
    /// * `chain_path` - The derivation path to use
    ///
    /// # Returns
    /// A tuple containing the derived scalar and public key, or an error if derivation fails.
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

    /// Derives a child public key with the given chain path.
    ///
    /// # Arguments
    /// * `chain_path` - The derivation path to use
    ///
    /// # Returns
    /// The derived public key, or an error if derivation fails.
    pub fn derive_child_pubkey(
        &self,
        chain_path: &DerivationPath,
    ) -> Result<ProjectivePoint, BIP32Error> {
        let (_, child_pubkey) = self.derive_with_offset(chain_path)?;

        Ok(child_pubkey)
    }

    /// Derives an extended public key with the given prefix and chain path.
    ///
    /// # Arguments
    /// * `prefix` - The prefix to use for the extended public key
    /// * `chain_path` - The derivation path to use
    ///
    /// # Returns
    /// The derived extended public key, or an error if derivation fails.
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
