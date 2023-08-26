//! DKLs23 rust implementation
// #![deny(missing_docs, unsafe_code)]

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// DKLs23 keygen protocol
pub mod keygen;

/// DKLs23 signing protocol
pub mod sign;

/// Setup message creation/parsing
pub mod setup;

pub use sl_mpc_mate::{coord::MessageRelay, message::*};

/// Utilities
pub mod utils {
    use k256::{
        ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey},
        // elliptic_curve::{generic_array::GenericArray, group::GroupEncoding},
        sha2::{Digest, Sha256},
        // ProjectivePoint,
    };
    use sl_mpc_mate::SessionId;

    /// Empty Initial state of a state machine
    pub struct Init;

    /// Calculates the final session id from the list of session ids.
    pub fn calculate_final_session_id(party_ids: &[usize], sid_i_list: &[SessionId]) -> SessionId {
        let mut hasher = Sha256::new();

        party_ids
            .iter()
            .for_each(|pid| hasher.update((*pid as u32).to_be_bytes()));

        sid_i_list.iter().for_each(|sid| hasher.update(sid));

        SessionId::new(hasher.finalize().into())
    }

    /// Get the Sha-256 hash of the given data.
    pub fn get_hash(data: &[&[u8]]) -> [u8; 32] {
        let mut hasher = Sha256::new();

        for d in data {
            hasher.update(d);
        }

        hasher.finalize().into()
    }

    // /// Decrypts the given ciphertext using the given sender public key and recipient secret key.
    // pub fn decrypt_point(
    //     ciphertext: &EncryptedData,
    //     sender_pubkey: &BoxPubkey,
    //     recipient_secret_key: &BoxPrivKey,
    // ) -> Result<ProjectivePoint, String> {
    //     let bytes = ciphertext
    //         .enc_data
    //         .decrypt_to_vec(&ciphertext.nonce, sender_pubkey, recipient_secret_key)
    //         .map_err(|e| e.to_string())?;

    //     let option = ProjectivePoint::from_bytes(GenericArray::from_slice(&bytes));
    //     if option.is_none().unwrap_u8() == 1 {
    //         return Err("Could not decrypt point".to_string());
    //     }

    //     Ok(option.unwrap())
    // }

    /// Parse the raw signature (r, s) into a Signature object.
    pub fn parse_raw_sign(r: &[u8], s: &[u8]) -> Result<Signature, k256::ecdsa::Error> {
        // Pad r and s to 32 bytes
        let mut raw_sign = [0u8; 64];

        let r_pad = 32 - r.len();
        let s_pad = 32 - s.len();

        raw_sign[r_pad..32].copy_from_slice(r);
        raw_sign[32 + s_pad..64].copy_from_slice(s);

        Signature::try_from(raw_sign.as_slice())
    }

    /// Verify the ecdsa signature given the message hash, r, s and public key.
    /// # ⚠️ Security Warning
    /// If prehash is something other than the output of a cryptographically secure hash function,
    /// an attacker can potentially forge signatures by solving a system of linear equations.
    pub fn verify_final_signature(
        message_hash: &[u8],
        sign: &Signature,
        pubkey_bytes: &[u8],
    ) -> Result<(), k256::ecdsa::Error> {
        let verify_key = VerifyingKey::from_sec1_bytes(pubkey_bytes)?;

        verify_key.verify_prehash(message_hash, sign)?;
        Ok(())
    }
}

/// Seed for our RNG
pub type Seed = <ChaCha20Rng as SeedableRng>::Seed;

///
#[derive(Debug)]
pub struct BadPartyIndex;
