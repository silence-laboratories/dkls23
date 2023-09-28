//! DKLs23 rust implementation
#![deny(missing_docs, unsafe_code)]

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// DKLs23 keygen protocol
pub mod keygen;

/// DKLs23 signing protocol
pub mod sign;

/// Setup message creation/parsing
pub mod setup;

/// Utilities
pub mod utils {
    // use std::task::{Context, Poll};

    use k256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};

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
        VerifyingKey::from_sec1_bytes(pubkey_bytes)?.verify_prehash(message_hash, sign)
    }
}

/// Seed for our RNG
pub type Seed = <ChaCha20Rng as SeedableRng>::Seed;

///
#[derive(Debug)]
pub struct BadPartyIndex;
