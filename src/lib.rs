//! DKLs23 rust implementation
#![deny(missing_docs, unsafe_code)]

/// DKLs23 keygen protocol
pub mod keygen;

/// DKLs23 signing protocol
pub mod sign;

/// Utilities
pub mod utils {
    use k256::sha2::{Digest, Sha256};
    use sl_mpc_mate::SessionId;

    /// Empty Initial state of a state machine
    pub struct Init;

    /// Calculates the final session id from the list of session ids.
    pub fn calculate_final_session_id(
        party_ids: impl IntoIterator<Item = usize>,
        sid_i_list: &[SessionId],
    ) -> SessionId {
        let mut hasher = Sha256::new();

        party_ids
            .into_iter()
            .for_each(|pid| hasher.update((pid as u32).to_be_bytes()));

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
}
