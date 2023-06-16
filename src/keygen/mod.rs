mod dkg;
mod types;

pub use dkg::*;
pub use types::*;
mod utils;
pub use utils::*;

/// Keygen protocol messages
pub mod messages;

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use k256::{elliptic_curve::group::GroupEncoding, NonZeroScalar};
    use rand::seq::SliceRandom;

    use crate::keygen::{check_all_but_one_seeds, check_secret_recovery};

    use super::process_keygen;

    #[test]
    fn test_keygen() {
        const T: usize = 3;
        const N: usize = 5;
        let (_parties, keyshares) = process_keygen::<T, N>(None);
        let pubkeys = keyshares.iter().map(|key| key.public_key.to_bytes());
        check_not_unique(pubkeys);

        let x_i_list = keyshares.iter().map(|key| key.x_i.to_bytes());
        check_unique(x_i_list);

        let big_s_list = keyshares.iter().map(|key| {
            key.big_s_list
                .iter()
                .map(|s| s.to_bytes())
                .collect::<Vec<_>>()
        });

        check_not_unique(big_s_list);

        for (pid, key) in keyshares.iter().enumerate() {
            assert_eq!(T, key.threshold);
            assert_eq!(N, key.total_parties);
            assert_eq!(pid, key.party_id);
            assert_eq!(0, key.rank);
        }

        let mut rng = rand::thread_rng();
        let big_s_list = &keyshares[0].big_s_list;
        let public_key = &keyshares[0].public_key;
        let x_i_list = &keyshares[0].x_i_list;

        for _ in 0..N {
            let threshold_keyshares = keyshares.choose_multiple(&mut rng, T).collect::<Vec<_>>();
            let rank_list = threshold_keyshares
                .iter()
                .map(|key| key.rank)
                .collect::<Vec<_>>();
            check_secret_recovery(x_i_list, &rank_list, big_s_list, public_key)
                .expect("Failed to recover secret");
        }
        let party_1 = &keyshares[0];
        let party_2 = &keyshares[1];
        let party_3 = &keyshares[2];

        check_all_but_one_seeds(&party_1.seed_ot_senders[0], &party_2.seed_ot_receivers[0]);
        check_all_but_one_seeds(&party_2.seed_ot_senders[0], &party_1.seed_ot_receivers[0]);

        // party1 - party3
        check_all_but_one_seeds(&party_1.seed_ot_senders[1], &party_3.seed_ot_receivers[0]);
        check_all_but_one_seeds(&party_3.seed_ot_senders[0], &party_1.seed_ot_receivers[1]);

        // party2 - party3
        check_all_but_one_seeds(&party_2.seed_ot_senders[1], &party_3.seed_ot_receivers[1]);
        check_all_but_one_seeds(&party_3.seed_ot_senders[1], &party_2.seed_ot_receivers[1]);
    }

    fn check_unique<T: std::cmp::Eq + std::hash::Hash>(list: impl Iterator<Item = T>) {
        let mut unique = HashSet::new();
        let mut count = 0;
        for item in list {
            unique.insert(item);
            count += 1;
        }
        assert!(unique.len() == count)
    }

    fn check_not_unique<T: std::cmp::Eq + std::hash::Hash>(list: impl Iterator<Item = T>) {
        let mut unique = HashSet::new();
        for item in list {
            unique.insert(item);
        }
        assert!(unique.len() == 1)
    }
}
