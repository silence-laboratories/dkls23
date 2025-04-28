// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! Protocol for refreshing existing keyshares without changing the corresponding public key

use std::fmt;

use k256::{
    elliptic_curve::{group::GroupEncoding, PrimeField},
    NonZeroScalar, ProjectivePoint, Scalar,
};

use zeroize::Zeroize;

use sl_mpc_mate::coord::*;

use crate::keygen::utils::{get_birkhoff_coefficients, get_lagrange_coeff};

use crate::{
    keygen::{run_inner, KeyRefreshData, KeygenError, Keyshare},
    proto::{tags::*, *},
    setup::KeygenSetupMessage,
    Seed,
};

/// Keyshare for refresh of a party.
#[derive(Clone, Zeroize)]
pub struct KeyshareForRefresh {
    /// Rank of each party
    pub rank_list: Vec<u8>,

    /// Threshold value
    pub threshold: u8,

    /// Public key of the generated key.
    pub public_key: ProjectivePoint,

    // Root chain code (used to derive child public keys)
    pub(crate) root_chain_code: [u8; 32],

    /// set s_i to None if party_i lost their key_share
    pub s_i: Option<Scalar>,

    /// set s_i to None if party_i lost their key_share
    pub x_i_list: Option<Vec<NonZeroScalar>>,

    /// list of participants ids who lost their key_shares,
    /// should be in range [0, n-1]
    pub lost_keyshare_party_ids: Vec<u8>,

    /// Part ID from key share
    pub party_id: u8,
}

impl fmt::Debug for KeyshareForRefresh {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyshareForRefresh")
            .field("rank_list", &self.rank_list)
            .field("threshold", &self.threshold)
            .field("public_key", &self.public_key)
            .field("lost_keyshare_party_ids", &self.lost_keyshare_party_ids)
            .finish()
    }
}

impl KeyshareForRefresh {
    #[allow(clippy::too_many_arguments)]
    /// Create new KeyshareForRefresh object.
    /// # Warning
    /// It is recommended to use `KeyshareForRefresh::from_keyshare()` and `KeyshareForRefresh::from_lost_keyshare()` instead.
    /// This is for advanced usecases only.
    pub fn new(
        rank_list: Vec<u8>,
        threshold: u8,
        public_key: ProjectivePoint,
        root_chain_code: [u8; 32],
        s_i: Option<Scalar>,
        x_i_list: Option<Vec<NonZeroScalar>>,
        lost_keyshare_party_ids: Vec<u8>,
        party_id: u8,
    ) -> Self {
        Self {
            rank_list,
            threshold,
            public_key,
            root_chain_code,
            s_i,
            x_i_list,
            lost_keyshare_party_ids,
            party_id,
        }
    }
    /// Create KeyshareForRefresh struct from Keyshare
    pub fn from_keyshare(
        keyshare: &Keyshare,
        lost_keyshare_party_ids: Option<Vec<u8>>,
    ) -> Self {
        let lost_keyshare_party_ids =
            lost_keyshare_party_ids.unwrap_or_default();
        Self {
            rank_list: keyshare.rank_list(),
            threshold: keyshare.threshold,
            public_key: keyshare.public_key(),
            root_chain_code: keyshare.root_chain_code,
            s_i: Some(keyshare.s_i()),
            x_i_list: Some(keyshare.x_i_list()),
            lost_keyshare_party_ids,
            party_id: keyshare.party_id,
        }
    }

    /// Create KeyshareForRefresh struct for the participant who lost their keyshare
    pub fn from_lost_keyshare(
        rank_list: Vec<u8>,
        threshold: u8,
        public_key: ProjectivePoint,
        lost_keyshare_party_ids: Vec<u8>,
        party_id: u8,
    ) -> Self {
        Self {
            rank_list,
            threshold,
            public_key,
            root_chain_code: [0u8; 32],
            s_i: None,
            x_i_list: None,
            lost_keyshare_party_ids,
            party_id,
        }
    }

    ///  Serialize KeyshareForRefresh to bytes
    ///  Used to send KeyshareForRefresh to other parties, for key-import
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.size());

        bytes.push(self.party_id);

        bytes.push(self.rank_list.len() as u8);
        bytes.extend_from_slice(&self.rank_list);

        bytes.push(self.threshold);

        bytes.extend_from_slice(&self.public_key.to_affine().to_bytes());

        bytes.extend_from_slice(&self.root_chain_code);

        if let Some(s_i) = self.s_i {
            bytes.push(1);
            bytes.extend_from_slice(&s_i.to_bytes());
        } else {
            bytes.push(0);
        }

        if let Some(x_i_list) = &self.x_i_list {
            bytes.push(x_i_list.len() as u8);
            for x_i in x_i_list {
                bytes.extend_from_slice(&x_i.to_bytes());
            }
        } else {
            bytes.push(0);
        }

        bytes.push(self.lost_keyshare_party_ids.len() as u8);
        bytes.extend_from_slice(&self.lost_keyshare_party_ids);

        bytes
    }

    /// Deserialize KeyshareForRefresh from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let offset = std::cell::Cell::new(0usize);

        let read_data = |num_bytes: u8| {
            let len = num_bytes as usize;
            let off = offset.replace(offset.get() + len);
            bytes.get(off..off + len)
        };

        let read_byte = || read_data(1).map(|b| b[0]);

        let party_id = read_byte()?;

        let rank_list_len = read_byte()?;
        let rank_list = read_data(rank_list_len)?;

        let threshold = read_byte()?;

        let public_key = read_data(33).and_then(|b| {
            ProjectivePoint::from_bytes(b.into()).into_option()
        })?;

        let root_chain_code: [u8; 32] = read_data(32)?.try_into().ok()?;

        let s_i = if read_byte()? == 1 {
            let s_i_bytes: [u8; 32] = read_data(32)?.try_into().ok()?;
            Scalar::from_repr(s_i_bytes.into()).into()
        } else {
            None
        };

        let x_i_list_len = read_byte()?;
        let x_i_list = if x_i_list_len != 0 {
            let mut x_i_list = Vec::with_capacity(x_i_list_len as usize);
            for _ in 0..x_i_list_len {
                let x_i_bytes: [u8; 32] = read_data(32)?.try_into().ok()?;
                let x_i: NonZeroScalar =
                    Option::from(NonZeroScalar::from_repr(x_i_bytes.into()))?;
                x_i_list.push(x_i);
            }
            Some(x_i_list)
        } else {
            None
        };

        let lost_keyshare_party_ids_len = read_byte()?;
        let lost_keyshare_party_ids = read_data(lost_keyshare_party_ids_len)?;

        Some(Self {
            rank_list: rank_list.to_vec(),
            threshold,
            public_key,
            root_chain_code,
            s_i,
            x_i_list,
            lost_keyshare_party_ids: lost_keyshare_party_ids.to_vec(),
            party_id,
        })
    }

    fn size(&self) -> usize {
        let mut size = 1 + self.rank_list.len();
        size += 1; // party_id
        size += 1;
        size += 33;
        size += 32;
        size += 1;
        if self.s_i.is_some() {
            size += 32;
        }
        if let Some(x_i_list) = &self.x_i_list {
            size += 1;
            size += x_i_list.len() * 32;
        } else {
            size += 1;
        }
        size += 1 + self.lost_keyshare_party_ids.len();
        size
    }
}

/// Execute Key Refresh protocol.
pub async fn run<R, S>(
    setup: S,
    seed: Seed,
    relay: R,
    old_keyshare: KeyshareForRefresh,
) -> Result<Keyshare, KeygenError>
where
    S: KeygenSetupMessage,
    R: Relay,
{
    let abort_msg = create_abort_message(&setup);
    let mut relay = FilteredMsgRelay::new(relay);

    let my_party_id = old_keyshare.party_id;
    let n = setup.total_participants();

    let mut s_i_0 = Scalar::ZERO;
    if old_keyshare.s_i.is_some() && old_keyshare.x_i_list.is_some() {
        // calculate additive share s_i_0 of participant_i,
        // \sum_{i=0}^{n-1} s_i_0 = private_key
        let s_i = &old_keyshare.s_i.unwrap();
        let rank_list = &old_keyshare.rank_list;
        let x_i_list = &old_keyshare.x_i_list.unwrap();
        let x_i = &x_i_list[my_party_id as usize];

        let party_ids_with_keyshares = (0..n as u8)
            .filter(|p| {
                !old_keyshare.lost_keyshare_party_ids.contains(&{ *p })
            })
            .collect::<Vec<_>>();

        let all_ranks_zero = rank_list.iter().all(|r| r == &0u8);

        let lambda = if all_ranks_zero {
            get_lagrange_coeff(x_i, x_i_list, &party_ids_with_keyshares)
        } else {
            get_birkhoff_coefficients(
                rank_list,
                x_i_list,
                &party_ids_with_keyshares,
            )
            .get(&(my_party_id as usize))
            .cloned()
            .unwrap_or(Scalar::ZERO)
        };

        s_i_0 = lambda * s_i;
    }

    let key_refresh_data = KeyRefreshData {
        s_i_0,
        lost_keyshare_party_ids: old_keyshare.lost_keyshare_party_ids,
        expected_public_key: old_keyshare.public_key,
        root_chain_code: old_keyshare.root_chain_code,
    };

    let result: Result<Keyshare, KeygenError> =
        run_inner(setup, seed, &mut relay, Some(&key_refresh_data)).await;

    let new_keyshare = match result {
        Ok(eph_keyshare) => eph_keyshare,

        Err(KeygenError::AbortProtocol(p)) => {
            return Err(KeygenError::AbortProtocol(p))
        }

        Err(KeygenError::SendMessage) => {
            return Err(KeygenError::SendMessage)
        }

        Err(err_message) => {
            #[cfg(feature = "tracing")]
            tracing::debug!("sending abort message");

            relay.send(abort_msg).await?;

            return Err(err_message);
        }
    };

    Ok(new_keyshare)
}

/// Generate ValidatedSetup and seed for Key refresh
#[cfg(any(test, feature = "test-support"))]
pub fn setup_key_refresh(
    t: u8,
    n: u8,
    n_i_list: Option<&[u8]>,
    key_shares_for_refresh: Vec<KeyshareForRefresh>,
) -> Vec<(
    crate::setup::keygen::SetupMessage,
    [u8; 32],
    KeyshareForRefresh,
)> {
    super::utils::setup_keygen(None, t, n, n_i_list)
        .into_iter()
        .zip(key_shares_for_refresh)
        .map(|((setup, seed), share)| (setup, seed, share))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use k256::elliptic_curve::group::GroupEncoding;

    use super::*;

    use tokio::task::JoinSet;

    use crate::keygen::utils::gen_keyshares;

    use crate::sign::{run as run_dsg, setup_dsg};

    // (flavor = "multi_thread")
    #[tokio::test(flavor = "multi_thread")]
    async fn r1() {
        let mut old_shares = gen_keyshares(2, 3, Some(&[0, 0, 0])).await;

        old_shares.swap(0, 2);

        let coord = SimpleMessageRelay::new();

        let mut parties = JoinSet::new();

        let key_shares_for_refresh = old_shares
            .iter()
            .map(|share| KeyshareForRefresh::from_keyshare(share, None))
            .collect();

        for (setup, seed, share) in
            setup_key_refresh(2, 3, Some(&[0, 1, 1]), key_shares_for_refresh)
        {
            parties.spawn(run(setup, seed, coord.connect(), share));
        }

        let mut new_shares = vec![];
        while let Some(fini) = parties.join_next().await {
            let fini = fini.unwrap();

            if let Err(ref err) = fini {
                println!("error {}", err);
            }

            assert!(fini.is_ok());

            let new_share = fini.unwrap();
            let pk = hex::encode(new_share.public_key().to_bytes());

            new_shares.push(Arc::new(new_share));

            println!("PK {}", pk);
        }

        // sign with new key_shares
        let coord = SimpleMessageRelay::new();

        new_shares.sort_by_key(|share| share.party_id);
        let subset = &new_shares[0..2_usize];

        let mut parties: JoinSet<Result<_, _>> = JoinSet::new();
        for (setup, seed) in setup_dsg(None, subset, "m") {
            parties.spawn(run_dsg(setup, seed, coord.connect()));
        }

        while let Some(fini) = parties.join_next().await {
            let fini = fini.unwrap();

            if let Err(ref err) = fini {
                println!("error {err:?}");
            }
            let _fini = fini.unwrap();
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn recover_lost_share() {
        let coord = SimpleMessageRelay::new();
        let mut parties = JoinSet::new();

        let t = 2;
        let n = 4;
        let rank_list = [0, 0, 0, 0];
        let old_keyshares = gen_keyshares(t, n, Some(&rank_list)).await;
        let public_key = old_keyshares[0].public_key();

        // party_0 and party_1 key_shares was lost
        let lost_keyshare_party_ids = vec![0, 1];
        let rank_list = vec![0u8, 0u8, 0u8, 0u8];
        let mut key_shares_for_refresh = Vec::with_capacity(n as usize);
        key_shares_for_refresh.push(KeyshareForRefresh::from_lost_keyshare(
            rank_list.clone(),
            t,
            public_key,
            lost_keyshare_party_ids.clone(),
            0,
        ));
        key_shares_for_refresh.push(KeyshareForRefresh::from_lost_keyshare(
            rank_list,
            t,
            public_key,
            lost_keyshare_party_ids,
            1,
        ));
        key_shares_for_refresh.push(KeyshareForRefresh::from_keyshare(
            &old_keyshares[2],
            Some(vec![0, 1]),
        ));
        key_shares_for_refresh.push(KeyshareForRefresh::from_keyshare(
            &old_keyshares[3],
            Some(vec![0, 1]),
        ));

        // recover lost key_share
        for (setup, seed, share) in setup_key_refresh(
            t,
            n,
            Some(&[0, 0, 0, 0]),
            key_shares_for_refresh,
        ) {
            parties.spawn(run(setup, seed, coord.connect(), share));
        }

        let mut new_shares = vec![];
        while let Some(fini) = parties.join_next().await {
            let fini = fini.unwrap();

            if let Err(ref err) = fini {
                println!("error {}", err);
            }

            assert!(fini.is_ok());

            let new_share = fini.unwrap();
            println!("PK {}", hex::encode(new_share.public_key().to_bytes()));

            new_shares.push(Arc::new(new_share));
        }

        // sign with party_0 and party_1 new key_shares
        let coord = SimpleMessageRelay::new();

        new_shares.sort_by_key(|share| share.party_id);
        let subset = &new_shares[0..2_usize];

        let mut parties: JoinSet<Result<_, _>> = JoinSet::new();
        for (setup, seed) in setup_dsg(None, subset, "m") {
            parties.spawn(run_dsg(setup, seed, coord.connect()));
        }

        while let Some(fini) = parties.join_next().await {
            let fini = fini.unwrap();

            if let Err(ref err) = fini {
                println!("error {err:?}");
            }
            let _fini = fini.unwrap();
        }
    }

    #[test]
    fn refresh_ser_de() {
        let share = KeyshareForRefresh::new(
            vec![0, 0, 0, 0],
            2,
            ProjectivePoint::GENERATOR * Scalar::ONE,
            [0u8; 32],
            Some(Scalar::ONE),
            Some(vec![NonZeroScalar::new(Scalar::ONE).unwrap()]),
            vec![0, 1],
            0,
        );

        let bytes = share.to_bytes();
        let share2 = KeyshareForRefresh::from_bytes(&bytes).unwrap();

        assert_eq!(share.rank_list, share2.rank_list);
        assert_eq!(share.threshold, share2.threshold);
        assert_eq!(share.public_key, share2.public_key);
        assert_eq!(share.root_chain_code, share2.root_chain_code);
        assert_eq!(share.s_i, share2.s_i);
        assert_eq!(share.x_i_list.is_some(), share2.x_i_list.is_some());
        let x_i_list = share.x_i_list.unwrap();
        let x_i_list2 = share2.x_i_list.unwrap();

        assert_eq!(x_i_list.len(), x_i_list2.len());

        for (x_i, x_i2) in x_i_list.iter().zip(x_i_list2.iter()) {
            assert_eq!(x_i.to_bytes(), x_i2.to_bytes());
        }

        assert_eq!(
            share.lost_keyshare_party_ids,
            share2.lost_keyshare_party_ids
        );
    }
}
