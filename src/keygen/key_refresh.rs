//

use k256::{NonZeroScalar, ProjectivePoint, Scalar};
use rand::prelude::*;

use sl_mpc_mate::{coord::*, message::*};

use crate::{
    Seed,
    keygen::{check_secret_recovery, run_inner, KeygenError, Keyshare},
    setup::{keygen::SetupBuilder, keygen::ValidatedSetup, PartyInfo, SETUP_MESSAGE_TAG},
};

/// Keyshare for refresh of a party.
// #[allow(unused)]
#[derive(Clone, bincode::Encode, bincode::Decode)]
pub struct KeyshareForRefresh {
    /// A marker
    pub magic: u32,

    /// Rank of each party
    pub rank_list: Vec<u8>,

    /// Threshold value
    pub threshold: u8,

    /// Public key of the generated key.
    pub public_key: Opaque<ProjectivePoint, GR>,

    /// Root chain code (used to derive child public keys)
    pub root_chain_code: [u8; 32],

    pub(crate) s_i: Opaque<Scalar, PF>,
    pub(crate) big_s_list: Vec<Opaque<ProjectivePoint, GR>>,
    pub(crate) x_i_list: Vec<Opaque<NonZeroScalar, NZ>>,
}

impl KeyshareForRefresh {
    /// Create KeyshareForRefresh struct from Keyshare
    pub fn from_keyshare(keyshare: &Keyshare) -> Self {
        Self {
            magic: keyshare.magic,
            rank_list: keyshare.rank_list.clone(),
            threshold: keyshare.threshold,
            public_key: keyshare.public_key,
            root_chain_code: keyshare.root_chain_code,
            s_i: keyshare.s_i,
            big_s_list: keyshare.big_s_list.clone(),
            x_i_list: keyshare.x_i_list.clone(),
        }
    }
}

/// Execute Key Refresh protocol.
pub async fn run<R>(
    setup: ValidatedSetup,
    seed: Seed,
    mut relay: R,
    old_keyshare: KeyshareForRefresh,
) -> Result<Keyshare, KeygenError>
where
    R: Relay,
{
    let x_i = &old_keyshare.x_i_list[setup.party_id() as usize] as &NonZeroScalar;
    let result: Result<Keyshare, KeygenError> =
        run_inner(setup, seed, |_| {}, &mut relay, Some(x_i)).await;
    let mut new_keyshare = match result {
        Ok(eph_keyshare) => eph_keyshare,
        Err(err_message) => return Err(err_message),
    };

    // checks for new_keyshare
    let cond1 = (new_keyshare.rank_list == old_keyshare.rank_list)
        && (new_keyshare.threshold == old_keyshare.threshold)
        && (new_keyshare.big_s_list.len() == old_keyshare.big_s_list.len())
        && (new_keyshare.x_i_list.len() == old_keyshare.x_i_list.len());
    cond1.then_some(()).ok_or(KeygenError::InvalidKeyRefresh)?;

    let mut cond2 = true;
    for i in 0..new_keyshare.x_i_list.len() {
        let l = &new_keyshare.x_i_list[i] as &Scalar;
        let r = &old_keyshare.x_i_list[i] as &Scalar;
        if l != r {
            cond2 = false;
        }
    }
    cond2.then_some(()).ok_or(KeygenError::InvalidKeyRefresh)?;

    // update existed keyshare with ephemeral keyshare
    new_keyshare.public_key = old_keyshare.public_key;
    new_keyshare.root_chain_code = old_keyshare.root_chain_code;
    new_keyshare.s_i = Opaque::from(&new_keyshare.s_i as &Scalar + &old_keyshare.s_i as &Scalar);
    let mut new_big_s_list: Vec<ProjectivePoint> = vec![];
    for i in 0..old_keyshare.big_s_list.len() {
        let point = &new_keyshare.big_s_list[i] as &ProjectivePoint
            + &old_keyshare.big_s_list[i] as &ProjectivePoint;
        new_big_s_list.push(point)
    }

    // check secret recovery
    let x_i_list: Vec<NonZeroScalar> = new_keyshare.x_i_list.iter().map(|v| v.0).collect();
    check_secret_recovery(
        &x_i_list,
        &new_keyshare.rank_list,
        &new_big_s_list,
        &new_keyshare.public_key as &ProjectivePoint,
    )?;

    new_keyshare.big_s_list = new_big_s_list
        .into_iter()
        .map(Opaque::from)
        .collect();

    Ok(new_keyshare)
}

/// Generate ValidatedSetup and seed for Key refresh
pub fn setup_key_refresh(
    t: u8,
    n: u8,
    n_i_list: Option<&[u8]>,
    shares: &[Keyshare],
) -> Vec<(ValidatedSetup, [u8; 32], KeyshareForRefresh)> {
    let n_i_list = if let Some(n_i_list) = n_i_list {
        assert_eq!(n_i_list.len(), n as usize);
        n_i_list.into()
    } else {
        vec![0u8; n as usize]
    };

    let mut rng = rand::thread_rng();

    let instance = InstanceId::from(rng.gen::<[u8; 32]>());

    // signing key to sing the setup message
    let setup_sk = SigningKey::from_bytes(&rng.gen());
    let setup_vk = setup_sk.verifying_key();
    let setup_pk = setup_vk.to_bytes();

    let setup_msg_id = MsgId::new(&instance, &setup_pk, None, SETUP_MESSAGE_TAG);

    // a signing key for each party.
    let party_sk: Vec<SigningKey> = (0..n).map(|_| SigningKey::from_bytes(&rng.gen())).collect();

    // Create a setup message. In a real world,
    // this part will be created by an initiator.
    // The setup message contail public keys of
    // all parties that will participate in this
    // protocol execution.
    let mut setup = n_i_list
        .iter()
        .enumerate()
        .fold(SetupBuilder::new(), |setup, (idx, rank)| {
            let vk = party_sk[idx].verifying_key();
            setup.add_party(*rank, &vk)
        })
        .build(&setup_msg_id, 100, t, &setup_sk)
        .unwrap();

    let mut result = vec![];
    for (party_sk, share) in party_sk.iter().zip(shares.iter()) {
        result.push((
            ValidatedSetup::decode(
                &mut setup,
                &instance,
                &setup_vk,
                party_sk.clone(),
                |_, _| true,
            )
            .unwrap(),
            rng.gen(),
            KeyshareForRefresh::from_keyshare(share),
        ));
    }
    result
}

#[cfg(test)]
mod tests {
    use k256::elliptic_curve::group::GroupEncoding;

    use super::*;

    use tokio::task::JoinSet;

    use crate::keygen::gen_keyshares;

    use crate::sign::{run as run_dsg, setup_dsg};

    // (flavor = "multi_thread")
    #[tokio::test(flavor = "multi_thread")]
    async fn r1() {
        let old_shares = gen_keyshares(2, 3, Some(&[0, 1, 1])).await;

        let coord = SimpleMessageRelay::new();

        let mut parties = JoinSet::new();
        for (setup, seed, share) in
            setup_key_refresh(2, 3, Some(&[0, 1, 1]), &old_shares).into_iter()
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
            new_shares.push(new_share.clone());

            println!(
                "PK {}",
                new_share
                    .public_key
                    .to_bytes()
                    .iter()
                    .map(|v| format!("{:02X}", v))
                    .collect::<Vec<_>>()
                    .join(".")
            );
        }

        // sign with new_keyshare
        let coord = SimpleMessageRelay::new();

        new_shares.sort_by_key(|share| share.party_id);
        let subset = &new_shares[0..2 as usize];

        let pk = subset[0].public_key.to_affine();
        let chain_path = "m".parse().unwrap();

        let mut parties: JoinSet<Result<_, _>> = JoinSet::new();
        for (setup, seed) in setup_dsg(&pk, &subset, &chain_path).into_iter() {
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
}
