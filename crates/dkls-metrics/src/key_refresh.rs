// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::sync::Arc;

use dkls23::keygen::key_refresh::KeyshareForRefresh;
use dkls23::keygen::{
    key_refresh::run as run_key_refresh, key_refresh::setup_key_refresh, Keyshare,
};
use sl_mpc_mate::coord::SimpleMessageRelay;
use tokio::task::JoinSet;

pub async fn run(
    old_shares: &[Arc<Keyshare>],
    ranks: &[u8],
    opts: &crate::flags::Dkg,
) -> Result<(), anyhow::Error> {
    let k = opts.k.unwrap_or(100);

    let start = std::time::Instant::now();

    let key_shares_for_refresh: Vec<KeyshareForRefresh> = old_shares
        .iter()
        .map(|share| KeyshareForRefresh::from_keyshare(share, None))
        .collect();

    for _ in 0..k {
        let coord = SimpleMessageRelay::new();

        let mut parties = JoinSet::new();
        for (setup, seed, share) in
            setup_key_refresh(opts.t, opts.n, Some(ranks), key_shares_for_refresh.clone())
        {
            parties.spawn(run_key_refresh(setup, seed, coord.connect(), share));
        }

        let mut new_keyshares = vec![];

        while let Some(fini) = parties.join_next().await {
            let fini = fini.unwrap();

            if let Err(ref err) = fini {
                println!("error {}", err);
            }

            assert!(fini.is_ok());

            let new_share = fini.unwrap();

            new_keyshares.push(new_share)
        }
    }

    let d = start.elapsed();
    println!(
        "ROT: N={}, T={}, t={:?}, K={}, {:?}",
        opts.n,
        opts.t,
        d / k as u32,
        k,
        d
    );

    Ok(())
}
