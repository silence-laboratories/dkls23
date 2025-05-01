// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use tokio::task::JoinSet;

use msg_relay::MsgRelay;
use sl_dkls23::{keygen::Keyshare, sign};
use sl_mpc_mate::coord::stats::{RelayStats, Stats};

use crate::{
    flags,
    relay::{MessageTrace, Tracing},
};

pub async fn run_one(
    instance: [u8; 32],
    subset: &[Arc<Keyshare>],
    chain_path: &str,
    relay: &MsgRelay,
) -> Arc<Mutex<Stats>> {
    let (setup, seed) = sign::setup_dsg(Some(instance), subset, chain_path)
        .into_iter()
        .next()
        .unwrap();

    let stats = Stats::alloc();
    let relay = RelayStats::new(relay.connect(), stats.clone());

    sl_dkls23::sign::run(setup, seed, relay).await.unwrap();

    stats
}

pub async fn run(
    keyshares: &[Arc<Keyshare>],
    opts: &flags::Dkg,
) -> Result<(), anyhow::Error> {
    let chain_path = "m";
    let subset = &keyshares[0..opts.t as usize];

    let (instance, messages) = {
        let instance = rand::random();

        let trace = MessageTrace::new();

        run_inner(Some(instance), subset, chain_path, Some(trace.clone()))
            .await;

        (instance, trace.messages())
    };

    println!(
        "DSG: traced {} messages, {} total bytes",
        messages.len(),
        messages.iter().map(|v| v.len()).sum::<usize>()
    );

    let relay = MsgRelay::new(None);

    for msg in messages {
        relay.send(msg);
    }

    let k: usize = opts.k.unwrap_or(100);

    let start = Instant::now();

    let mut last = None;

    for _ in 0..k {
        let stats = run_one(instance, subset, chain_path, &relay).await;
        last = Some(stats);
    }

    let d = start.elapsed();

    if let Some(stats) = last {
        let stats = stats.lock().unwrap();
        println!(
            "DSG: send {} {}, recv {} {}",
            stats.send_count,
            stats.send_size,
            stats.recv_count,
            stats.recv_size,
        );
    }

    let one = d / k as u32;
    println!(
        "DSG: N = {:2}, T = {:2}, K = {:3}, t = {:?}, {:?}",
        opts.n, opts.t, k, one, d
    );

    // println!("pre-sign: t={:?}", pre_total / k as u32,);
    // println!("finish:   t={:?}", fin_total / k as u32);

    Ok(())
}

pub async fn run_inner(
    instance: Option<[u8; 32]>,
    shares: &[Arc<Keyshare>],
    chain_path: &str,
    trace: Option<Arc<MessageTrace>>,
) {
    let relay = MsgRelay::new(None);

    let mut parties = JoinSet::new();

    // let start = Instant::now();

    for (setup, seed) in sign::setup_dsg(instance, shares, chain_path) {
        let relay = Tracing::new(relay.connect(), trace.clone());
        parties.spawn(sign::run(
            setup.with_ttl(Duration::from_secs(1000)),
            seed,
            relay,
        ));
    }

    while let Some(fini) = parties.join_next().await {
        let fini = fini.unwrap();

        if let Err(ref err) = fini {
            println!("error {err:?}");
        }

        let _fini = fini.unwrap();
    }
}
