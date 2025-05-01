// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::{
    fs::File,
    io::{BufRead, BufReader, Write},
    path::Path,
    sync::{Arc, Mutex},
    time::Instant,
};

use anyhow::anyhow;
use tokio::task::JoinSet;

use msg_relay::MsgRelay;
use sl_dkls23::keygen::{self, utils::setup_keygen, KeygenError, Keyshare};
use sl_mpc_mate::{
    coord::stats::{RelayStats, Stats},
    message::*,
};

use crate::{
    dsg, flags, key_refresh,
    relay::{MessageTrace, Tracing},
};

#[allow(dead_code)]
pub struct Trace {
    instance: [u8; 32],
    shares: Vec<Arc<Keyshare>>,
    relay: MsgRelay,
}

impl Trace {
    pub fn new(
        instance: [u8; 32],
        shares: Vec<Arc<Keyshare>>,
        messages: Vec<Vec<u8>>,
    ) -> Self {
        let relay = MsgRelay::new(None);

        for msg in messages {
            relay.send(msg);
        }

        Trace {
            instance,
            shares,
            relay,
        }
    }

    pub fn n(&self) -> u8 {
        self.shares[0].total_parties
    }

    pub fn t(&self) -> u8 {
        self.shares[0].threshold
    }

    pub fn ranks(&self) -> Vec<u8> {
        self.shares[0].rank_list()
    }

    pub fn relay(&self) -> &MsgRelay {
        &self.relay
    }

    pub fn shares(&self) -> &[Arc<Keyshare>] {
        &self.shares
    }

    pub fn load<P: AsRef<Path>>(
        key_id: &[u8],
        base: P,
    ) -> anyhow::Result<Trace> {
        let base = base.as_ref().to_path_buf();
        let key_id_str = hex::encode(key_id);

        let relay = MsgRelay::new(None);

        let msg_list_file = BufReader::new(File::open(
            base.join(format!("{}.messages", key_id_str)),
        )?);

        for msg_id in msg_list_file.lines() {
            relay.send(std::fs::read(base.join(format!("{}.msg", msg_id?)))?);
        }

        let instance =
            std::fs::read(base.join(format!("{}.instance", key_id_str)))?
                .try_into()
                .map_err(|_| anyhow!("invalid size of instance-id"))?;

        let mut shares = Vec::new();

        shares.push(Arc::new(
            Keyshare::from_bytes(&std::fs::read(
                base.join(format!("{}.share.00", key_id_str)),
            )?)
            .unwrap(),
        ));

        for idx in 1..shares[0].total_parties {
            shares.push(Arc::new(
                Keyshare::from_bytes(&std::fs::read(
                    base.join(format!("{}.share.{:02}", key_id_str, idx)),
                )?)
                .ok_or_else(|| anyhow!("key share decode {}", idx))?,
            ));
        }

        Ok(Trace {
            instance,
            shares,
            relay,
        })
    }

    pub fn save(
        base: &Path,
        instance: &[u8],
        messages: Vec<Vec<u8>>,
        shares: Vec<Arc<Keyshare>>,
    ) -> anyhow::Result<()> {
        let mut message_list = Vec::new();

        for msg in messages {
            if let Ok(id) = MsgId::try_from(msg.as_slice()) {
                let path = base.join(format!("{:x}.msg", id));
                std::fs::write(path, msg)?;

                writeln!(&mut message_list, "{:x}", id)?;
            }
        }

        let key_id = hex::encode(shares[0].key_id);

        std::fs::write(
            base.join(format!("{}.messages", &key_id)),
            message_list,
        )?;

        for share in shares {
            let id = share.party_id;

            std::fs::write(
                base.join(format!("{}.share.{:02}", &key_id, id)),
                share.as_slice(),
            )?;
        }

        std::fs::write(base.join(format!("{}.instance", key_id)), instance)?;

        Ok(())
    }

    pub async fn run_one(
        &self,
        ranks: Option<&[u8]>,
        n: u8,
        t: u8,
    ) -> Result<Arc<Mutex<Stats>>, KeygenError> {
        let (setup, seed) = setup_keygen(Some(self.instance), t, n, ranks)
            .into_iter()
            .next()
            .unwrap();

        let stats = Stats::alloc();
        let relay = RelayStats::new(self.relay.connect(), stats.clone());

        let _keyshare = sl_dkls23::keygen::run(setup, seed, relay).await?;

        Ok(stats)
    }
}

pub async fn run_inner(
    instance: Option<[u8; 32]>,
    ranks: Option<&[u8]>,
    n: u8,
    t: u8,
    trace: Option<Arc<MessageTrace>>,
) -> Vec<Arc<Keyshare>> {
    let relay = MsgRelay::new(None);

    let mut keyshares = Vec::with_capacity(n as usize);
    let mut parties = JoinSet::new();

    for (setup, seed) in setup_keygen(instance, t, n, ranks) {
        let relay = Tracing::new(relay.connect(), trace.clone());
        parties.spawn(keygen::run(setup, seed, relay));
    }

    while let Some(fini) = parties.join_next().await {
        let fini = fini.unwrap();
        keyshares.push(Arc::new(fini.unwrap()));
    }

    // sort by ranks, thus at least one share with rank 0 will be at
    // position 0.
    keyshares.sort_by_key(|s| {
        let ranks = s.rank_list();
        ranks[s.party_id as usize]
    });

    keyshares
}

pub async fn run_cmd(
    ranks: Vec<u8>,
    opts: flags::Dkg,
) -> Result<(), anyhow::Error> {
    let trace = {
        let instance = rand::random();

        let trace = MessageTrace::new();

        let shares = run_inner(
            Some(instance),
            Some(&ranks),
            opts.n,
            opts.t,
            Some(trace.clone()),
        )
        .await;

        let messages = trace.messages();

        println!(
            "DKG: traced {} messages, {} total bytes",
            messages.len(),
            messages.iter().map(|v| v.len()).sum::<usize>()
        );

        Trace::new(instance, shares, messages)
    };

    let k = opts.k.unwrap_or(100);

    let mut last = None;

    let start = Instant::now();

    for _ in 0..k {
        let stats = trace.run_one(Some(&ranks), opts.n, opts.t).await?;
        last = Some(stats);
    }

    let d = start.elapsed();
    let one = d / k as u32;

    println!(
        "DKG: N = {:2}, T = {:2}, K = {:3}, t = {:?}, {:?}",
        opts.n, opts.t, k, one, d
    );

    if let Some(stats) = last {
        let stats = stats.lock().unwrap();
        println!(
            "DKG: send {} {}, recv {} {}",
            stats.send_count,
            stats.send_size,
            stats.recv_count,
            stats.recv_size,
        );
    }

    if opts.dsg {
        dsg::run(&trace.shares, &opts).await?;
    }

    if opts.key_refresh {
        key_refresh::run(&trace.shares, &ranks, &opts).await?;
    }

    Ok(())
}
