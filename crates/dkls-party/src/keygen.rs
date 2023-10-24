use std::str::FromStr;
use std::time::Instant;

use k256::elliptic_curve::group::GroupEncoding;
use tokio::task;

use dkls23::{
    keygen,
    setup::{self, keygen::ValidatedSetup, *},
};

use msg_relay_client::MsgRelayClient;
use sl_mpc_mate::{
    coord::{stats::*, *},
    message::*,
};

use crate::{default_coord, flags, serve::*, utils::*};

pub async fn setup(opts: flags::KeygenSetup) -> anyhow::Result<()> {
    let setup_sk = load_signing_key(opts.sign)?;
    let setup_vk = setup_sk.verifying_key();

    let builder = opts.party.into_iter().try_fold(
        setup::keygen::SetupBuilder::new(),
        |builder, party| {
            let mut parts = party.split(':');

            let vk = parts
                .next()
                .ok_or(anyhow::Error::msg("missing party PK"))
                .and_then(parse_verifying_key)?;

            let rank = <u8>::from_str(parts.next().unwrap_or("0"))
                .map_err(|_| anyhow::Error::msg("cant  parse rank"))?;

            Ok::<_, anyhow::Error>(builder.add_party(rank, &vk))
        },
    )?;

    let instance = parse_instance_bytes(&opts.instance)?;
    let msg_id = MsgId::new(
        &InstanceId::from(instance),
        setup_vk.as_bytes(),
        None,
        SETUP_MESSAGE_TAG,
    );

    let setup = builder
        .build(&msg_id, opts.ttl, opts.threshold, &setup_sk)
        .ok_or(anyhow::Error::msg("Cant create setup message"))?;

    let coord = opts.coordinator.unwrap_or_else(default_coord);
    let mut msg_relay = MsgRelayClient::connect(&coord).await?;

    msg_relay
        .send(setup)
        .await
        .map_err(|_| anyhow::Error::msg("send error"))?;

    tracing::info!("sent setup message {:X}", msg_id);

    if !opts.node.is_empty() {
        let mut inits = tokio::task::JoinSet::new();

        for node in &opts.node {
            inits.spawn(
                reqwest::Client::new()
                    .post(node.join("/v1/keygen")?)
                    .json(&KeygenParams::new(&instance))
                    .send(),
            );
        }

        let mut keys = vec![];

        while let Some(resp) = inits.join_next().await {
            let resp = resp?;
            let resp = resp?;

            let status = resp.status();

            if status == reqwest::StatusCode::OK {
                let resp: KeygenResponse = resp.json().await?;
                keys.push(resp.public_key);
            } else {
                return Err(anyhow::Error::msg(""));
            }
        }

        println!("{} {}", hex::encode(&keys[0]), keys.len());
    }

    Ok(())
}

pub async fn run_keygen(opts: flags::KeyGen) -> anyhow::Result<()> {
    let start = Instant::now();

    let mut parties = task::JoinSet::new();

    let instance = parse_instance_id(&opts.instance)?;
    let setup_vk = parse_verifying_key(&opts.setup_vk)?;

    let msg_id = MsgId::new(
        &instance,
        setup_vk.as_bytes(),
        None,
        SETUP_MESSAGE_TAG,
    );

    let coord = opts.coordinator.unwrap_or_else(default_coord);

    opts.party.into_iter().try_for_each(|desc| {
        let sk = load_signing_key(desc.into())?;

        let seed = rand::random();

        let coord = coord.clone();

        parties.spawn(async move {
            let stats = Stats::alloc();

            let msg_relay = MsgRelayClient::connect(&coord).await?;
            let msg_relay = RelayStats::new(msg_relay, stats.clone());
            let mut msg_relay = BufferedMsgRelay::new(msg_relay);

            let mut setup = msg_relay.recv(&msg_id, 10).await.ok_or(
                anyhow::Error::msg("Can't receive setup message"),
            )?;

            let setup = ValidatedSetup::decode(
                &mut setup,
                &instance,
                &setup_vk,
                sk,
                |_, _, _| true,
            )
            .ok_or(anyhow::Error::msg("cant parse setup message"))?;

            let share = keygen::run(setup, seed, msg_relay).await?;

            Ok::<_, anyhow::Error>((share, stats))
        });

        Ok::<_, anyhow::Error>(())
    })?;

    let prefix = opts.prefix.unwrap_or_else(|| ".".into());

    let mut results = vec![];

    while let Some(share) = parties.join_next().await {
        let (keyshare, stats) = share??;
        results.push((keyshare, Stats::inner(stats)));
    }

    tracing::info!("total time {:?}", start.elapsed());

    for (keyshare, stats) in &results {
        let pid = keyshare.party_id;

        let share = bincode::encode_to_vec(
            keyshare,
            bincode::config::standard(),
        )?;

        let keyshare_file =
            prefix.join(format!("keyshare.{}", keyshare.party_id));

        std::fs::write(keyshare_file, share)?;

        tracing::info!("send_count: {} {}", pid, stats.send_count);
        tracing::info!("send_size:  {} {}", pid, stats.send_size);
        tracing::info!("recv_count: {} {}", pid, stats.recv_count);
        tracing::info!("recv_size:  {} {}", pid, stats.recv_size);
        tracing::info!("wait_time:  {} {:?}", pid, stats.wait_time);

        for (id, wait) in &stats.wait_times {
            tracing::info!(" - {} {:?} {:?}", pid, id, wait);
        }
    }

    Ok(())
}

pub fn run_share_pubkey(
    opts: flags::SharePubkey,
) -> anyhow::Result<()> {
    let body = std::fs::read(opts.share)?;

    let (share, _): (keygen::Keyshare, usize) =
        bincode::decode_from_slice(&body, bincode::config::standard())?;

    let pubkey = share.public_key.to_affine().to_bytes();

    println!("{}", hex::encode(pubkey));

    Ok(())
}
