use std::str::FromStr;

use k256::elliptic_curve::group::GroupEncoding;
use tokio::task;

use dkls23::{
    keygen,
    setup::{self, keygen::ValidatedSetup, *},
};

use msg_relay_client::MsgRelayClient;
use sl_mpc_mate::{
    coord::{BoxedRelay, Relay},
    message::*,
};

use crate::{default_coord, flags, utils::*};

pub async fn setup(opts: flags::KeygenSetup) -> anyhow::Result<()> {
    let setup_sk = load_signing_key(opts.sign)?;
    let setup_vk = setup_sk.verifying_key();

    let builder = opts.party.into_iter().try_fold(
        setup::keygen::SetupBuilder::new(),
        |builder, party| {
            let mut parts = party.split(":");

            let vk = parts
                .next()
                .ok_or(anyhow::Error::msg("missing party PK"))
                .and_then(parse_verifying_key)?;

            let rank = <u8>::from_str(parts.next().unwrap_or("0"))
                .map_err(|_| anyhow::Error::msg("cant  parse rank"))?;

            Ok::<_, anyhow::Error>(builder.add_party(rank, &vk))
        },
    )?;

    let msg_id = MsgId::new(
        &parse_instance_id(&opts.instance)?,
        setup_vk.as_bytes(),
        None,
        SETUP_MESSAGE_TAG,
    );

    let setup = builder
        .build(&msg_id, opts.ttl, opts.threshold, &setup_sk)
        .ok_or(anyhow::Error::msg("Cant create setup message"))?;

    let coord = opts.coordinator.unwrap_or_else(default_coord);
    let msg_relay: BoxedRelay =
        Box::new(MsgRelayClient::connect(&coord).await?);

    msg_relay.send(setup).await;

    Ok(())
}

pub async fn run_keygen(opts: flags::KeyGen) -> anyhow::Result<()> {
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
            let msg_relay: BoxedRelay =
                Box::new(MsgRelayClient::connect(&coord).await?);
            let relay_stats = RelayStats::new(msg_relay);
            let msg_relay = relay_stats.clone_relay();

            let mut setup = msg_relay.recv(msg_id, 10).await.ok_or(
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

            let stats = relay_stats.stats();

            Ok::<_, anyhow::Error>((share, stats))
        });

        Ok::<_, anyhow::Error>(())
    })?;

    let prefix = opts.prefix.unwrap_or_else(|| ".".into());

    while let Some(share) = parties.join_next().await {
        let (keyshare, stats) = share??;
        let pid = keyshare.party_id;

        let share = bincode::encode_to_vec(
            &keyshare,
            bincode::config::standard(),
        )?;

        let keyshare_file =
            prefix.join(format!("keyshare.{}", keyshare.party_id));

        std::fs::write(keyshare_file, share)?;

        tracing::info!("send_count: {} {}", pid, stats.send_count);
        tracing::info!("send_size:  {} {}", pid, stats.send_size);
        tracing::info!("recv_count: {} {}", pid, stats.recv_count);
        tracing::info!("recv_size:  {} {}", pid, stats.recv_size);
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
