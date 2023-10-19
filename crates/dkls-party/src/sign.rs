use tokio::task;

use dkls23::setup::{self, *};
use dkls23::{keygen::Keyshare, sign};

use derivation_path::DerivationPath;
use msg_relay_client::MsgRelayClient;
use sl_mpc_mate::{
    coord::{stats::*, *},
    message::*,
    HashBytes,
};

use crate::{default_coord, flags, serve::*, utils::*, SignHashFn};

pub async fn setup(opts: flags::SignSetup) -> anyhow::Result<()> {
    let pk: k256::AffinePoint = parse_affine_point(&opts.public_key)?;
    let chain_path_str = &opts.chain_path;
    let chain_path: DerivationPath = chain_path_str.parse().unwrap();
    let setup_sk = load_signing_key(opts.sign)?;
    let setup_vk = setup_sk.verifying_key();

    let builder = opts.party.into_iter().try_fold(
        setup::sign::SetupBuilder::new(&pk)
            .chain_path(Some(&chain_path)),
        |builder, party| {
            let vk = parse_verifying_key(&party)?;
            Ok::<_, anyhow::Error>(builder.add_party(vk))
        },
    )?;

    let builder = match opts.hash_fn.unwrap_or(SignHashFn::NoHash) {
        SignHashFn::NoHash => {
            let hash = parse_sign_message(&opts.message)?;
            builder.with_hash(HashBytes::new(hash))
        }

        SignHashFn::Sha256 => {
            builder.with_sha256(opts.message.into_bytes())
        }

        _ => unimplemented!(),
    };

    let instance = parse_instance_bytes(&opts.instance)?;
    let msg_id = MsgId::new(
        &InstanceId::from(instance),
        setup_vk.as_bytes(),
        None,
        SETUP_MESSAGE_TAG,
    );

    let setup = builder
        .build(&msg_id, opts.ttl, &setup_sk)
        .ok_or(anyhow::Error::msg("cant create setup message"))?;

    let coord = opts.coordinator.unwrap_or_else(default_coord);
    let mut msg_relay = MsgRelayClient::connect(&coord).await?;

    msg_relay
        .send(setup)
        .await
        .map_err(|_| anyhow::Error::msg("setup msg send error"))?;

    if !opts.node.is_empty() {
        let mut inits = tokio::task::JoinSet::new();

        for node in &opts.node {
            inits.spawn(
                reqwest::Client::new()
                    .post(node.join("/v1/signgen")?)
                    .json(&SignParams::new(&instance))
                    .send(),
            );
        }

        let mut signs = vec![];

        while let Some(resp) = inits.join_next().await {
            let resp = resp?;
            let resp = resp?;

            let status = resp.status();

            if status == reqwest::StatusCode::OK {
                let resp: SignResponse = resp.json().await?;
                signs.push(resp.sign);
            } else {
                return Err(anyhow::Error::msg("sign error"));
            }
        }

        println!("{}", hex::encode(&signs[0]));
    }

    Ok(())
}

fn load_keyshare(file_name: &str) -> anyhow::Result<Keyshare> {
    tracing::info!("load key share {}", file_name);
    let bytes = std::fs::read(file_name)?;

    let (share, _) = bincode::decode_from_slice(
        &bytes,
        bincode::config::standard(),
    )?;

    Ok(share)
}

pub async fn run_sign(opts: flags::SignGen) -> anyhow::Result<()> {
    let mut parties = task::JoinSet::new();

    let instance = parse_instance_id(&opts.instance)?;
    let setup_vk = parse_verifying_key(&opts.setup_vk)?;

    let coord = opts.coordinator.unwrap_or_else(default_coord);

    let msg_id = MsgId::new(
        &instance,
        &setup_vk.to_bytes(),
        None,
        SETUP_MESSAGE_TAG,
    );

    opts.party.into_iter().try_for_each(|desc| {
        let mut parts = desc.split(':');

        let party_sk = parts
            .next()
            .ok_or(anyhow::Error::msg("missing party signing key"))?;

        let sk = load_signing_key(party_sk.into())?;

        let keyshare = parts
            .next()
            .ok_or(anyhow::Error::msg("missing party keyshare"))?;

        let keyshare = load_keyshare(keyshare)?;

        let party_id = keyshare.party_id;

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

            let setup = setup::sign::ValidatedSetup::decode(
                &mut setup,
                &instance,
                &setup_vk,
                sk,
                move |_, _| Some(keyshare),
            )
            .ok_or(anyhow::Error::msg("cant parse setup message"))?;

            let sign = sign::run(setup, seed, msg_relay).await?;

            Ok::<_, anyhow::Error>((sign, party_id, stats))
        });

        Ok::<_, anyhow::Error>(())
    })?;

    while let Some(share) = parties.join_next().await {
        let (sign, pid, stats) = share??;

        let sign_file_name = opts.prefix.join(format!("sign.{}", pid));

        let bytes = sign.to_der().to_bytes();

        std::fs::write(sign_file_name, bytes)?;

        let stats = stats.lock().unwrap();

        tracing::info!("send_count: {} {}", pid, stats.send_count);
        tracing::info!("send_size:  {} {}", pid, stats.send_size);
        tracing::info!("recv_count: {} {}", pid, stats.recv_count);
        tracing::info!("recv_size:  {} {}", pid, stats.recv_size);
    }

    Ok(())
}
