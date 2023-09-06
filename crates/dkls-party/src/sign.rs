use dkls23::MsgId;
use rand;
use tokio::task;

use dkls23::setup::{self, *};
use dkls23::{keygen::Keyshare, sign};

use msg_relay_client::MsgRelayClient;
use sl_mpc_mate::{coord::BoxedRelay, HashBytes};

use crate::{default_coord, flags, utils::*, SignHashFn};

pub async fn setup(opts: flags::SignSetup) -> anyhow::Result<()> {
    let pk = parse_affine_point(&opts.public_key)?;
    let setup_sk = load_signing_key(opts.sign)?;
    let setup_vk = setup_sk.verifying_key();

    let builder = opts.party.into_iter().try_fold(
        setup::sign::SetupBuilder::new(&pk),
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

        SignHashFn::Sha256 => builder.with_sha256(opts.message.into_bytes()),

        _ => unimplemented!(),
    };

    let msg_id = MsgId::new(
        &parse_instance_id(&opts.instance)?,
        &setup_vk.to_bytes(),
        None,
        SETUP_MESSAGE_TAG,
    );

    let setup = builder
        .build(&msg_id, opts.ttl, &setup_sk)
        .ok_or(anyhow::Error::msg("cant create setup message"))?;

    let coord = opts.coordinator.unwrap_or_else(default_coord);
    let msg_relay: BoxedRelay = Box::new(MsgRelayClient::connect(&coord).await?);

    msg_relay.send(setup).await;

    Ok(())
}

fn load_keyshare(file_name: &str) -> anyhow::Result<Keyshare> {
    tracing::info!("load key share {}", file_name);
    let bytes = std::fs::read(file_name)?;

    let (share, _) = bincode::decode_from_slice(&bytes, bincode::config::standard())?;

    Ok(share)
}

pub async fn run_sign(opts: flags::SignGen) -> anyhow::Result<()> {
    let mut parties = task::JoinSet::new();

    let instance = parse_instance_id(&opts.instance)?;
    let setup_vk = parse_verifying_key(&opts.setup_vk)?;

    let coord = opts.coordinator.unwrap_or_else(default_coord);

    let msg_id = MsgId::new(&instance, &setup_vk.to_bytes(), None, SETUP_MESSAGE_TAG);

    opts.party.into_iter().try_for_each(|desc| {
        let mut parts = desc.split(":");

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
            let msg_relay: BoxedRelay = Box::new(MsgRelayClient::connect(&coord).await?);

            let mut setup = msg_relay
                .recv(msg_id, 10)
                .await
                .ok_or(anyhow::Error::msg("Can't receive setup message"))?;

            let setup = setup::sign::ValidatedSetup::decode(
                &mut setup,
                &instance,
                &setup_vk,
                sk,
                move |_, _| Some(keyshare),
            )
            .ok_or(anyhow::Error::msg("cant parse setup message"))?;

            let sign = sign::run(setup, seed, msg_relay).await?;

            Ok::<_, anyhow::Error>((sign, party_id))
        });

        Ok::<_, anyhow::Error>(())
    })?;

    while let Some(share) = parties.join_next().await {
        let (sign, party_id) = share??;

        let sign_file_name = opts.prefix.join(format!("sign.{}", party_id));

        let bytes = sign.to_der().to_bytes();

        std::fs::write(sign_file_name, bytes)?;
    }

    Ok(())
}
