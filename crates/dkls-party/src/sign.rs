use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use tiny_keccak::{Hasher, Keccak};
use tokio::task;

use dkls23::sign::{R2State, SignMsg2, SignMsg3, SignMsg4, SignerParty};

use dkls23::keygen::messages::Keyshare;

use sl_mpc_mate::traits::{HasFromParty, HasToParty, PersistentObject, Round};

use super::*;

struct PartyParams {
    session: String,
    signature: String,
    share: String,
}

fn parse_party(party: &str) -> anyhow::Result<PartyParams> {
    let parts = party.split(':').collect::<Vec<_>>(); // sid:share:singature

    if parts.len() != 3 {
        anyhow::bail!("invalid --party option: {party:?}")
    }

    let session = *parts.first().unwrap();

    let share = *parts.get(1).unwrap();

    let signature = *parts.get(2).unwrap();

    Ok(PartyParams {
        session: session.into(),
        signature: signature.into(),
        share: share.into(),
    })
}

fn load_keyshare(file_name: &str) -> anyhow::Result<Keyshare> {
    tracing::info!("load key share {}", file_name);
    let body = std::fs::read(file_name)?;

    Ok(Keyshare::from_bytes(&body).unwrap())
}

fn get_party_messages<M: HasToParty + HasFromParty + Clone>(
    for_party: usize,
    msgs: &[Vec<M>],
) -> Vec<M> {
    let mut msgs_for_party = vec![];
    for msg_list in msgs {
        if msg_list[0].get_pid() == for_party {
            continue;
        }
        for msg in msg_list {
            if msg.get_receiver() == for_party {
                msgs_for_party.push(msg.clone());
            }
        }
    }

    msgs_for_party
}

fn hash_message(message: &[u8], hash_fn: SignHashFn) -> [u8; 32] {
    match hash_fn {
        SignHashFn::Keccak256 => {
            let mut hash = [0u8; 32];
            let mut hasher = Keccak::v256();
            hasher.update(message.as_ref());
            hasher.finalize(&mut hash);
            hash
        }

        SignHashFn::Sha256 => Sha256::new()
            .chain_update(message.as_ref())
            .finalize()
            .into(),

        SignHashFn::Sha256D => {
            let mut hasher = Sha256::new();
            hasher.update(message.as_ref());
            let hash1 = hasher.finalize_reset();
            hasher.chain_update(hash1).finalize().into()
        }

        SignHashFn::NoHash => message
            .as_ref()
            .try_into()
            .expect("Without a hashing function, the given message must be 32 bytes long"),
    }
}

pub async fn sign_party(
    coord: &mut Coordinator,
    share: Keyshare,
    hash_fn: SignHashFn,
) -> anyhow::Result<(Vec<u8>, Vec<(u32, Duration)>)> {
    tracing::info!("enter sign_party session {}", coord.session_id());

    let r0 = {
        let mut rng = rand::thread_rng();
        SignerParty::new(share, &mut rng)
    };

    let public_keys = r0.get_public_keys().to_bytes().unwrap();

    coord.send(public_keys, 0).await?;

    let SessionConfig { signmsg, .. } = coord.session_config().await?;

    log::info!("signmsg: sid {} {:?}", coord.session_id(), signmsg);

    let msg = signmsg.as_ref().map(|s| s.as_bytes()).unwrap_or(&[]);

    let hash = hash_message(msg, hash_fn);

    let r1 = coord.run_round(r0, 0, true).await?;

    tracing::info!("r1");

    let mut r2 = coord.run_round(r1, 1, true).await?;

    tracing::info!("r2");

    let batch2 = coord
        .recv(2, true)
        .await
        .map(|b| Vec::<SignMsg2>::decode_batch(&b).unwrap())
        .unwrap();

    let pid = r2.get_pid();
    let msgs = get_party_messages(pid, &batch2);

    let sign_msgs3 = msgs
        .into_iter()
        .map(|msg| task::block_in_place(|| r2.process_p2p(msg).unwrap()))
        .collect::<Vec<_>>();

    let r3 = if let R2State::R2Complete(party3) = r2.check_proceed() {
        party3
    } else {
        panic!("Party {} not ready to proceed", pid);
    };

    coord.send(sign_msgs3.to_bytes().unwrap(), 3).await?;

    let batch3 = coord
        .recv(3, true)
        .await
        .map(|b| Vec::<SignMsg3>::decode_batch(&b).unwrap())
        .unwrap();

    let msgs = get_party_messages(pid, &batch3);

    let r4 = task::block_in_place(|| r3.process(msgs).unwrap());

    let (r5, sign_msg4) = task::block_in_place(|| r4.process(hash).unwrap());

    coord.send(sign_msg4.to_bytes().unwrap(), 4).await?;

    let batch4 = coord
        .recv(4, true)
        .await
        .map(|b| SignMsg4::decode_batch(&b).unwrap())
        .unwrap();

    let mut times = r5.get_times();

    let r5_start = Instant::now();

    let sign = task::block_in_place(|| r5.process(batch4).unwrap());

    log::info!("done sid {}", coord.session_id());

    times.push((6, r5_start.elapsed()));

    Ok((sign.to_der().as_bytes().to_vec(), times))
}

pub async fn run_sign(opts: flags::SignGen) -> anyhow::Result<()> {
    let hash_fn = opts.hash_fn.unwrap_or(SignHashFn::Sha256);

    let futs = opts
        .party
        .iter()
        .map(|s| parse_party(s))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(|params| {
            let base_url = opts
                .coordinator
                .as_ref()
                .cloned()
                .unwrap_or_else(default_coord);

            tokio::spawn(async move {
                let PartyParams {
                    session,
                    signature,
                    share,
                } = params;

                let mut coord = Coordinator::new(base_url, &session, 5, None);

                let keyshare = load_keyshare(&share)?;

                tracing::info!("loaded share {}", share);

                let (sign, times) = sign_party(&mut coord, keyshare, hash_fn).await?;

                // for (k, v) in &coord.times {
                //     tracing::info!("sign {} {} {:?}", session, k, v);
                // }

                for (r, d) in &times {
                    tracing::info!("sign {} R {} {:?}", session, r, d);
                }

                Ok::<_, anyhow::Error>((sign, signature))
            })
        })
        .collect::<Vec<_>>();

    for handle in futs.into_iter() {
        let res = handle.await?;

        let (sign, file_name) = res?;

        std::fs::write(file_name, sign)?;
    }

    Ok(())
}
