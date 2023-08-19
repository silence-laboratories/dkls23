use rand::prelude::*;

use k256::elliptic_curve::group::GroupEncoding;
use tokio::task;

use dkls23::keygen::{
    messages::{KeygenMsg1, KeygenMsg2, KeygenMsg3, KeygenMsg4, KeygenMsg5, KeygenMsg6, Keyshare},
    KeygenParty, PartyKeys, PartyPublicKeys,
};
use sl_mpc_mate::traits::{PersistentObject, Round};

use super::{default_coord, flags, Coordinator};

struct PartyParams {
    session: String,
    share: String,
    keys: PartyKeys,
    n_i: u8,
}

fn parse_party(party: &str) -> anyhow::Result<PartyParams> {
    let parts = party.split(':').collect::<Vec<_>>(); // sid:share:keys:n_i

    if parts.len() < 2 {
        anyhow::bail!("invalid --party option: {party:?}")
    }

    let session = parts.first().unwrap().to_string();

    let share = parts.get(1).unwrap().to_string();

    let keys = parts
        .get(2)
        .filter(|s| !s.is_empty())
        .map(|s| load_party_keys(s))
        .transpose()?
        .unwrap_or_else(|| {
            let mut rng = rand::thread_rng();
            PartyKeys::new(&mut rng)
        });

    let n_i = parts.get(3).and_then(|s| s.parse::<u8>().ok()).unwrap_or(0);

    Ok(PartyParams {
        session,
        share,
        keys,
        n_i,
    })
}

pub async fn keygen_party(
    coord: &mut Coordinator,
    party_keys: PartyKeys,
    t: u8,
    n: u8,
    n_i: u8,
) -> anyhow::Result<Keyshare> {
    tracing::info!("start T {}, N {} session {}", t, n, coord.session_id());

    let public_keys = party_keys.public_keys().to_bytes().unwrap();

    log::info!("sending public keys");

    let pid = coord.send(public_keys, 0).await?;

    let init = {
        let mut rng = rand::thread_rng();
        let seed: [u8; 32] = rng.gen();

        KeygenParty::new(t as _, n as _, pid as _, n_i as _, &party_keys, seed)?
    };

    tracing::info!("keygen: pid {pid} sent pubkeys");

    let batch0 = coord
        .recv(0, true)
        .await
        .map(|b| PartyPublicKeys::decode_batch(&b).unwrap())
        .unwrap();

    log::info!("keygen: recv {pid} {}", 0);

    let (r1, msg1) = init.process(batch0).unwrap();

    coord.send(msg1.to_bytes().unwrap(), 1).await.unwrap();

    let batch1 = coord
        .recv(1, true)
        .await
        .map(|b| KeygenMsg1::decode_batch(&b).unwrap())
        .unwrap();

    log::info!("keygen: recv {pid} {}", 1);

    let (r2, msg2) = task::block_in_place(|| r1.process(batch1).unwrap());

    coord.send(msg2.to_bytes().unwrap(), 2).await.unwrap();

    let batch2 = coord
        .recv(2, true)
        .await
        .map(|b| KeygenMsg2::decode_batch(&b).unwrap())
        .unwrap();

    log::info!("keygen: recv {pid} {}", 2);

    let (r3, msg3) = task::block_in_place(|| r2.process(batch2).unwrap());

    coord.send(msg3.to_bytes().unwrap(), 3).await.unwrap();

    let batch3 = coord
        .recv(3, true)
        .await
        .map(|b| KeygenMsg3::decode_batch(&b).unwrap())
        .unwrap();

    log::info!("keygen: recv {pid} {}", 3);

    let (r4, msg4) = task::block_in_place(|| r3.process(batch3).unwrap());

    coord.send(msg4.to_bytes().unwrap(), 4).await.unwrap();

    let batch4 = coord
        .recv(4, true)
        .await
        .map(|b| KeygenMsg4::decode_batch(&b).unwrap())
        .unwrap();

    log::info!("keygen: recv {pid} {}", 4);

    let (r5, msg5) = task::block_in_place(|| r4.process(batch4).unwrap());

    coord.send(msg5.to_bytes().unwrap(), 5).await.unwrap();

    let batch5 = coord
        .recv(5, true)
        .await
        .map(|b| KeygenMsg5::decode_batch(&b).unwrap())
        .unwrap();

    log::info!("keygen: recv {pid} {}", 5);

    let (r6, msg6) = task::block_in_place(|| r5.process(batch5).unwrap());

    coord.send(msg6.to_bytes().unwrap(), 6).await.unwrap();

    let batch6 = coord
        .recv(6, true)
        .await
        .map(|b| KeygenMsg6::decode_batch(&b).unwrap())
        .unwrap();

    log::info!("keygen: recv {pid} {}", 6);

    let (keyshare, _final_message) = task::block_in_place(|| r6.process(batch6).unwrap());

    log::info!("keygen: done {pid}");

    Ok(keyshare)
}

fn load_party_keys(file_name: &str) -> anyhow::Result<PartyKeys> {
    log::info!("load_party_keys {file_name:?}");

    let bytes = std::fs::read(file_name)?;

    let keys = PartyKeys::from_bytes(&bytes).unwrap();

    Ok(keys)
}

pub async fn run_keygen(opts: flags::KeyGen) -> anyhow::Result<()> {
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
                    share,
                    keys,
                    n_i,
                } = params;

                let mut coord = Coordinator::new(base_url, &session, 6 + 1, None);

                let keyshare = keygen_party(&mut coord, keys, opts.t, opts.n, n_i).await?;

                Ok::<_, anyhow::Error>((keyshare, share))
            })
        })
        .collect::<Vec<_>>();

    for handle in futs.into_iter() {
        let res = handle.await?;

        let (keyshare, file_name) = res?;

        std::fs::write(file_name, keyshare.to_bytes().unwrap())?;
    }

    Ok(())
}

pub fn party_keys(opts: flags::PartyKeys) -> anyhow::Result<()> {
    let mut rng = rand::thread_rng();

    let party_keys = PartyKeys::new(&mut rng).to_bytes().unwrap();

    std::fs::write(opts.path, party_keys)?;

    Ok(())
}

pub fn run_share_pubkey(opts: flags::SharePubkey) -> anyhow::Result<()> {
    let body = std::fs::read(opts.share)?;

    let share = Keyshare::from_bytes(&body).unwrap();

    let pubkey = share.public_key.to_affine().to_bytes().to_vec();

    println!("{}", hex::encode(pubkey));

    Ok(())
}
