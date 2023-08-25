use rand::seq::IteratorRandom;
use tokio::task::JoinSet;

use dkls23::{
    keygen::{gen_keyshares, messages::Keyshare},
    sign,
};
use sl_mpc_mate::coord::SimpleMessageRelay;

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let keyshares = gen_keyshares::<3, 5>(None).await;

    let mut rng = rand::thread_rng();

    let subset: Vec<_> = keyshares.into_iter().choose_multiple(&mut rng, 3);

    let start = std::time::Instant::now();

    for _ in 0..100 {
        dsg(&subset).await;
    }

    println!("Time taken: {:?}", start.elapsed());
}

async fn dsg(shares: &[Keyshare]) {
    let coord = SimpleMessageRelay::new();

    let pk = shares[0].public_key.to_affine();

    let mut parties = JoinSet::new();
    for (setup, seed) in sign::setup_dsg(&pk, shares).into_iter() {
        parties.spawn(sign::run(setup, seed, coord.connect()));
    }

    while let Some(fini) = parties.join_next().await {
        let fini = fini.unwrap();

        if let Err(ref err) = fini {
            println!("error {err:?}");
        }

        let _fini = fini.unwrap();
    }
}
