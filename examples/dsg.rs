// use rand::seq::IteratorRandom;
use std::time::Duration;
use tokio::task::JoinSet;

use dkls23::{
    keygen::{gen_keyshares, messages::Keyshare},
    sign,
};
use sl_mpc_mate::coord::SimpleMessageRelay;

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let t: u8 = 3;
    let n: u8 = 5;

    const K: usize = 100;

    let ranks: Vec<u8> = (0..n).map(|i| (i != 0) as u8).collect(); // 0, 1, ...
    let keyshares = gen_keyshares(t, n, Some(&ranks)).await;

    // let mut rng = rand::thread_rng();
    // let subset: Vec<_> = keyshares.into_iter().choose_multiple(&mut rng, T);
    let subset = &keyshares[0..t as usize];

    let start = std::time::Instant::now();

    for _ in 0..K {
        dsg(&subset).await;
    }

    let d = start.elapsed();
    let one = Duration::new(0, (d.as_nanos() / K as u128) as u32);
    println!("Time taken: DSG {}x{} {:?}/{} {:?}", t, n, d, K, one);
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
