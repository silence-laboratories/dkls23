use dkls23::keygen::{
    gen_keyshares, key_refresh::run as run_key_refresh, key_refresh::setup_key_refresh, KeygenError,
};
use sl_mpc_mate::coord::SimpleMessageRelay;
use tokio::task::JoinSet;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), KeygenError> {
    tracing_subscriber::fmt::init();

    const T: u8 = 2;
    const N: u8 = 3;
    const K: u8 = 100;

    let start = std::time::Instant::now();

    for _ in 0..K {
        let old_shares = gen_keyshares(T, N, Some(&[0, 1, 1])).await;

        let coord = SimpleMessageRelay::new();

        let mut parties = JoinSet::new();
        for (setup, seed, share) in
            setup_key_refresh(2, 3, Some(&[0, 1, 1]), &old_shares).into_iter()
        {
            parties.spawn(run_key_refresh(setup, seed, coord.connect(), share));
        }

        let mut new_keyshares = vec![];

        while let Some(fini) = parties.join_next().await {
            let fini = fini.unwrap();

            if let Err(ref err) = fini {
                println!("error {}", err);
            }

            assert!(fini.is_ok());

            let new_share = fini.unwrap();

            new_keyshares.push(new_share)
        }
    }

    println!("Time taken: {:?}", start.elapsed());

    Ok(())
}
