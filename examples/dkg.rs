use dkls23::keygen::{self, setup_keygen, KeygenError};
// use k256::elliptic_curve::group::GroupEncoding;
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
        let coord = SimpleMessageRelay::new();

        let mut parties = JoinSet::new();
        for (setup, seed) in setup_keygen(T, N, None).into_iter() {
            parties.spawn(keygen::run(setup, seed, coord.connect()));
        }

        let mut keyshares = vec![];

        while let Some(fini) = parties.join_next().await {
            let fini = fini.unwrap();

            if let Err(ref err) = fini {
                println!("error {err:?}");
            }

            assert!(fini.is_ok());

            let share = fini.unwrap();

            keyshares.push(share);
        }
    }

    println!("Time taken: {:?}", start.elapsed());

    // for (pid, key) in keyshares.iter().enumerate() {
    //     println!(
    //         "Party-{}'s public_key: 0x{}, OT count: {}+{}",
    //         pid,
    //         hex::encode(key.public_key.to_bytes()),
    //         key.seed_ot_senders.len(),
    //         key.seed_ot_receivers.len()
    //     );
    // }

    Ok(())
}
