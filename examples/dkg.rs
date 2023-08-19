use dkls23::keygen::{run_round, setup_keygen, KeygenError};
use k256::elliptic_curve::group::GroupEncoding;

fn main() -> Result<(), KeygenError> {
    const T: usize = 3;
    const N: usize = 5;

    let start = std::time::Instant::now();

    let (parties, mut coord) = setup_keygen::<T, N>(None)?;
    let parties1 = run_round(&mut coord, parties, 0);
    let parties2 = run_round(&mut coord, parties1, 1);
    let parties3 = run_round(&mut coord, parties2, 2);
    let parties4 = run_round(&mut coord, parties3, 3);
    let parties5 = run_round(&mut coord, parties4, 4);
    let parties6 = run_round(&mut coord, parties5, 5);
    let keyshares = run_round(&mut coord, parties6, 6);
    println!("Time taken: {:?}", start.elapsed());

    for (pid, key) in keyshares.iter().enumerate() {
        println!(
            "Party-{}'s public_key: 0x{}, OT count: {}+{}",
            pid,
            hex::encode(key.public_key.to_bytes()),
            key.seed_ot_senders.len(),
            key.seed_ot_receivers.len()
        );
    }

    Ok(())
}
