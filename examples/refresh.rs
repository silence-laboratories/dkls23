use k256::elliptic_curve::group::GroupEncoding;
use rand::Rng;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sl_dkls23::keygen::key_refresh::KeyshareForRefresh;
use sl_mpc_mate::coord::SimpleMessageRelay;
use std::sync::Arc;
use tokio::task::JoinSet;

mod common;

#[tokio::main]
pub async fn main() {
    // Create 3 keyshares in order to be refreshed
    let old_shares = common::shared::gen_keyshares(2, 3).await;

    // Logic: The relayer follows the Actor model: It spawns from the caller task, does the assigned task
    // independently and return the result in the main task. For the purpose of that example there is no real
    // networking, but instead a combination of shared state between rust tasks and message channel passing where
    // receiver and sender channels are interleaved for p2p and broadcast communication. That is a SimpleMessageRelay.
    // In a real setup the relayer can be an independent network entity, where all the nodes can talk to. It
    // can be implemented with a variety of existing  networking protocols such as websockets; as long as it follows the
    // underlying pull logic : Each receiver knows what message to subscribe for and so it asks the relayer to deliver it
    // as long as it arrives from the expected sender.
    // Rust: SimpleMessageRelay::new() creates an Arc<Mutex> object to be shared among all tasks. The objects does message
    // accounting in hashmap : messages: HashMap<MsgId, MsgEntry>
    let coord = SimpleMessageRelay::new();

    // Here the parties are simulated as in a real world example but locally as a set of rust async tasks:
    // One task for each node to run the DKLs23 ecdsa refresh algorithm
    let mut parties = JoinSet::new();

    // Tag into a new type the old key shares in order to be identifiable as key shares to be refreshed from the existing refresh
    let key_shares_for_refresh: Vec<KeyshareForRefresh> = old_shares
        .iter()
        .map(|share| KeyshareForRefresh::from_keyshare(share, None))
        .collect();

    let mut rng = ChaCha20Rng::from_entropy();

    // For each node in the protocol a setup msg should be created tailored for that keygen protocol. The setupmsg
    // contains information about the public parameters of the protocol: number of nodes = n, minimum threshold = t dictating
    // the minimum required nodes that need to be online in order to compute the distributed signature, a unique instance id for the keygen protocol
    // a unique id that identifies that key share id that will be created common for all nodes in order to distinguish from
    // other key shares that will be potentially created, the public signature keys of each other node in order to
    // verify authenticity and integrity of p2p and broadcast messages, and the secret signing key of the node boostraping the protocol which is
    // unique and different per node.
    for (setup, share) in common::shared::setup_keygen(2, 3, None)
        .into_iter()
        .zip(key_shares_for_refresh)
        .collect::<Vec<_>>()
    {
        // run the keyrefresh protocol for each node
        parties.spawn(sl_dkls23::keygen::key_refresh::run(
            setup,
            rng.gen(),
            coord.connect(),
            share,
        ));
    }

    let mut new_shares = vec![];
    while let Some(fini) = parties.join_next().await {
        let fini = fini.unwrap();

        if let Err(ref err) = fini {
            println!("error {}", err);
        }

        assert!(fini.is_ok());

        // Print all the new PK of the refreshed share
        let new_share = fini.unwrap();
        let pk = hex::encode(new_share.public_key().to_bytes());

        new_shares.push(Arc::new(new_share));

        println!("PK {}", pk);
    }

    //check that this is equal the old key share public key
    println!(
        "Old PK{}",
        hex::encode(old_shares[0].public_key().to_bytes())
    );

    // sign with new key_shares and verify
    let coord = SimpleMessageRelay::new();

    new_shares.sort_by_key(|share| share.party_id);
    let subset = &new_shares[0..2_usize];

    let mut parties: JoinSet<Result<_, _>> = JoinSet::new();
    for setup in common::shared::setup_dsg(subset, "m") {
        parties.spawn(sl_dkls23::sign::run(
            setup,
            rng.gen(),
            coord.connect(),
        ));
    }

    while let Some(fini) = parties.join_next().await {
        let fini = fini.unwrap();

        if let Err(ref err) = fini {
            println!("error {err:?}");
        }
        let _fini = fini.unwrap();
    }
}
