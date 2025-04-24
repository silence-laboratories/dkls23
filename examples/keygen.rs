use dkls23::keygen;
use k256::elliptic_curve::group::GroupEncoding;
use rand::Rng;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use std::sync::Arc;

mod common;

#[tokio::main]
pub async fn main() {
    let t: u8 = 2;
    let n: u8 = 3;

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
    let coord = sl_mpc_mate::coord::SimpleMessageRelay::new();

    // Here the parties are simulated as in a real world example but locally as a set of rust async tasks:
    // One task for each node to run the dkls23 ecdsa keygen algorithm
    let mut parties = tokio::task::JoinSet::new();

    // For each node in the protocol a setup msg should be created tailored for that keygen protocol. The setupmsg
    // contains information about the public parameters of the protocol: number of nodes = n, minimum threshold = t dictating
    // the minimum required nodes that need to be online in order to compute the distributed signature, a unique instance id for the keygen protocol
    // a unique id that identifies that key share id that will be created common for all nodes in order to distinguish from
    // other key shares that will be potentially created, the public signature keys of each other node in order to
    // verify authenticity and integrity of p2p and broadcast messages, and the secret signing key of the node boostraping the protocol which is
    // unique and different per node.
    for setup in common::shared::setup_keygen(t, n, None) {
        parties.spawn({
            // Each task representing a different node is "connecting" to the coordinator relayer: a new mpsc channel is created
            // in a new per node relay, whereby each relay shares the same  Arc<Mutex> messages object which has been created outside the loop
            let relay = coord.connect();
            // At that point we have created the correct setup msgs for each party with the aforementioned helper function, which
            // in real world does not exist but the consumers of the library node should create. The next step is to execute each
            // task in an async fashion. That function in a real world example runs by each node independently.
            let mut rng = ChaCha20Rng::from_entropy();
            keygen::run(setup, rng.gen(), relay)
        });
    }

    // Here we create a vector to consolidate all the created key shares from the keygen protocol.
    // In a real world each node receives each secret keyshare and nothing else
    let mut shares = vec![];

    // After all the tasks have finished we extract the  key share per node and store it
    // in the shares vector in order to later test that they all agree on the public key
    while let Some(fini) = parties.join_next().await {
        if let Err(ref err) = fini {
            println!("error {err:?}");
        } else {
            match fini.unwrap() {
                Err(err) => panic!("err {:?}", err),
                Ok(share) => shares.push(Arc::new(share)),
            }
        }
    }

    //print the common public key created from each user key share
    for keyshare in shares.iter() {
        println!("PK{}", hex::encode(keyshare.public_key().to_bytes()));
    }
}
