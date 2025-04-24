use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinSet;

use derivation_path::DerivationPath;

use rand::Rng;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use k256::ecdsa::{RecoveryId, VerifyingKey};

use dkls23::{
    keygen::Keyshare,
    setup::{sign::SetupMessage, NoSigningKey, NoVerifyingKey},
    sign,
};
use sl_mpc_mate::{coord::SimpleMessageRelay, message::*};

mod common;
pub fn setup_dsg(shares: &[Arc<Keyshare>], chain_path: &str) -> Vec<SetupMessage> {
    let chain_path = DerivationPath::from_str(chain_path).unwrap();

    let t = shares[0].threshold as usize;
    assert!(shares.len() >= t);

    // make sure that first share has rank 0
    assert_eq!(shares[0].get_rank(0), 0);

    // fetch some randomness in order to uniquely identify that protocol execution with an instance id
    let mut rnd = ChaCha20Rng::from_entropy();
    let instance = rnd.gen();

    let party_vk: Vec<NoVerifyingKey> = shares
        .iter()
        .map(|share| NoVerifyingKey::new(share.party_id as _))
        .collect();

    shares
        .iter()
        .enumerate()
        .map(|(party_idx, share)| {
            SetupMessage::new(
                InstanceId::new(instance),
                NoSigningKey,
                party_idx,
                party_vk.clone(),
                share.clone(),
            )
            .with_chain_path(chain_path.clone())
            .with_hash([1; 32])
            .with_ttl(Duration::from_secs(1000))
        })
        .collect::<Vec<_>>()
}
#[tokio::main]
async fn main() {
    // Logic: The relayer follows the Actor model: It spawns from the caller task, does the assigned task
    // independently and return the result in the main task. For the purpose of that example there is no real
    // networking, but instead a combination of shared state between rust tasks and message channel passing where
    // receiver and sender channels are interleaved for p2p and broadcast communication. That is a SimpleMessageRelay. async
    // In a real setup the relayer can be an independent network entity, where all the nodes can talk to. It
    // can be implemented with a variety of existing  networking protocols such as websockets; as long as it follows the
    // underlying pull logic : Each receiver knows what message to subscribe for and so it asks the relayer to deliver it
    // as long as it arrives from the expected sender.
    // Rust: SimpleMessageRelay::new() creates an Arc<Mutex> object to be shared among all tasks. The objects does message
    // accounting in hashmap : messages: HashMap<MsgId, MsgEntry>
    let coord = SimpleMessageRelay::new();

    // We locally generate some key shares in order to test the signing procedure.
    let shares = common::shared::gen_keyshares(2, 3, Some(&[0, 0])).await;

    //fetch the public verification key from one of the keyshares
    let vk = VerifyingKey::from_affine(shares[0].public_key().to_affine()).unwrap();

    //define a chain path for the signature: m is the default one
    let chain_path = "m";

    // Here the parties are simulated as in a real world example but locally as a set of rust async tasks:
    // One task for each node to run the dkls23 ecdsa sign algorithm
    let mut parties = JoinSet::new();

    // For each node in the protocol a setup msg should be created tailored for that sign protocol. The setupmsg
    // contains information about the public parameters of the protocol: number of nodes = n, minimum threshold = t dictating
    // the minimum required nodes that need to be online in order to compute the distributed signature, a unique instance id for the sign protocol
    // a unique id that identifies that key share id that will be created common for all nodes in order to distinguish from
    // other key shares that will be potentially created, the public signature keys of each other node in order to
    // verify authenticity and integrity of p2p and broadcast messages, and the secret signing key of the node boostraping the protocol which is
    // unique and different per node.
    for setup in setup_dsg(&shares[0..2], chain_path) {
        let mut rng = ChaCha20Rng::from_entropy();
        // Each task representing a different node is "connecting" to the coordinator relayer: a new mpsc channel is created
        // in a new per node relay, whereby each relay shares the same  Arc<Mutex> messages object which has been created outside the loop
        let relay = coord.connect();

        // At that point we have created the correct setup msgs for each party with the aforementioned helper function, which
        // in real world does not exist but the consumers of the library node should create. The next step is to execute each
        // task in a an async fashion. That function in a real world example runs by each node independently who want to compute the final
        // signature.
        parties.spawn(sign::run(setup, rng.gen(), relay));
    }

    // After all the tasks have finished we extract the signature and verifying it against the public key
    while let Some(fini) = parties.join_next().await {
        let fini = fini.unwrap();

        if let Err(ref err) = fini {
            println!("error {err:?}");
        }

        let (sign, recid) = fini.unwrap();

        let hash = [1u8; 32];

        let recid2 = RecoveryId::trial_recovery_from_prehash(&vk, &hash, &sign).unwrap();

        assert_eq!(recid, recid2);
    }
}
