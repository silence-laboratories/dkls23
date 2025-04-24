pub mod shared {
    use dkls23::keygen;
    use dkls23::keygen::Keyshare;
    use dkls23::setup::sign::SetupMessage as SignSetupMessage;
    use dkls23::setup::{
        keygen::SetupMessage, keygen::SetupMessage as KeygenSetupMessage, NoSigningKey,
        NoVerifyingKey,
    };
    use std::str::FromStr;

    use rand::Rng;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use std::sync::Arc;
    use std::time::Duration;

    use derivation_path::DerivationPath;
    use sl_mpc_mate::message::InstanceId;

    //helper function to create the setup messages per party
    pub fn setup_keygen(t: u8, n: u8, ranks: Option<&[u8]>) -> Vec<KeygenSetupMessage> {
        use std::time::Duration;

        use sl_mpc_mate::message::InstanceId;

        let ranks = if let Some(ranks) = ranks {
            assert_eq!(ranks.len(), n as usize);
            ranks.to_vec()
        } else {
            vec![0u8; n as usize]
        };

        // fetch some randomness in order to uniquely identify that protocol execution with an instance id
        let mut rnd = ChaCha20Rng::from_entropy();
        let instance = rnd.gen();

        // a secret signing key for each party in order to send signed messages over the network.
        // For local tests that is disabled with an empty key
        let party_sk: Vec<NoSigningKey> = std::iter::repeat_with(|| NoSigningKey)
            .take(n as usize)
            .collect();

        // Compute the corresponding verification key of each party
        let party_vk: Vec<NoVerifyingKey> = party_sk
            .iter()
            .enumerate()
            .map(|(party_id, _)| NoVerifyingKey::new(party_id))
            .collect();

        // iterate all parties and create locally the setup message for each one. In a real world setup
        // the parties do start sharing their verification keys with each other in order to to all have
        // a common view in a local map :party_ids->verification keys
        party_sk
            .into_iter()
            .enumerate()
            .map(|(party_id, sk)| {
                SetupMessage::new(
                    InstanceId::new(instance),
                    sk,
                    party_id,
                    party_vk.clone(),
                    &ranks,
                    t as usize,
                )
                .with_ttl(Duration::from_secs(1000)) // for dkls-metrics benchmarks
            })
            .collect::<Vec<_>>()
    }
    pub async fn gen_keyshares(t: u8, n: u8) -> Vec<Arc<Keyshare>> {
        let coord = sl_mpc_mate::coord::SimpleMessageRelay::new();

        let mut parties = tokio::task::JoinSet::new();
        for setup in setup_keygen(t, n, None) {
            parties.spawn({
                let relay = coord.connect();
                let mut rng = ChaCha20Rng::from_entropy();
                keygen::run(setup, rng.gen(), relay)
            });
        }

        let mut shares = vec![];

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

        shares.sort_by_key(|share| share.party_id);

        shares
    }
    pub fn setup_dsg(
        shares: &[Arc<Keyshare>],
        chain_path: &str,
    ) -> Vec<dkls23::setup::sign::SetupMessage> {
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
                SignSetupMessage::new(
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
}
