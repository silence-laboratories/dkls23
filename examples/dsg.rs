use k256::sha2::{Digest, Sha256};
use rand::seq::IteratorRandom;

use sl_mpc_mate::{
    cooridinator::Coordinator,
    recv_broadcast,
    traits::{HasFromParty, HasToParty, PersistentObject, Round},
};

use dkls23::{
    keygen::{messages::Keyshare, process_keygen, run_round},
    sign::{R2State, SignMsg2, SignerParty},
};

fn gen_keyshares<const T: usize, const N: usize>() -> [Keyshare; N] {
    let (_, keyshares) = process_keygen::<T, N>(None);

    keyshares
}

fn main() {
    let keyshares = gen_keyshares::<3, 5>();

    let mut rng = rand::thread_rng();

    let subset: Vec<_> = keyshares.into_iter().choose_multiple(&mut rng, 3);

    let start = std::time::Instant::now();

    for _ in 0..100 {
        dsg(&subset);
    }

    println!("Time taken: {:?}", start.elapsed());
}

fn dsg(subset: &[Keyshare]) {
    let mut rng = rand::thread_rng();

    let mut coord = Coordinator::new(subset.len(), 3);
    let mut parties0 = vec![];

    for keyshare in subset.iter() {
        let party = SignerParty::new(keyshare.clone(), &mut rng);
        let pubkeys = party.get_public_keys();
        coord.send(0, pubkeys.to_bytes().unwrap()).unwrap();
        parties0.push(party);
    }

    let parties1 = run_round(&mut coord, parties0, 0);
    let parties2 = run_round(&mut coord, parties1, 1);

    let msgs: Vec<Vec<SignMsg2>> = recv_broadcast(&mut coord, 2);

    let mut sign_msgs3_list = vec![];
    let mut parties3 = vec![];

    for mut party in parties2 {
        let pid = party.get_pid();
        let msgs = get_party_messages(pid, &msgs);

        let sign_msgs3 = msgs
            .into_iter()
            .map(|msg| party.process_p2p(msg).unwrap())
            .collect::<Vec<_>>();

        sign_msgs3_list.push(sign_msgs3);

        if let R2State::R2Complete(party3) = party.check_proceed() {
            parties3.push(party3);
        } else {
            panic!("Party {} not ready to proceed", pid);
        }
    }

    let mut parties4 = vec![];
    for party in parties3 {
        let pid = party.get_pid();
        let msgs = get_party_messages(pid, &sign_msgs3_list);

        let p4 = party.process(msgs).unwrap();
        parties4.push(p4);
    }

    let mut hasher = Sha256::new();
    hasher.update(b"Hello World");
    let hash = hasher.finalize().into();

    let mut parties5 = vec![];
    let mut msgs4 = vec![];
    for party in parties4 {
        let (party5, msg4) = party.process(hash).unwrap();
        parties5.push(party5);
        msgs4.push(msg4.clone());
    }

    for party in parties5 {
        let _sign = party.process(msgs4.clone()).unwrap();

        // println!("Signature: {:?}", sign.to_string())
    }
}

fn get_party_messages<M: HasToParty + HasFromParty + Clone>(
    for_party: usize,
    msgs: &[Vec<M>],
) -> Vec<M> {
    let mut msgs_for_party = vec![];
    for msg_list in msgs {
        if msg_list[0].get_pid() == for_party {
            continue;
        }
        for msg in msg_list {
            if msg.get_receiver() == for_party {
                msgs_for_party.push(msg.clone());
            }
        }
    }

    msgs_for_party
}
