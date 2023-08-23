use sl_mpc_mate::{message::*, coord::MessageRelay};

/// Pairwise MTA
pub mod pairwise_mta;

mod dsg;
mod messages;
mod types;

pub use dsg::*;
pub use messages::*;
pub use types::*;


// fn find_pair<T>(pairs: &[(u8, T)], party_id: u8) -> Result<&T, KeygenError> {
//     pairs
//         .iter()
//         .find(|(p, _)| *p == party_id)
//         .map(|(_, v)| v)
//         .ok_or(KeygenError::InvalidParty(party_id))
// }

// fn pop_pair<T>(pairs: &mut Pairs<T>, party_id: u8) -> Result<T, KeygenError> {
//     let pos = pairs
//         .iter()
//         .position(|(p, _)| *p == party_id)
//         .ok_or(KeygenError::InvalidParty(party_id))?;

//     Ok(pairs.remove(pos).1)
// }

// fn remove_ids<T>(mut pairs: Vec<(u8, T)>) -> Vec<T> {
//     pairs.sort_by_key(|(p, _)| *p);
//     pairs.into_iter().map(|(_, v)| v).collect()
// }

// fn remove_ids_and_wrap<T, K>(mut pairs: Vec<(u8, T)>) -> Vec<Opaque<T, K>> {
//     pairs.sort_by_key(|(p, _)| *p);
//     pairs.into_iter().map(|(_, v)| Opaque::from(v)).collect()
// }

// fn recv_p2p_messages(
//     setup: &ValidatedSetup,
//     tag: MessageTag,
//     relay: &MessageRelay,
// ) -> JoinSet<Result<(Vec<u8>, u8), KeygenError>> {
//     let mut js = JoinSet::new();
//     let me = Some(setup.party_id());
//     setup.other_parties_iter().for_each(|(p, vk)| {
//         // P2P message from party VK (p) to me
//         let msg_id = setup.msg_id_from(vk, me, tag);
//         let relay = relay.clone();

//         js.spawn(async move {
//             let msg = relay
//                 .recv(msg_id, 10)
//                 .await
//                 .ok_or(KeygenError::InvalidMessage)?;
//             Ok::<_, KeygenError>((msg, p))
//         });
//     });

//     js
// }

// fn recv_broadcast_messages(
//     setup: &ValidatedSetup,
//     tag: MessageTag,
//     relay: &MessageRelay,
// ) -> JoinSet<Result<(Vec<u8>, u8), KeygenError>> {
//     let mut js = JoinSet::new();
//     setup.other_parties_iter().for_each(|(p, vk)| {
//         // broadcast message from party `p'
//         let msg_id = setup.msg_id_from(vk, None, tag);
//         let relay = relay.clone();

//         js.spawn(async move {
//             let msg = relay
//                 .recv(msg_id, 10)
//                 .await
//                 .ok_or(KeygenError::InvalidMessage)?;
//             Ok::<_, KeygenError>((msg, p))
//         });
//     });

//     js
// }

// fn decode_signed_message<T: bincode::Decode>(
//     msg: Result<Result<(Vec<u8>, u8), KeygenError>, JoinError>,
//     setup: &ValidatedSetup,
// ) -> Result<(T, u8), KeygenError> {
//     let (mut msg, party_id) = msg.map_err(|_| KeygenError::InvalidMessage)??; // it's ugly, I know

//     let msg = Message::from_buffer(&mut msg)?;
//     let msg = msg.verify_and_decode::<T>(&setup.party_verifying_key(party_id).unwrap())?;

//     Ok((msg, party_id))
// }

// fn decode_encrypted_message<T: bincode::Decode>(
//     msg: Result<Result<(Vec<u8>, u8), KeygenError>, JoinError>,
//     secret: &ReusableSecret,
//     enc_pub_keys: &[(u8, PublicKey)],
// ) -> Result<(T, u8), KeygenError> {
//     let (mut msg, party_id) = msg.map_err(|_| KeygenError::InvalidMessage)??; // it's ugly, I know

//     let mut msg = Message::from_buffer(&mut msg)?;
//     let msg = msg.decrypt_and_decode::<T>(
//         MESSAGE_HEADER_SIZE,
//         secret,
//         find_pair(enc_pub_keys, party_id)?,
//     )?;

//     Ok((msg, party_id))
// }
