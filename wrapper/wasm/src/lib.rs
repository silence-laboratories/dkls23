use std::borrow::Borrow;

use hex::FromHex;
use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;

use sl_mpc_mate::{coord::*, message::*};

mod abort;
mod keygen;
mod keyshare;
mod relay;
mod setup;
mod sign;
mod utils;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

fn parse_instance_bytes(s: &str) -> Result<[u8; 32], JsError> {
    Ok(<[u8; 32]>::from_hex(s)?)
}

fn parse_instance_id(s: &str) -> Result<InstanceId, JsError> {
    Ok(InstanceId::from(parse_instance_bytes(s)?))
}

#[wasm_bindgen(js_name = genInstanceId)]
pub fn gen_instance_id() -> Uint8Array {
    let bytes: [u8; 32] = rand::random();

    Uint8Array::from(bytes.as_slice())
}

#[wasm_bindgen(js_name = verifyingKey)]
pub fn verying_key(sk: &[u8]) -> Uint8Array {
    let sk = sk.try_into().expect_throw("invalid SK size");
    let sk = SigningKey::from_bytes(&sk);

    Uint8Array::from(sk.verifying_key().as_bytes().as_slice())
}

#[wasm_bindgen(js_name = createMsgId)]
pub fn create_msg_id(
    instance: &str,
    sender_pk: &str,
    receiver_pk: Option<String>,
    tag: u32,
) -> Result<Uint8Array, JsError> {
    let instance = parse_instance_id(instance)?;

    let sender_pk = <[u8; 32]>::from_hex(sender_pk)?;

    let receiver_pk = match receiver_pk {
        None => None,
        Some(pk) => Some(<[u8; 32]>::from_hex(pk)?),
    };

    let tag = MessageTag::tag(tag as _);

    let msg_id = MsgId::new(&instance, &sender_pk, receiver_pk.as_ref(), tag);

    Ok(Uint8Array::from(msg_id.borrow()))
}
