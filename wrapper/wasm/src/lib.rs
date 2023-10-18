use std::borrow::Borrow;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use js_sys::{Promise, Uint8Array};

use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;

use serde::{Deserialize, Serialize};

use dkls23::{keygen, setup, setup::SETUP_MESSAGE_TAG, sign};
use k256::{
    elliptic_curve::{generic_array::GenericArray, group::GroupEncoding},
    AffinePoint,
};
use sl_mpc_mate::{bincode, coord::*, message::*};

mod utils;

use hex::FromHex;
use utils::set_panic_hook;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

#[wasm_bindgen(module = "/js/msg-relay.js")]
extern "C" {
    pub type MsgRelayClient;

    #[wasm_bindgen(js_namespace = MsgRelayClient)]
    pub fn connect(endpoint: &str) -> Promise;

    #[wasm_bindgen(method, js_class = "MsgRelayClient")]
    pub fn send(this: &MsgRelayClient, msg: Uint8Array);

    #[wasm_bindgen(method, js_class = "MsgRelayClient")]
    pub fn next(this: &MsgRelayClient) -> Promise;

    #[wasm_bindgen(method, js_class = "MsgRelayClient")]
    pub fn close(this: &MsgRelayClient) -> Promise;
}

#[wasm_bindgen]
pub async fn msg_relay_connect(endpoint: &str) -> Result<MsgRelayClient, JsValue> {
    let client = JsFuture::from(MsgRelayClient::connect(endpoint)).await?;
    let client: MsgRelayClient = client.dyn_into()?;

    Ok(client)
}

pub struct MsgRelay {
    ws: MsgRelayClient,
    closef: Option<(JsFuture, bool)>,
    next: Option<JsFuture>,
}

impl MsgRelay {
    pub fn new(ws: MsgRelayClient) -> Self {
        Self {
            ws,
            closef: None,
            next: None,
        }
    }
}

impl Stream for MsgRelay {
    type Item = Vec<u8>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        loop {
            if let Some(fut) = &mut this.next {
                match Pin::new(fut).poll(cx) {
                    Poll::Pending => return Poll::Pending,

                    Poll::Ready(Err(_)) => {
                        this.next = None;
                        return Poll::Ready(None);
                    }

                    Poll::Ready(Ok(msg)) => {
                        this.next = None;
                        let msg = match msg.dyn_into::<Uint8Array>() {
                            Ok(msg) => msg,
                            Err(_) => return Poll::Ready(None),
                        };

                        // let hdr = MsgHdr::from(&msg.to_vec()).unwrap();
                        // log(&format!("got {:X} {:?}", hdr.id, hdr.kind));

                        return Poll::Ready(Some(msg.to_vec()));
                    }
                }
            } else {
                this.next = Some(JsFuture::from(this.ws.next()));
            }
        }
    }
}

impl Sink<Vec<u8>> for MsgRelay {
    type Error = InvalidMessage;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
        // let hdr = MsgHdr::from(&item).unwrap();
        // log(&format!("send {:X} {:?}", hdr.id, hdr.kind));
        self.ws.send(Uint8Array::from(item.as_ref()));

        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        loop {
            if let Some((fut, closed)) = &mut this.closef {
                if *closed || Pin::new(fut).poll(cx).is_ready() {
                    *closed = true;
                    return Poll::Ready(Ok(()));
                } else {
                    return Poll::Pending;
                }
            }

            this.closef = Some((JsFuture::from(this.ws.close()), false));
        }
    }
}

fn parse_instance_bytes(s: &str) -> Result<[u8; 32], JsValue> {
    <[u8; 32]>::from_hex(s).map_err(|_| JsValue::from_str("cant parse hex"))
}

fn parse_instance_id(s: &str) -> Result<InstanceId, JsValue> {
    Ok(InstanceId::from(parse_instance_bytes(s)?))
}

#[wasm_bindgen]
pub async fn dkg(
    instance: &str,
    setup_vk: &str,
    signing_key: &str,
    endpoint: &str,
    seed: &str,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();

    let instance = parse_instance_id(instance)?;
    let setup_vk =
        VerifyingKey::from_bytes(&parse_instance_bytes(setup_vk)?).expect_throw("parse setup VK");
    let signing_key = SigningKey::from_bytes(&parse_instance_bytes(signing_key)?);
    let seed = parse_instance_bytes(seed)?;

    let ws = msg_relay_connect(endpoint).await?;
    let msg_relay = MsgRelay::new(ws);
    let mut msg_relay = BufferedMsgRelay::new(msg_relay);

    let msg_id = MsgId::new(&instance, setup_vk.as_bytes(), None, SETUP_MESSAGE_TAG);

    let mut setup_msg = msg_relay
        .recv(&msg_id, 10)
        .await
        .expect_throw("recv setup msg");

    let setup = keygen::ValidatedSetup::decode(
        &mut setup_msg,
        &instance,
        &setup_vk,
        signing_key,
        |_, _, _| true,
    )
    .expect_throw("parse setup msg");

    let keyshare = keygen::run(setup, seed, msg_relay)
        .await
        .expect_throw("DKG failed");

    let keyshare = bincode::encode_to_vec(keyshare, bincode::config::standard()).unwrap_throw();

    Ok(Uint8Array::from(keyshare.as_ref()))
}

#[wasm_bindgen]
pub async fn dsg(
    instance: &str,
    setup_vk: &str,
    signing_key: &str,
    endpoint: &str,
    seed: &str,
    keyshare: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();

    let (share, _) =
        bincode::decode_from_slice(&keyshare.to_vec(), bincode::config::standard()).unwrap_throw();

    let instance = parse_instance_id(instance)?;
    let setup_vk = VerifyingKey::from_bytes(&parse_instance_bytes(setup_vk)?).unwrap_throw();
    let signing_key = SigningKey::from_bytes(&parse_instance_bytes(signing_key)?);
    let seed = parse_instance_bytes(seed)?;

    let ws = msg_relay_connect(endpoint).await?;
    let msg_relay = MsgRelay::new(ws);
    let mut msg_relay = BufferedMsgRelay::new(msg_relay);

    let msg_id = MsgId::new(&instance, setup_vk.as_bytes(), None, SETUP_MESSAGE_TAG);

    let mut setup_msg = msg_relay.recv(&msg_id, 10).await.unwrap_throw();

    let setup =
        sign::ValidatedSetup::decode(&mut setup_msg, &instance, &setup_vk, signing_key, |_, _| {
            Some(share)
        })
        .unwrap_throw();

    let sign = sign::run(setup, seed, msg_relay).await.unwrap_throw();

    Ok(Uint8Array::from(sign.to_der().as_bytes()))
}

#[wasm_bindgen(js_name = genInstanceId)]
pub fn gen_instance_id() -> Uint8Array {
    let bytes: [u8; 32] = rand::random();

    Uint8Array::from(bytes.as_slice())
}

#[wasm_bindgen(js_name = verifyingKey)]
pub fn verying_key(sk: Vec<u8>) -> Uint8Array {
    let sk = sk.try_into().expect_throw("invalid SK size");
    let sk = SigningKey::from_bytes(&sk);

    Uint8Array::from(sk.verifying_key().as_bytes().as_slice())
}

#[derive(Serialize, Deserialize)]
pub struct PartyDefs {
    pub rank: Option<u8>,

    #[serde(with = "serde_bytes")]
    pub public_key: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct KeygenSetupOpts {
    #[serde(with = "serde_bytes")]
    instance: Vec<u8>,

    #[serde(with = "serde_bytes")]
    signing_key: Vec<u8>,

    parties: Vec<PartyDefs>,

    threshold: u8,

    ttl: u32,
}

#[wasm_bindgen(js_name = createMsgId)]
pub fn create_msg_id(
    instance: &str,
    sender_pk: &str,
    receiver_pk: Option<String>,
    tag: u32,
) -> Result<Uint8Array, JsValue> {
    let instance = parse_instance_id(instance)?;

    let sender_pk =
        <[u8; 32]>::from_hex(sender_pk).map_err(|_| JsValue::from_str("cant parse hex"))?;

    let receiver_pk = match receiver_pk {
        None => None,
        Some(pk) => {
            Some(<[u8; 32]>::from_hex(pk).map_err(|_| JsValue::from_str("cant parse hex"))?)
        }
    };

    let tag = MessageTag::tag(tag as _);

    let msg_id = MsgId::new(&instance, &sender_pk, receiver_pk.as_ref(), tag);

    Ok(Uint8Array::from(msg_id.borrow()))
}

#[wasm_bindgen(js_name = dkgSetupMessage)]
pub fn dkg_setup_msg(opts: JsValue) -> Result<Uint8Array, JsValue> {
    let opts: KeygenSetupOpts = serde_wasm_bindgen::from_value(opts)?;

    let instance: [u8; 32] = opts
        .instance
        .try_into()
        .expect_throw("bad opts.instance size");
    let instance = InstanceId::from(instance);

    let sk = SigningKey::from_bytes(&opts.signing_key.try_into().expect_throw("SK size"));

    let msg_id = MsgId::new(
        &instance,
        sk.verifying_key().as_bytes(),
        None,
        setup::SETUP_MESSAGE_TAG,
    );

    let mut builder = setup::keygen::SetupBuilder::new();

    for party in opts.parties {
        let rank = party.rank.unwrap_or(0);
        let vk = party.public_key;
        let vk = VerifyingKey::from_bytes(&vk.try_into().expect_throw("party PK size"))
            .expect_throw("party PK");
        builder = builder.add_party(rank, &vk);
    }

    let msg = builder
        .build(&msg_id, opts.ttl, opts.threshold, &sk)
        .ok_or_else(|| JsValue::from_str("cant build DKG setup message"))?;

    Ok(Uint8Array::from(msg.as_ref()))
}

#[derive(Serialize, Deserialize)]
pub struct PartyVerifyingKey {
    #[serde(with = "serde_bytes")]
    pub public_key: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct SignSetupOpts {
    #[serde(with = "serde_bytes")]
    instance: Vec<u8>,

    #[serde(with = "serde_bytes")]
    signing_key: Vec<u8>,

    #[serde(with = "serde_bytes")]
    public_key: Vec<u8>,

    parties: Vec<PartyVerifyingKey>,

    #[serde(with = "serde_bytes")]
    message: Vec<u8>,

    ttl: u32,
}

#[wasm_bindgen(js_name = dsgSetupMessage)]
pub fn dsg_setup_msg(opts: JsValue) -> Result<Uint8Array, JsValue> {
    let opts: SignSetupOpts = serde_wasm_bindgen::from_value(opts)?;

    let instance: [u8; 32] = opts
        .instance
        .try_into()
        .expect_throw("bad opts.instance size");
    let instance = InstanceId::from(instance);

    let sk = SigningKey::from_bytes(&opts.signing_key.try_into().expect_throw("SK size"));

    let msg_id = MsgId::new(
        &instance,
        sk.verifying_key().as_bytes(),
        None,
        setup::SETUP_MESSAGE_TAG,
    );

    let public_key = GenericArray::from_slice(&opts.public_key);
    let public_key = AffinePoint::from_bytes(public_key);

    if public_key.is_none().into() {
        return Err(JsValue::from_str("Invalid puiblic key"));
    }

    let mut builder = setup::sign::SetupBuilder::new(&public_key.unwrap());

    for party in opts.parties {
        let vk = party.public_key.try_into().expect_throw("party PK size");
        builder = builder.add_party(VerifyingKey::from_bytes(&vk).expect_throw("party PK"));
    }

    let msg = builder
        .with_sha256(opts.message)
        .build(&msg_id, opts.ttl, &sk)
        .ok_or_else(|| JsValue::from_str("cant build DSG setup message"))?;

    Ok(Uint8Array::from(msg.as_ref()))
}
