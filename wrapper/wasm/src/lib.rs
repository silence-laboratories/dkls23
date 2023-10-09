use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use js_sys::{Promise, Uint8Array};
use utils::set_panic_hook;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;

use dkls23::{keygen, setup::SETUP_MESSAGE_TAG, sign};
use sl_mpc_mate::{bincode, coord::*, message::*};

mod utils;

use hex::FromHex;

// #[wasm_bindgen]
// extern "C" {
//     #[wasm_bindgen(js_namespace = console)]
//     fn log(s: &str);
// }

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

async fn msg_relay_connect(endpoint: &str) -> Result<MsgRelayClient, JsValue> {
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

                    Poll::Ready(Err(_)) => return Poll::Ready(None),

                    Poll::Ready(Ok(msg)) => {
                        let msg = match msg.dyn_into::<Uint8Array>() {
                            Ok(msg) => msg,
                            Err(_) => return Poll::Ready(None),
                        };

                        return Poll::Ready(Some(msg.to_vec()));
                    }
                }
            }

            this.next = Some(JsFuture::from(this.ws.next()));
        }
    }
}

impl Sink<Vec<u8>> for MsgRelay {
    type Error = InvalidMessage;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
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
    let setup_vk = VerifyingKey::from_bytes(&parse_instance_bytes(setup_vk)?).unwrap_throw();
    let signing_key = SigningKey::from_bytes(&parse_instance_bytes(signing_key)?);
    let seed = parse_instance_bytes(seed)?;

    let ws = msg_relay_connect(endpoint).await?;
    let msg_relay = MsgRelay::new(ws);
    let mut msg_relay = BufferedMsgRelay::new(msg_relay);

    let msg_id = MsgId::new(&instance, setup_vk.as_bytes(), None, SETUP_MESSAGE_TAG);

    let mut setup_msg = msg_relay.recv(&msg_id, 10).await.unwrap_throw();

    let setup = keygen::ValidatedSetup::decode(
        &mut setup_msg,
        &instance,
        &setup_vk,
        signing_key,
        |_, _, _| true,
    )
    .unwrap_throw();

    let keyshare = keygen::run(setup, seed, msg_relay).await.unwrap_throw();

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
