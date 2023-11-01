use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;

use js_sys::{Promise, Uint8Array};
use web_sys::AbortSignal;

use sl_mpc_mate::{coord::*, message::*};

#[wasm_bindgen(module = "/js/msg-relay.js")]
extern "C" {
    pub type MsgRelayClient;

    #[wasm_bindgen(js_namespace = MsgRelayClient)]
    pub fn connect(endpoint: &str, singal: AbortSignal) -> Promise;

    #[wasm_bindgen(method, js_class = "MsgRelayClient")]
    pub fn send(this: &MsgRelayClient, msg: Uint8Array);

    #[wasm_bindgen(method, js_class = "MsgRelayClient")]
    pub fn next(this: &MsgRelayClient) -> Promise;

    #[wasm_bindgen(method, js_class = "MsgRelayClient")]
    pub fn close(this: &MsgRelayClient) -> Promise;

    #[wasm_bindgen(method, js_class = "MsgRelayClient")]
    pub fn wsClose(this: &MsgRelayClient);
}

#[wasm_bindgen]
pub async fn msg_relay_connect(
    endpoint: &str,
    singal: AbortSignal,
) -> Result<MsgRelayClient, JsError> {
    let client: MsgRelayClient = JsFuture::from(MsgRelayClient::connect(endpoint, singal))
        .await
        .expect_throw("connect error")
        .dyn_into()
        .expect_throw("expect MsgRelayClient");

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

impl Drop for MsgRelay {
    fn drop(&mut self) {
        self.ws.wsClose();
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
