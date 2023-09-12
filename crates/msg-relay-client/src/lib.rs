use std::sync::Arc;

use futures_util::{
    stream::{SplitSink, StreamExt},
    SinkExt,
};
use url::Url;

use tokio::{
    net::TcpStream,
    sync::{oneshot, watch, Mutex},
};
use tokio_tungstenite::{
    connect_async, tungstenite::Message as WsMessage, MaybeTlsStream, WebSocketStream,
};

use sl_mpc_mate::{
    coord::{BoxedRecv, BoxedRelay, BoxedSend, Relay},
    message::*,
};

type WS = WebSocketStream<MaybeTlsStream<TcpStream>>;

struct Inner {
    sender: Mutex<SplitSink<WS, WsMessage>>,
    queue: Mutex<Vec<(MsgId, oneshot::Sender<Vec<u8>>)>>,
    closed: watch::Sender<bool>,
}

impl Inner {
    async fn send(&self, msg: Vec<u8>) {
        let _ = self.sender.lock().await.send(WsMessage::Binary(msg)).await;
    }
}

#[derive(Clone)]
pub struct MsgRelayClient {
    inner: Arc<Inner>,
}

impl MsgRelayClient {
    pub async fn connect(endpoint: &Url) -> anyhow::Result<Self> {
        tracing::info!("connecting to {}", endpoint);

        let (ws, _) = connect_async(endpoint).await?;

        let (sender, mut receiver) = ws.split();

        let (tx_close, mut rx_close) = watch::channel(false);

        let inner = Arc::new(Inner {
            sender: Mutex::new(sender),
            queue: Mutex::new(vec![]),
            closed: tx_close,
        });

        let tx_inner = inner.clone();

        // task to pump messages from the WS connection
        // and dispatch to a receivers.
        tokio::spawn(async move {
            while let Some(msg) = tokio::select! {
                msg = receiver.next() => msg,
                _closed = rx_close.changed() => return
            } {
                let msg = match msg {
                    Err(_) => return,
                    Ok(msg) => msg,
                };

                match msg {
                    WsMessage::Binary(mut data) => {
                        let in_id = if let Ok(msg) = Message::from_buffer(&mut data) {
                            msg.id()
                        } else {
                            continue;
                        };

                        let mut queue = tx_inner.queue.lock().await;
                        let pos = queue.iter().position(|(id, _)| id.eq(&in_id));

                        if let Some(pos) = pos {
                            let (_, tx) = queue.swap_remove(pos);
                            // Ignore send error. Drop the message
                            // if no one is waiting for it.
                            let _ = tx.send(data);
                        } else {
                            // Drop the message, no one is waiting for.
                            continue;
                        }
                    }

                    // TODO handle Ping messages?
                    _ => {}
                }
            }
        });

        Ok(Self { inner })
    }

    pub fn send(&self, msg: Vec<u8>) -> BoxedSend {
        let inner = self.inner.clone();

        Box::pin(async move {
            inner.send(msg).await;
        })
    }

    pub fn recv(&self, id: MsgId, ttl: u32) -> BoxedRecv {
        let msg = AskMsg::allocate(&id, ttl);

        let (tx, rx) = oneshot::channel();

        let inner = self.inner.clone();

        Box::pin(async move {
            // register itself as a waiter for the message
            inner.queue.lock().await.push((id, tx));

            // send an ASK message
            inner.send(msg).await;

            // wait for the message
            let msg = rx.await.ok()?;

            Some(msg)
        })
    }

    pub fn close(&self) {
        let _ = self.inner.closed.send(true);
    }
}

impl Relay for MsgRelayClient {
    fn send(&self, msg: Vec<u8>) -> BoxedSend {
        self.send(msg)
    }

    fn recv(&self, id: MsgId, ttl: u32) -> BoxedRecv {
        self.recv(id, ttl)
    }

    fn clone_relay(&self) -> BoxedRelay {
        Box::new(self.clone())
    }
}
