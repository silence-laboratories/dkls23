use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Instant;

use futures_util::FutureExt;
use futures_util::{stream::StreamExt, Sink, SinkExt, Stream};
use url::Url;

use tokio::{net::TcpStream, sync::mpsc};
use tokio_tungstenite::{
    connect_async, tungstenite::Message as WsMessage, MaybeTlsStream, WebSocketStream,
};

use sl_mpc_mate::{coord::*, message::*};

type WS = WebSocketStream<MaybeTlsStream<TcpStream>>;

pub struct MsgRelayClient {
    ws: WS,
}

impl MsgRelayClient {
    pub async fn connect(endpoint: &Url) -> anyhow::Result<Self> {
        tracing::info!("connecting to {}", endpoint);

        let (ws, _) = connect_async(endpoint).await?;

        Ok(Self { ws })
    }
}

impl Stream for MsgRelayClient {
    type Item = Vec<u8>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            match self.ws.poll_next_unpin(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Ready(Some(Err(_err))) => return Poll::Ready(None),

                Poll::Ready(Some(Ok(WsMessage::Binary(msg)))) => return Poll::Ready(Some(msg)),

                Poll::Ready(Some(Ok(WsMessage::Ping(m)))) => {
                    match self.ws.send(WsMessage::Pong(m)).poll_unpin(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(_) => {}
                    }
                }

                Poll::Ready(Some(Ok(WsMessage::Close(_)))) => return Poll::Ready(None),

                Poll::Ready(Some(Ok(_))) => {}
            }
        }
    }
}

impl Sink<Vec<u8>> for MsgRelayClient {
    type Error = InvalidMessage;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.ws
            .poll_ready_unpin(cx)
            .map_err(|_| InvalidMessage::SendError)
    }

    fn start_send(mut self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
        self.ws
            .start_send_unpin(WsMessage::Binary(item))
            .map_err(|_| InvalidMessage::SendError)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.ws
            .poll_flush_unpin(cx)
            .map_err(|_| InvalidMessage::SendError)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.ws
            .poll_close_unpin(cx)
            .map_err(|_| InvalidMessage::SendError)
    }
}

struct DistatchTable {
    id_map: HashMap<MsgId, (Instant, mpsc::Sender<Vec<u8>>)>,
}

pub struct MsgRelayMux {
    tx: mpsc::Sender<Vec<u8>>,
    tbl: Arc<Mutex<DistatchTable>>,
}

pub struct MsgRelayMuxConn {
    tx: mpsc::Sender<Vec<u8>>,
    in_tx: mpsc::Sender<Vec<u8>>,
    in_rx: mpsc::Receiver<Vec<u8>>,
    out_buf: Vec<Pin<Box<dyn Future<Output = ()> + Send + 'static>>>,
    tbl: Arc<Mutex<DistatchTable>>,
}

impl MsgRelayMux {
    pub fn new<R: Relay + Send + 'static>(mut relay: R, output_buffer_size: usize) -> Self {
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(output_buffer_size);

        let tbl = Arc::new(Mutex::new(DistatchTable {
            id_map: HashMap::new(),
        }));

        let in_tbl = tbl.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    msg = rx.recv() => {
                        if let Some(msg) = msg {
                            let _ = relay.send(msg).await;
                        } else {
                            return;
                        }
                    }

                    msg = relay.next() => {
                        if let Some(msg) = msg {
                            if let Some(hdr) = MsgHdr::from(&msg) {
                                if let Some((_, tx)) = {
                                    let mut tbl = in_tbl.lock().unwrap();
                                    let ent = tbl.id_map.remove(&hdr.id);

                                    // make sure we do not hold tbl
                                    // across await point
                                    drop(tbl);

                                    ent
                                } {
                                    let _ = tx.send(msg).await;
                                }
                            } else {
                                // skip invalid message
                                continue;
                            }
                        } else {
                            // end of input stream,  exit
                            return;
                        }
                    }
                };
            }
        });

        Self { tx, tbl }
    }

    pub fn connect(&self, input_buffer_size: usize) -> MsgRelayMuxConn {
        let (in_tx, in_rx) = mpsc::channel(input_buffer_size);

        MsgRelayMuxConn {
            in_tx,
            in_rx,
            tx: self.tx.clone(),
            out_buf: vec![],
            tbl: self.tbl.clone(),
        }
    }
}

impl MsgRelayMuxConn {
    fn flush_output(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), InvalidMessage>> {
        while let Some(mut fut) = self.out_buf.pop() {
            if fut.poll_unpin(cx).is_pending() {
                self.out_buf.push(fut);
                return Poll::Pending;
            }
        }

        Poll::Ready(Ok(()))
    }
}

impl Sink<Vec<u8>> for MsgRelayMuxConn {
    type Error = InvalidMessage;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.flush_output(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
        if let Some(hdr) = MsgHdr::from(&item) {
            if hdr.kind == Kind::Ask {
                let expire = Instant::now() + hdr.ttl;

                let mut tbl = self.tbl.lock().unwrap();

                tbl.id_map.insert(hdr.id, (expire, self.in_tx.clone()));
            }

            let tx = self.tx.clone();
            self.out_buf.push(Box::pin(async move {
                let _ = tx.send(item).await;
            }));
        }

        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.flush_output(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.flush_output(cx)
    }
}

impl Stream for MsgRelayMuxConn {
    type Item = Vec<u8>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.in_rx.poll_recv(cx)
    }
}

#[cfg(test)]
mod test {

    use std::time::Duration;

    use super::*;

    fn mk_msg(id: &MsgId, sk: &SigningKey) -> Vec<u8> {
        Builder::<Signed>::encode(id, Duration::new(10, 0), sk, &(0u32, 255u64)).unwrap()
    }

    // (flavor = "multi_thread")
    #[tokio::test(flavor = "multi_thread")]
    async fn mux() {
        let sk = SigningKey::from_bytes(&rand::random());
        let instance = InstanceId::from(rand::random::<[u8; 32]>());

        let s = SimpleMessageRelay::new();

        let c1 = s.connect();
        let mut c2 = s.connect();

        let c1 = MsgRelayMux::new(c1, 10);

        let mut m1 = c1.connect(10);
        let mut m2 = c1.connect(10);

        let msg_0_id = MsgId::new(
            &instance,
            &sk.verifying_key().as_bytes(),
            None,
            MessageTag::tag(0),
        );
        let msg_0 = mk_msg(&msg_0_id, &sk);

        // request a msg_0 on m1
        m1.send(AskMsg::allocate(&msg_0_id, 10)).await.unwrap();

        // c2 -> s -> c1 -> m1
        c2.send(msg_0.clone()).await.unwrap();

        let msg_0_in = m1.next().await.unwrap();

        assert_eq!(msg_0, msg_0_in);

        let msg_1_id = MsgId::new(
            &instance,
            &sk.verifying_key().as_bytes(),
            None,
            MessageTag::tag(1),
        );
        let msg_1 = mk_msg(&msg_1_id, &sk);

        // m2 -> c1 -> s -> c2
        m2.send(msg_1.clone()).await.unwrap();

        // request msg_1
        c2.send(AskMsg::allocate(&msg_1_id, 10)).await.unwrap();
        // recv msg_1
        let msg_1_in = c2.next().await.unwrap();

        assert_eq!(msg_1, msg_1_in);

    }
}
