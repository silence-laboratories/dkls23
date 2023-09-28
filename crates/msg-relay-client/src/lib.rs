use std::pin::Pin;
use std::task::{Context, Poll};

use futures_util::FutureExt;
use futures_util::{stream::StreamExt, Sink, SinkExt, Stream};
use url::Url;

use tokio::net::TcpStream;
use tokio_tungstenite::{
    connect_async, tungstenite::Message as WsMessage, MaybeTlsStream, WebSocketStream,
};

use sl_mpc_mate::message::*;

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
