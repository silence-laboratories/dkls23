use futures_util::stream::{SplitSink, StreamExt, SplitStream};

use futures_util::SinkExt;

use tokio::net::TcpStream;
use tokio_tungstenite::{connect_async, tungstenite::Message,  MaybeTlsStream, WebSocketStream};
use url::Url;

type WS = WebSocketStream<MaybeTlsStream<TcpStream>>;

#[allow(dead_code)]
pub struct MsgRelayClient {
    sink: SplitSink<WS, Message>,
    stream: SplitStream<WS>,
}

impl MsgRelayClient {
    pub async fn connect(endpoint: &Url) -> anyhow::Result<Self> {
        let (ws, _) = connect_async(endpoint).await?;

        let (sink, stream) = ws.split();

        Ok(Self { sink, stream })
    }

    pub async fn ask(&mut self, msg: Vec<u8>) -> anyhow::Result<()> {
        self.sink.send(Message::Binary(msg)).await?;
        Ok(())
    }

    pub fn publish(&mut self, _msg: &[u8]) {
        todo!()
    }

    pub async fn recv(&mut self) -> Vec<u8> {
        todo!()
    }
}
