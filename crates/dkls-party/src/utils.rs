use std::{
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use k256::{
    elliptic_curve::group::GroupEncoding, AffinePoint, CompressedPoint,
};

use std::path::PathBuf;

use hex::FromHex;

use sl_mpc_mate::{coord::*, message::*};

pub fn parse_instance_bytes(s: &str) -> anyhow::Result<[u8; 32]> {
    Ok(<[u8; 32]>::from_hex(s)?)
}

pub fn parse_instance_id(s: &str) -> anyhow::Result<InstanceId> {
    Ok(InstanceId::from(parse_instance_bytes(s)?))
}

pub fn parse_sign_message(s: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = <[u8; 32]>::from_hex(s)?;

    Ok(bytes)
}

pub fn load_signing_key(p: PathBuf) -> anyhow::Result<SigningKey> {
    let bytes = std::fs::read(p)?;
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
        anyhow::Error::msg("invalid length of signing key file")
    })?;

    Ok(SigningKey::from_bytes(&bytes))
}

/// Parse hex string into VerifyingKey
pub fn parse_verifying_key(s: &str) -> anyhow::Result<VerifyingKey> {
    tracing::info!("parse VK {:?}", s);
    Ok(VerifyingKey::from_bytes(&<[u8; 32]>::from_hex(s)?)?)
}

pub fn load_verifying_key(p: PathBuf) -> anyhow::Result<VerifyingKey> {
    let content = std::fs::read_to_string(p)?;

    Ok(VerifyingKey::from_bytes(&<[u8; 32]>::from_hex(
        content.trim(),
    )?)?)
}

pub fn parse_affine_point(s: &str) -> anyhow::Result<AffinePoint> {
    let bytes = CompressedPoint::from(<[u8; 33]>::from_hex(s)?);

    let pk = AffinePoint::from_bytes(&bytes);

    if bool::from(pk.is_some()) {
        Ok(pk.unwrap())
    } else {
        Err(anyhow::Error::msg("cant parse AffinePoint"))
    }
}

#[derive(Default, Clone, Debug)]
pub struct Stats {
    pub send_count: usize,
    pub send_size: usize,
    pub recv_size: usize,
    pub recv_count: usize,
    pub wait_time: Duration,
}

impl Stats {
    pub fn alloc() -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self::default()))
    }
}

pub struct RelayStats<R: Relay> {
    relay: R,
    stats: Arc<Mutex<Stats>>,
}

impl<R: Relay> RelayStats<R> {
    pub fn new(relay: R, stats: Arc<Mutex<Stats>>) -> Self {
        Self { relay, stats }
    }

    pub fn stats(&self) -> Stats {
        self.stats.lock().unwrap().clone()
    }
}

impl<R: Relay> Stream for RelayStats<R> {
    type Item = <R as Stream>::Item;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        match self.relay.poll_next_unpin(cx) {
            Poll::Ready(Some(msg)) => {
                let mut stats = self.stats.lock().unwrap();

                stats.recv_size += msg.len();
                stats.recv_count += 1;

                Poll::Ready(Some(msg))
            }

            r => r,
        }
    }
}

impl<R: Relay> Sink<Vec<u8>> for RelayStats<R> {
    type Error = <R as Sink<Vec<u8>>>::Error;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.relay.poll_ready_unpin(cx)
    }

    fn start_send(
        mut self: Pin<&mut Self>,
        item: Vec<u8>,
    ) -> Result<(), Self::Error> {

        let mut stats = self.stats.lock().unwrap();

        stats.send_size += item.len();
        stats.send_count += 1;
        drop(stats);

        self.relay.start_send_unpin(item)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.relay.poll_flush_unpin(cx)
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.relay.poll_close_unpin(cx)
    }
}
