use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use k256::{
    elliptic_curve::group::GroupEncoding, AffinePoint, CompressedPoint,
};

use std::path::PathBuf;

use hex::FromHex;

use sl_mpc_mate::{coord::*, message::*};

pub fn parse_instance_id(s: &str) -> anyhow::Result<InstanceId> {
    Ok(InstanceId::from(<[u8; 32]>::from_hex(s)?))
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
    Ok(VerifyingKey::from_bytes(&<[u8; 32]>::from_hex(s)?)?)
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

#[derive(Default, Clone)]
pub struct Stats {
    pub send_count: usize,
    pub send_size: usize,
    pub recv_size: usize,
    pub recv_count: usize,
    pub wait_time: Duration,
}

pub struct RelayStats {
    relay: BoxedRelay,
    stats: Arc<Mutex<Stats>>,
}

impl RelayStats {
    pub fn new(relay: BoxedRelay) -> Box<RelayStats> {
        Box::new(RelayStats {
            relay,
            stats: Arc::new(Mutex::new(Stats::default())),
        })
    }

    pub fn stats(&self) -> Stats {
        self.stats.lock().unwrap().clone()
    }
}

impl Relay for RelayStats {
    fn send(&self, msg: Vec<u8>) -> BoxedSend {
        let mut stats = self.stats.lock().unwrap();
        stats.send_size += msg.len();
        stats.send_count += 1;

        self.relay.send(msg)
    }

    fn recv(&self, id: MsgId, ttl: u32) -> BoxedRecv {
        let recv = self.relay.recv(id, ttl);
        let stats = self.stats.clone();

        Box::pin(async move {
            let start = Instant::now();
            let msg = recv.await;

            let wait_time = start.elapsed();

            if let Some(msg) = &msg {
                let mut stats = stats.lock().unwrap();
                stats.recv_size += msg.len();
                stats.recv_count += 1;
                stats.wait_time += wait_time;
            };

            msg
        })
    }

    fn clone_relay(&self) -> BoxedRelay {
        Box::new(RelayStats {
            relay: self.relay.clone_relay(),
            stats: self.stats.clone(),
        })
    }
}
