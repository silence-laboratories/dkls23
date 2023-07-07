use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use tokio::task;
use url::Url;

use sl_mpc_mate::traits::{PersistentObject, Round};

pub struct Coordinator {
    client: reqwest::Client,
    base: Url,
    sid: String,
    rounds: u8,

    pub total_send: usize,
    pub total_recv: usize,
    pub total_wait: Duration,
}

#[derive(Serialize)]
pub struct RegReq {
    rounds: u8,
    parties: u8,
    lifetime: Option<u32>,
    message: Option<String>,
}

#[derive(Deserialize)]
pub struct RegResp {
    ids: Vec<String>,
}

#[derive(Deserialize)]
struct SendResp {
    id: u8,
}

#[derive(Deserialize)]
pub struct SessionConfig {
    pub parties: u8,
    pub rounds: u8,
    pub remains: usize,
    pub signmsg: Option<String>,
}

impl Coordinator {
    pub fn new(base: Url, sid: &str, rounds: u8, client: Option<&reqwest::Client>) -> Self {
        Self {
            base,
            sid: sid.into(),
            rounds,
            client: client.cloned().unwrap_or_else(reqwest::Client::new),
            total_send: 0,
            total_recv: 0,
            total_wait: Duration::from_secs(0),
        }
    }

    pub fn session_id(&self) -> &str {
        &self.sid
    }

    pub async fn session_config(&self) -> anyhow::Result<SessionConfig> {
        let config_url = format!("/v1/config/{}", self.sid);

        let resp = self
            .client
            .post(self.base.join(&config_url)?)
            .send()
            .await?;

        if resp.status() != reqwest::StatusCode::OK {
            anyhow::bail!("session not found");
        }

        let resp = resp.json::<SessionConfig>().await?;

        Ok(resp)
    }

    pub async fn send(&mut self, msg: Vec<u8>, round: u8) -> anyhow::Result<u8> {
        let start = Instant::now();
        self.total_send += msg.len();

        let send_url = format!("/v1/send/{}/{}", self.sid, round);

        let resp = self
            .client
            .post(self.base.join(&send_url)?)
            .body(msg)
            .send()
            .await?;

        if resp.status() != reqwest::StatusCode::OK {
            anyhow::bail!("session not found");
        }

        let resp = resp.json::<SendResp>().await?;

        self.total_wait += Instant::now().duration_since(start);

        Ok(resp.id)
    }

    pub async fn recv(&mut self, round: u8, wait: bool) -> anyhow::Result<Vec<u8>> {
        let start = Instant::now();

        let round = if wait { round + self.rounds } else { round };
        let recv_url = format!("/v1/recv/{}/{}", self.sid, round);

        let resp = self.client.post(self.base.join(&recv_url)?).send().await?;

        if resp.status() != reqwest::StatusCode::OK {
            anyhow::bail!("session not found");
        }

        let resp = resp.bytes().await?;

        self.total_wait += Instant::now().duration_since(start);
        self.total_recv += resp.len();

        Ok(resp.into())
    }
}

impl Coordinator {
    pub async fn register(
        base_url: url::Url,
        parties: u8,
        rounds: u8,
        lifetime: Option<u32>,
        signmsg: Option<String>,
    ) -> anyhow::Result<Vec<String>> {
        let body = RegReq {
            rounds,
            parties,
            lifetime,
            message: signmsg,
        };

        let client = reqwest::Client::new();

        let ids = client
            .post(base_url.join("/v1/create")?)
            .json(&body)
            .send()
            .await?
            .json::<RegResp>()
            .await?;

        Ok(ids.ids)
    }
}

impl Coordinator {
    /// Execute one round of DKG protocol
    pub async fn run_round<I, N, R, M, E>(
        &mut self,
        actor: R,
        round: u8,
        do_send: bool,
    ) -> anyhow::Result<N>
    where
        R: Round<Input = Vec<I>, Output = std::result::Result<(N, M), E>>,
        I: PersistentObject + Clone,
        M: PersistentObject,
        E: std::error::Error + Send + Sync + 'static,
    {
        let batch = self.recv(round, true).await?;

        let batch = I::decode_batch(&batch).unwrap();

        let (next, msg) = task::block_in_place(|| actor.process(batch))?;

        let msg = msg.to_bytes().unwrap();

        if do_send {
            self.send(msg, round + 1).await?;
        }

        Ok(next)
    }
}
