use std::borrow::Cow;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::task::JoinSet;

use axum::{
    error_handling::HandleErrorLayer,
    extract::{Json, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use url::Url;

use tower::{BoxError, ServiceBuilder};
use tower_http::{cors::CorsLayer, trace::TraceLayer};

use k256::elliptic_curve::group::GroupEncoding;

use serde::{Deserialize, Serialize};

use dkls23::{
    keygen,
    setup::{self, SETUP_MESSAGE_TAG},
    sign,
};
use sl_mpc_mate::{bincode, coord::*, message::*};

use msg_relay_client::MsgRelayClient;

use crate::{default_coord, flags, utils::*};

mod b64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<T, S>(
        key: T,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        T: AsRef<[u8]>,
        S: Serializer,
    {
        serializer.serialize_str(&base64::encode(key))
    }

    pub fn deserialize<'de, D>(d: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let v = base64::decode(<&str>::deserialize(d)?)
            .map_err(serde::de::Error::custom)?;

        Ok(v)
    }
}

type AppState = Arc<Inner>;

struct Inner {
    coord: Url,
    setup_vk: VerifyingKey,
    party_key: SigningKey,
    shares: Mutex<Vec<keygen::Keyshare>>,
    storage: PathBuf,
}

impl Inner {
    fn new(
        setup_vk: VerifyingKey,
        party_key: SigningKey,
        coord: Url,
        storage: PathBuf,
    ) -> Self {
        Self {
            coord,
            setup_vk,
            party_key,
            storage,
            shares: Mutex::new(vec![]),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct KeygenParams {
    #[serde(with = "b64")]
    instance: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
struct KeygenResponse {
    #[serde(with = "b64")]
    public_key: Vec<u8>,

    total_send: u32,
    total_recv: u32,
    total_wait: u32,
    total_time: u32, // execution time in milliseconds
}

#[derive(Serialize, Deserialize, Debug)]
struct SignParams {
    #[serde(with = "b64")]
    instance: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
struct SignResponse {
    #[serde(with = "b64")]
    sign: Vec<u8>,

    total_send: u32,
    total_recv: u32,
    total_wait: u32,
    total_time: u32, // execution time in milliseconds
    times: Option<Vec<(u32, Duration)>>,
}

async fn handle_keygen(
    State(state): State<AppState>,
    Json(payload): Json<KeygenParams>,
) -> Result<Json<KeygenResponse>, StatusCode> {
    let start = Instant::now();

    let instance: [u8; 32] = payload
        .instance
        .try_into()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let instance = InstanceId::from(instance);

    let msg_relay = MsgRelayClient::connect(&state.coord)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let relay_stats = RelayStats::new(Box::new(msg_relay));

    let msg_id = MsgId::new(
        &instance,
        state.setup_vk.as_bytes(),
        None,
        SETUP_MESSAGE_TAG,
    );

    let mut setup = relay_stats
        .recv(msg_id, 10)
        .await
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

    let setup = setup::keygen::ValidatedSetup::decode(
        &mut setup,
        &instance,
        &state.setup_vk,
        state.party_key.clone(),
        |_, _, _| true,
    )
    .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

    let seed = rand::random();

    let share = keygen::run(setup, seed, relay_stats.clone_relay())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let total_time = start.elapsed().as_millis() as u32;

    let stats = relay_stats.stats();

    let pk_vec = share.public_key.to_affine().to_bytes().to_vec();
    let pk_hex = hex::encode(&pk_vec);

    let share =
        bincode::encode_to_vec(&share, bincode::config::standard())
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let keyshare_file =
        state.storage.join(format!("{}.keyshare", pk_hex));

    std::fs::write(keyshare_file, share)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let resp = Json(KeygenResponse {
        total_send: stats.send_size as u32,
        total_recv: stats.recv_size as u32,
        total_wait: stats.wait_time.as_millis() as u32,
        public_key: pk_vec,
        total_time,
    });

    Ok(resp)
}

async fn handle_sign(
    State(state): State<AppState>,
    Json(payload): Json<SignParams>,
) -> Result<Json<SignResponse>, StatusCode> {
    let start = Instant::now();

    let instance: [u8; 32] = payload
        .instance
        .try_into()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let instance = InstanceId::from(instance);

    let msg_relay = MsgRelayClient::connect(&state.coord)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let msg_id = MsgId::new(
        &instance,
        state.setup_vk.as_bytes(),
        None,
        SETUP_MESSAGE_TAG,
    );

    let relay_stats = RelayStats::new(Box::new(msg_relay));

    let mut setup = relay_stats
        .recv(msg_id, 10)
        .await
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

    let setup = setup::sign::ValidatedSetup::decode(
        &mut setup,
        &instance,
        &state.setup_vk,
        state.party_key.clone(),
        |setup, _| {
            let pk = hex::encode(&setup.public_key().to_bytes());
            let path = state.storage.join(format!("{}.keyshare", &pk));

            let bytes = std::fs::read(path).ok()?;

            let (share, _) = bincode::decode_from_slice(
                &bytes,
                bincode::config::standard(),
            )
            .ok()?;

            Some(share)
        },
    )
    .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

    let seed = rand::random();

    let sign = sign::run(setup, seed, relay_stats.clone_relay())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let total_time = start.elapsed().as_millis() as u32;

    let sign = sign.to_der().to_bytes().to_vec();

    let stats = relay_stats.stats();

    Ok(Json(SignResponse {
        sign,
        total_send: stats.send_size as u32,
        total_recv: stats.recv_size as u32,
        total_wait: stats.wait_time.as_millis() as u32,
        total_time,
        times: None,
    }))
}

async fn handle_party_keys() -> &'static str {
    "ok"
}

fn app(state: AppState) -> Router {
    Router::new()
        .route("/", get(health_check))
        .route("/v1/party-keys", post(handle_party_keys))
        .route("/v1/keygen", post(handle_keygen))
        .route("/v1/signgen", post(handle_sign))
        .layer(CorsLayer::permissive())
        .layer(
            ServiceBuilder::new()
                // Handle errors from middleware
                .layer(HandleErrorLayer::new(handle_error))
                .load_shed()
                .concurrency_limit(1024)
                .timeout(Duration::from_secs(500)) // 60
                .layer(TraceLayer::new_for_http()),
        )
        .with_state(state)
}

pub async fn run(opts: flags::Serve) -> anyhow::Result<()> {
    let setup_vk = parse_verifying_key(&opts.setup_vk)?;
    let party_key = load_signing_key(opts.party_key)?;
    let coord = opts.coordinator.unwrap_or_else(default_coord);

    let state =
        Arc::new(Inner::new(setup_vk, party_key, coord, opts.storage));
    let app = app(state);

    let listen = {
        if opts.listen.len() > 0 {
            opts.listen
        } else {
            vec![format!(
                "{}:{}",
                opts.host.unwrap_or(String::from("0.0.0.0")),
                opts.port.unwrap_or(8080)
            )]
        }
    };

    let mut servers = JoinSet::new();

    for addr in &listen {
        let addr: SocketAddr = addr.parse()?;

        tracing::info!("listening on {}", addr);

        servers.spawn(
            axum::Server::bind(&addr)
                .serve(app.clone().into_make_service()),
        );
    }

    while servers.join_next().await.is_some() {}

    Ok(())
}

async fn health_check() -> &'static str {
    "ok"
}

async fn handle_error(error: BoxError) -> impl IntoResponse {
    if error.is::<tower::timeout::error::Elapsed>() {
        return (
            StatusCode::REQUEST_TIMEOUT,
            Cow::from("request timed out"),
        );
    }

    if error.is::<tower::load_shed::error::Overloaded>() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Cow::from("service is overloaded, try again later"),
        );
    }

    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Cow::from(format!("Unhandled internal error: {error}")),
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn keygen_params() {}
}
