use std::borrow::Cow;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

// use k256::elliptic_curve::group::GroupEncoding;

use tokio::task::JoinSet;

use axum::{
    error_handling::HandleErrorLayer,
    extract::{Json, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Router,
};

// use url::Url;

use tower::{BoxError, ServiceBuilder};
use tower_http::{cors::CorsLayer, trace::TraceLayer};

use serde::{Deserialize, Serialize};

// use dkls23::keygen::Keyshare;

// use crate::coord;
use crate::flags;
// use crate::keygen::keygen_party;
// use crate::SignHashFn;

// use crate::sign::sign_party;

mod b64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<T, S>(key: T, serializer: S) -> Result<S::Ok, S::Error>
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
        let v = base64::decode(<&str>::deserialize(d)?).map_err(serde::de::Error::custom)?;

        Ok(v)
    }
}

#[derive(Clone)]
struct AppState {
    client: reqwest::Client,
}

impl AppState {
    fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct KeygenParams {
    coord: String,
    session: String,

    n: u8,
    t: u8,
    rank: u8,

    #[serde(with = "b64")]
    party_keys: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
struct KeygenResponse {
    #[serde(with = "b64")]
    keyshare: Vec<u8>,

    #[serde(with = "b64")]
    public_key: Vec<u8>,

    total_send: u32,
    total_recv: u32,
    total_wait: u32,
    total_time: u32, // execution time in milliseconds
}

#[derive(Serialize, Deserialize, Debug)]
struct SignParams {
    coord: String,
    session: String,
    hash_fn: String,

    #[serde(with = "b64")]
    keyshare: Vec<u8>,
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
    State(_state): State<AppState>,
    Json(_payload): Json<KeygenParams>,
) -> Result<Json<KeygenResponse>, StatusCode> {
    let _start = Instant::now();

    // let keys = PartyKeys::from_bytes(&payload.party_keys).ok_or(StatusCode::BAD_REQUEST)?;

    // let mut c = coord::Coordinator::new(
    //     Url::parse(&payload.coord).map_err(|_| StatusCode::BAD_REQUEST)?,
    //     &payload.session,
    //     6 + 1,
    //     Some(&state.client),
    // );

    // let keyshare = keygen_party(&mut c, keys, payload.t, payload.n, payload.rank)
    //     .await
    //     .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // let total_time = Instant::now().duration_since(start).as_millis() as u32;

    // let resp = Json(KeygenResponse {
    //     keyshare: keyshare.to_bytes().unwrap(),
    //     total_send: c.total_send as u32,
    //     total_recv: c.total_recv as u32,
    //     total_wait: c.total_wait.as_millis() as u32,
    //     public_key: keyshare.public_key.to_affine().to_bytes().to_vec(),
    //     total_time,
    // });

    // Ok(resp)

    todo!()
}

async fn handle_sign(
    State(_state): State<AppState>,
    Json(_payload): Json<SignParams>,
) -> Result<Json<SignResponse>, StatusCode> {
    let start = Instant::now();

    // let keyshare = Keyshare::from_bytes(&payload.keyshare).ok_or(StatusCode::BAD_REQUEST)?;

    // let hash_fn: SignHashFn = payload
    //     .hash_fn
    //     .parse()
    //     .map_err(|_| StatusCode::BAD_REQUEST)?;

    // let mut c = coord::Coordinator::new(
    //     Url::parse(&payload.coord).map_err(|_| StatusCode::BAD_REQUEST)?,
    //     &payload.session,
    //     5,
    //     Some(&state.client),
    // );

    // let (sign, times) = sign_party(&mut c, keyshare, hash_fn)
    //     .await
    //     .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let total_time = Instant::now().duration_since(start).as_millis() as u32;

    let sign = vec![];

    Ok(Json(SignResponse {
        sign,
        total_send: 0, //c.total_send as u32,
        total_recv: 0, // c.total_recv as u32,
        total_wait: 0, //c.total_wait.as_millis() as u32,
        total_time,
        times: None,
    }))
}

async fn handle_party_keys() -> String {
    // let mut rng = rand::thread_rng();
    // base64::ecnode(PartyKeys::new(&mut rng).to_bytes().unwrap());

    todo!()
}

fn app(state: Option<AppState>) -> Router {
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
        .with_state(state.unwrap_or_else(|| AppState::new()))
}

pub async fn run(opts: flags::Serve) -> anyhow::Result<()> {
    let app = app(None);

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

        servers.spawn(axum::Server::bind(&addr).serve(app.clone().into_make_service()));
    }

    while let Some(_) = servers.join_next().await {}

    Ok(())
}

async fn health_check() -> &'static str {
    "ok"
}

async fn handle_error(error: BoxError) -> impl IntoResponse {
    if error.is::<tower::timeout::error::Elapsed>() {
        return (StatusCode::REQUEST_TIMEOUT, Cow::from("request timed out"));
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
