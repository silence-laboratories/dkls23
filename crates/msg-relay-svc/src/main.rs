use std::env;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tokio::task::JoinSet;

use axum::{routing::get, Router};

use tower_http::{cors::CorsLayer, trace::TraceLayer};

use msg_relay::AppStateInner;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut servers = JoinSet::new();

    let app = Router::new()
        .route("/v1/msg-relay", get(msg_relay::handler))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(Arc::new(Mutex::new(AppStateInner::new())));

    for addr in env::var("LISTEN")
        .unwrap_or_else(|_| String::from("127.0.0.1:8080"))
        .split_whitespace()
    {
        let addr: SocketAddr = addr.parse()?;

        servers.spawn(
            axum::Server::bind(&addr)
                .serve(app.clone().into_make_service()),
        );
    }

    while let Some(_) = servers.join_next().await {}

    Ok(())
}
