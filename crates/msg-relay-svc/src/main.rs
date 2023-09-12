use std::env;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context;
use tokio::{sync::broadcast, task::JoinSet};

use axum::{routing::get, Router};
use url::Url;

use futures_util::{stream::StreamExt, SinkExt};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tower_http::{cors::CorsLayer, trace::TraceLayer};

use msg_relay::{AppState, AppStateInner};

mod flags;
use flags::MsgRelaySvc;

async fn run_peer<F: FnMut(Vec<u8>) + Send + 'static>(
    peer: Url,
    mut queue: broadcast::Receiver<Vec<u8>>,
    state: AppState<F>,
) {
    loop {
        tracing::info!("connecting to {}", peer);

        let ws = loop {
            match connect_async(&peer).await {
                Ok((ws, _)) => break ws,

                Err(err) => {
                    tracing::error!("connection error {:?}", err);

                    // TODO make configurable
                    tokio::time::sleep(Duration::new(3, 0)).await;
                }
            }
        };

        let (mut sender, mut receiver) = ws.split();

        loop {
            tokio::select! {
                msg = queue.recv() => {
                    if let Ok(msg) = msg {
                        let _ = sender.send(Message::Binary(msg)).await;
                    }
                },

                msg = receiver.next() => {
                    if let Some(Ok(msg)) = msg {
                        match msg {
                            Message::Binary(msg) => {
                                if msg.len() > 32 + 4 {
                                    state.lock().unwrap().handle_message(msg, None);
                                }
                            },

                            Message::Ping(_) => {}

                            _ => {}
                        }
                    } else {
                        break; // reconnect
                    }
                }
            };
        }

        tracing::info!("close connection to {}", peer);
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let flags = MsgRelaySvc::from_env_or_exit();

    tracing_subscriber::fmt::init();

    let mut servers = JoinSet::new();

    let (queue, _recv) =
        broadcast::channel(flags.queue_size.unwrap_or(256));

    let state = Arc::new(Mutex::new(AppStateInner::new({
        let queue = queue.clone();
        move |msg| {
            let _ = queue.send(msg);
        }
    })));

    for peer in flags.peer.into_iter() {
        tokio::spawn(run_peer(peer, queue.subscribe(), state.clone()));
    }

    let app = Router::new()
        .route("/v1/msg-relay", get(msg_relay::handler))
        .route("/v1/msg-stats", get(msg_relay::stats))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let listen = {
        let mut listen = flags.listen;

        if let Ok(var) = env::var("LISTEN") {
            for addr in var.split(' ') {
                listen.push(
                    addr.parse()
                        .context("can't parse address in LISTEN")?,
                )
            }
        };

        if listen.is_empty() {
            vec!["127.0.0.1:8080".parse().unwrap()]
        } else {
            listen
        }
    };

    for addr in &listen {
        servers.spawn(
            axum::Server::bind(addr)
                .serve(app.clone().into_make_service()),
        );

        tracing::info!("listen on {:?}", addr);
    }

    while servers.join_next().await.is_some() {}

    Ok(())
}
