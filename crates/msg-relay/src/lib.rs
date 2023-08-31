use std::cmp::Ordering;
use std::collections::{hash_map::Entry, BinaryHeap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use futures_util::stream::StreamExt;
use futures_util::SinkExt;

use tokio::sync::mpsc;

use axum::{
    extract::{
        ws::{Message, WebSocketUpgrade},
        State,
    },
    response::Response,
};

use sl_mpc_mate::message::*;

// #[derive(PartialOrd)]
struct Expire(Instant, MsgId, Kind);

impl PartialEq for Expire {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}

impl Eq for Expire {}

impl PartialOrd for Expire {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.0.partial_cmp(&other.0).map(Ordering::reverse)
    }
}

impl Ord for Expire {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0).reverse()
    }
}

enum MsgEntry {
    Waiters((Instant, Vec<mpsc::Sender<Vec<u8>>>)),
    Ready(Vec<u8>),
}

pub type AppState = Arc<Mutex<AppStateInner>>;

pub struct AppStateInner {
    expire: BinaryHeap<Expire>,
    messages: HashMap<MsgId, MsgEntry>,
}

impl AppStateInner {
    pub fn new() -> Self {
        Self {
            expire: BinaryHeap::new(),
            messages: HashMap::new(),
        }
    }

    fn cleanup_later(
        &mut self,
        id: MsgId,
        expire: Instant,
        kind: Kind,
    ) {
        self.expire.push(Expire(expire, id, kind));
    }

    fn cleanup(&mut self, now: Instant) {
        while let Some(ent) = self.expire.peek() {
            if ent.0 > now {
                break;
            }

            let Expire(_, id, kind) = self.expire.pop().unwrap();

            match self.messages.entry(id) {
                Entry::Occupied(ocp) => match ocp.get() {
                    MsgEntry::Ready(_) => {
                        if matches!(kind, Kind::Pub) {
                            ocp.remove();
                        }
                    }

                    MsgEntry::Waiters((expire, _)) => {
                        if matches!(kind, Kind::Ask) && *expire <= now {
                            ocp.remove();
                        }
                    }
                },

                // FIXME: report error?
                _ => {}
            }
        }
    }

    pub fn handle_message(
        &mut self,
        hdr: MsgHdr,
        msg: Vec<u8>,
        tx: &mpsc::Sender<Vec<u8>>,
    ) {
        let MsgHdr { id, ttl, kind } = hdr;

        let now = Instant::now();
        let expire = now + ttl;

        // we have a locked state, let's cleanup some old entries
        self.cleanup(now);

        match self.messages.entry(id) {
            Entry::Occupied(mut ocp) => {
                match ocp.get_mut() {
                    MsgEntry::Ready(msg) => {
                        if matches!(kind, Kind::Ask) {
                            // got an ASK for a Ready message
                            // send the message immediately
                            let tx = tx.clone();
                            let msg = msg.clone();
                            tokio::spawn(async move {
                                // ignore send error
                                let _ = tx.send(msg).await;
                            });
                        } else {
                            // ignore the duplicate message
                        }
                    }

                    MsgEntry::Waiters((prev, b)) => {
                        if matches!(kind, Kind::Ask) {
                            // join other waiters
                            if *prev < expire {
                                *prev = expire;
                            }
                            b.push(tx.clone());
                        } else {
                            // wake up all waiters
                            for s in b.drain(..) {
                                let msg = msg.clone();
                                tokio::spawn(async move {
                                    let _ = s.send(msg).await;
                                });
                            }
                            // and replace with a Read message
                            ocp.insert(MsgEntry::Ready(msg));
                        }

                        // remember to cleanup this entry later
                        self.cleanup_later(id, expire, kind);
                    }
                }
            }

            Entry::Vacant(vac) => {
                if matches!(kind, Kind::Ask) {
                    // This is the first ASK for the message
                    vac.insert(MsgEntry::Waiters((
                        expire,
                        vec![tx.clone()],
                    )));
                } else {
                    vac.insert(MsgEntry::Ready(msg));
                }

                self.cleanup_later(id, expire, kind);
            }
        }
    }
}

pub async fn handler(
    State(state): State<AppState>,
    ws: WebSocketUpgrade,
) -> Response {
    ws.on_upgrade(|socket| async move {
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(16);

        let (mut sender, mut receiver) = socket.split();

        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                let _ = sender.send(Message::Binary(msg)).await;
            }
        });

        while let Some(msg) = receiver.next().await {
            let msg = if let Ok(msg) = msg { msg } else { return };

            let msg = if let Message::Binary(msg) = msg {
                msg
            } else {
                continue; // skip unknown message
            };

            let hdr = if let Some(hdr) = MsgHdr::from(&msg) {
                hdr
            } else {
                continue; // skip bad messages
            };

            state.lock().unwrap().handle_message(hdr, msg, &tx);
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_msg(ttl: u32, size: usize) -> Vec<u8> {
        let mut msg = vec![0; 32 + 4 + size];

        msg[32..32 + 4].copy_from_slice(&ttl.to_be_bytes());

        msg
    }

    #[tokio::test]
    async fn handle_msg() {
        let (tx, _rx) = mpsc::channel::<Vec<u8>>(16);
        let mut app = AppStateInner::new();

        let msg = dummy_msg(10, 100);

        let hdr = MsgHdr::from(&msg).unwrap();

        app.handle_message(hdr, msg, &tx);
    }
}
