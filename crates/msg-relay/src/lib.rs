use std::cmp::Ordering;
use std::collections::{hash_map::Entry, BinaryHeap, HashMap};
use std::sync::{
    atomic::{AtomicUsize, Ordering::SeqCst},
    Arc, Mutex,
};
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
    Waiters((Instant, Vec<(usize, mpsc::Sender<Vec<u8>>)>)),
    Ready(Vec<u8>),
}

pub type AppState<F> = Arc<Mutex<AppStateInner<F>>>;

pub struct AppStateInner<F> {
    expire: BinaryHeap<Expire>,
    messages: HashMap<MsgId, MsgEntry>,
    total_size: u64,
    total_count: u64,
    enqueue: F,
}

impl<F> AppStateInner<F>
where
    F: FnMut(Vec<u8>) + Send + 'static,
{
    pub fn new(enqueue: F) -> Self {
        Self {
            expire: BinaryHeap::new(),
            messages: HashMap::new(),
            enqueue,
            total_size: 0,
            total_count: 0,
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

            tracing::info!("expire {:?} {:X}", kind, id);

            if let Entry::Occupied(ocp) = self.messages.entry(id) {
                match ocp.get() {
                    MsgEntry::Ready(_) => {
                        if kind == Kind::Pub {
                            ocp.remove();
                        }
                    }

                    MsgEntry::Waiters((expire, _)) => {
                        if kind == Kind::Ask && *expire <= now {
                            ocp.remove();
                        }
                    }
                }
            }
        }
    }

    pub fn handle_message(
        &mut self,
        msg: Vec<u8>,
        tx: Option<(usize, &mpsc::Sender<Vec<u8>>)>,
    ) {
        let MsgHdr { id, ttl, kind } = match MsgHdr::from(&msg) {
            Some(hdr) => hdr,
            None => return, // TODO report invalid message?
        };

        let now = Instant::now();
        let expire = now + ttl;

        self.total_size += msg.len() as u64;
        self.total_count += 1;

        tracing::info!("handle {:X} {:?} {}", id, kind, msg.len());

        // we have a locked state, let's cleanup some old entries
        self.cleanup(now);

        match self.messages.entry(id) {
            Entry::Occupied(mut ocp) => {
                match ocp.get_mut() {
                    MsgEntry::Ready(msg) => {
                        if matches!(kind, Kind::Ask) {
                            // Got an ASK for a Ready message.
                            // Send the message immediately.
                            if let Some((_, tx)) = tx {
                                let msg = msg.clone();
                                let tx = tx.clone();
                                tokio::spawn(async move {
                                    // ignore send error
                                    let _ = tx.send(msg).await;
                                });
                            }
                        } else {
                            // ignore the duplicate message
                            // TODO report duplicate message?
                        }
                    }

                    MsgEntry::Waiters((prev, b)) => {
                        if matches!(kind, Kind::Ask) {
                            // join other waiters
                            if let Some((id, tx)) = tx {
                                if b.iter()
                                    .find(|(tx_id, _)| *tx_id == id)
                                    .is_none()
                                {
                                    *prev = expire.max(*prev);
                                    b.push((id, tx.clone()));
                                    (self.enqueue)(msg);
                                }
                            }
                        } else {
                            // wake up all waiters
                            for s in b.drain(..) {
                                let msg = msg.clone();
                                tokio::spawn(async move {
                                    let _ = s.1.send(msg).await;
                                });
                            }
                            // and replace with a Read message
                            ocp.insert(MsgEntry::Ready(msg));
                        };

                        // remember to cleanup this entry later
                        self.cleanup_later(id, expire, kind);
                    }
                }
            }

            Entry::Vacant(vac) => {
                if matches!(kind, Kind::Ask) {
                    // This is the first ASK for the message
                    if let Some((id, tx)) = tx {
                        vac.insert(MsgEntry::Waiters((
                            expire,
                            vec![(id, tx.clone())],
                        )));

                        (self.enqueue)(msg);
                    }
                } else {
                    vac.insert(MsgEntry::Ready(msg));
                };

                self.cleanup_later(id, expire, kind);
            }
        };
    }
}

pub async fn handler<F: FnMut(Vec<u8>) + Send + 'static>(
    State(state): State<AppState<F>>,
    ws: WebSocketUpgrade,
) -> Response {
    ws.on_upgrade(|socket| async move {
        static CONN_ID: AtomicUsize = AtomicUsize::new(0);

        // TODO make buffer size configurable
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(16);

        // Generate unique connection ID.
        let tx_id = CONN_ID.fetch_add(1, SeqCst);

        let (mut sender, mut receiver) = socket.split();

        loop {
            tokio::select!{
                msg = rx.recv() => {
                    if let Some(msg) = msg {
                        let _ = sender.send(Message::Binary(msg)).await;
                    }
                }

                msg = receiver.next() => {
                    // FIXME should we report error here?
                    let msg = if let Some(Ok(msg)) = msg { msg } else { break; };

                    match msg {
                        Message::Binary(msg) => {
                            state.lock().unwrap().handle_message(msg, Some((tx_id, &tx)));
                        }

                        Message::Ping(msg) => {
                            let _ = sender.send(Message::Pong(msg)).await;
                        }

                        _ => {}
                    }
                }
            }
        };

        tracing::info!("close ws connection");
    })
}

pub async fn stats<F>(State(state): State<AppState<F>>) -> String {
    let (size, count) = {
        let state = state.lock().unwrap();

        (state.total_size, state.total_count)
    };

    format!("{} {}", size, count)
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
        let mut app = AppStateInner::new(|_| {});

        let msg = dummy_msg(10, 100);

        let _hdr = MsgHdr::from(&msg).unwrap();

        app.handle_message(msg, Some((0, &tx)));
    }
}
