// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::{
    cmp::Ordering,
    collections::{hash_map::Entry, BinaryHeap, HashMap},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{ready, Context, Poll},
    time::Instant,
};

use tokio::sync::mpsc;

use sl_mpc_mate::message::*;

pub use sl_mpc_mate::{coord::*, message::MESSAGE_HEADER_SIZE};

struct Expire(Instant, MsgId, Kind);

impl PartialEq for Expire {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}

impl Eq for Expire {}

impl PartialOrd for Expire {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Expire {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0).reverse()
    }
}

enum MsgEntry {
    Waiters {
        expire: Instant,
        waiters: Vec<(u64, mpsc::UnboundedSender<Vec<u8>>)>,
    },

    Ready {
        msg: Vec<u8>,
    },
}

pub type OnAskMessage = dyn Fn(&[u8]) + Send + 'static;

#[derive(Clone)]
pub struct MsgRelay {
    inner: Arc<Mutex<Inner>>,
}

impl MsgRelay {
    pub fn new(on_ask_msg: Option<Box<OnAskMessage>>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                conn_id: 0,
                expire: BinaryHeap::new(),
                messages: HashMap::new(),
                total_size: 0,
                total_count: 0,
                on_ask_msg,
            })),
        }
    }

    pub fn handle_message(&self, msg: Vec<u8>, tx: Option<(u64, &mpsc::UnboundedSender<Vec<u8>>)>) {
        self.inner.lock().unwrap().handle_message(msg, tx);
    }

    pub fn send(&self, msg: Vec<u8>) {
        self.handle_message(msg, None);
    }

    pub fn stats(&self) -> (u64, u64) {
        let state = self.inner.lock().unwrap();
        (state.total_size, state.total_count)
    }

    pub fn connect(&self) -> MsgRelayConnection {
        // TODO make buffer size configurable
        let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();

        MsgRelayConnection {
            tx,
            rx,
            tx_id: self.inner.lock().unwrap().next_conn_id(),
            inner: self.inner.clone(),
            stats: Default::default(),
        }
    }

    pub fn messages<F>(&self, f: F)
    where
        F: Fn(&MsgId, usize),
    {
        let lock = self.inner.lock().unwrap();

        for (k, v) in &lock.messages {
            let waiters = match v {
                MsgEntry::Ready { msg: _ } => 0,
                MsgEntry::Waiters { expire: _, waiters } => waiters.len(),
            };

            f(k, waiters);
        }
    }
}

#[derive(Default, Clone)]
pub struct MsgRelayConnectionStats {
    pub send_count: usize,
    pub send_size: usize,
    pub ask_count: usize,
    pub recv_count: usize,
    pub recv_size: usize,
}

pub struct MsgRelayConnection {
    tx_id: u64,
    tx: mpsc::UnboundedSender<Vec<u8>>,
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
    inner: Arc<Mutex<Inner>>,
    stats: MsgRelayConnectionStats,
}

impl MsgRelayConnection {
    /// Send message to the connection.
    pub fn send_message(&self, msg: Vec<u8>) {
        self.inner
            .lock()
            .unwrap()
            .handle_message(msg, Some((self.tx_id, &self.tx)))
    }

    pub fn get(&mut self, id: &MsgId) -> Option<Vec<u8>> {
        let tbl = self.inner.lock().ok()?;

        match tbl.messages.get(id) {
            Some(MsgEntry::Ready { msg }) => Some(msg.clone()),
            _ => None,
        }
    }

    /// Receive an ASKed message.
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.rx.recv().await
    }

    /// Returns connection ID
    pub fn conn_id(&self) -> u64 {
        self.tx_id
    }

    pub fn stats(&mut self) -> MsgRelayConnectionStats {
        self.stats.clone()
    }
}

struct Inner {
    conn_id: u64,
    expire: BinaryHeap<Expire>,
    messages: HashMap<MsgId, MsgEntry>,
    total_size: u64,
    total_count: u64,
    on_ask_msg: Option<Box<OnAskMessage>>,
}

impl Inner {
    fn next_conn_id(&mut self) -> u64 {
        self.conn_id += 1;
        self.conn_id
    }

    fn cleanup_later(&mut self, id: MsgId, expire: Instant, kind: Kind) {
        self.expire.push(Expire(expire, id, kind));
    }

    fn cleanup(&mut self, now: Instant) {
        while let Some(ent) = self.expire.peek() {
            if ent.0 > now {
                break;
            }

            let Expire(_, id, kind) = self.expire.pop().unwrap();

            tracing::debug!("expire {:?} {:X}", kind, id);

            if let Entry::Occupied(ocp) = self.messages.entry(id) {
                match ocp.get() {
                    MsgEntry::Ready { .. } => {
                        if kind == Kind::Pub {
                            ocp.remove();
                        }
                    }

                    MsgEntry::Waiters { expire, .. } => {
                        if kind == Kind::Ask && *expire <= now {
                            ocp.remove();
                        }
                    }
                }
            }
        }
    }

    fn handle_message(&mut self, msg: Vec<u8>, tx: Option<(u64, &mpsc::UnboundedSender<Vec<u8>>)>) {
        let hdr = match <&MsgHdr>::try_from(msg.as_slice()) {
            Ok(hdr) => hdr,
            Err(_) => return, // TODO report invalid message?
        };

        let kind = if msg.len() == MESSAGE_HEADER_SIZE {
            Kind::Ask
        } else {
            Kind::Pub
        };
        let id = *hdr.id();
        let ts = Instant::now();
        let msg_expire = ts + hdr.ttl();

        self.total_size += msg.len() as u64;
        self.total_count += 1;

        // we have a locked state, let's cleanup some old entries
        self.cleanup(ts);

        match self.messages.entry(id) {
            Entry::Occupied(mut ocp) => {
                match ocp.get_mut() {
                    MsgEntry::Ready { msg } => {
                        if kind == Kind::Ask {
                            // Got an ASK for a Ready message.
                            // Send the message immediately.
                            if let Some((_, tx)) = tx {
                                tracing::debug!("rdy-msg {:X} {}", id, msg.len());
                                let _ = tx.send(msg.clone());
                            }
                        }
                    }

                    MsgEntry::Waiters { expire, waiters } => {
                        if kind == Kind::Ask {
                            // join other waiters
                            if let Some((w_id, tx)) = tx {
                                let cnt = waiters.len();
                                if !waiters.iter().any(|(tx_id, _)| *tx_id == w_id) {
                                    tracing::debug!("add-ask {:X} {} {}", id, msg.len(), cnt + 1);

                                    *expire = msg_expire.max(*expire);
                                    waiters.push((w_id, tx.clone()));
                                    if let Some(on_ask_msg) = &self.on_ask_msg {
                                        on_ask_msg(&msg);
                                    }
                                }
                            }
                        } else {
                            tracing::debug!("wak-msg {:X} {} {}", id, msg.len(), waiters.len());
                            // wake up all waiters
                            for (_, tx) in waiters.drain(..) {
                                let _ = tx.send(msg.clone()); // TODO handle error
                            }
                            // and replace with a Read message
                            ocp.insert(MsgEntry::Ready { msg });
                        };

                        // remember to cleanup this entry later
                        self.cleanup_later(id, msg_expire, kind);
                    }
                }
            }

            Entry::Vacant(vac) => {
                if matches!(kind, Kind::Ask) {
                    // This is the first ASK for the message
                    if let Some((w_id, tx)) = tx {
                        vac.insert(MsgEntry::Waiters {
                            expire: msg_expire,
                            waiters: vec![(w_id, tx.clone())],
                        });

                        tracing::debug!("add-ask {:X} {} 1", id, msg.len());

                        if let Some(on_ask_msg) = &self.on_ask_msg {
                            on_ask_msg(&msg);
                        }
                    }
                } else {
                    tracing::debug!("add-msg {:X} {}", id, msg.len());

                    vac.insert(MsgEntry::Ready { msg });
                };

                self.cleanup_later(id, msg_expire, kind);
            }
        };
    }
}

impl Stream for MsgRelayConnection {
    type Item = Vec<u8>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let msg = ready!(this.rx.poll_recv(cx));

        if let Some(msg) = &msg {
            this.stats.recv_count += 1;
            this.stats.recv_size += msg.len();
        }

        Poll::Ready(msg)
    }
}

impl Sink<Vec<u8>> for MsgRelayConnection {
    type Error = MessageSendError;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
        let this = self.get_mut();
        this.stats.send_count += 1;
        this.stats.send_size += item.len();

        if item.len() == MESSAGE_HEADER_SIZE {
            this.stats.ask_count += 1;
        }

        this.send_message(item);

        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

impl Relay for MsgRelayConnection {}

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
        let (tx, _rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let app = MsgRelay::new(None);

        let msg = dummy_msg(10, 100);

        let _hdr = <&MsgHdr>::try_from(msg.as_slice()).unwrap();

        app.handle_message(msg, Some((0, &tx)));
    }
}
