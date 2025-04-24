// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::{
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use sl_mpc_mate::{coord::*, message::MESSAGE_HEADER_SIZE};

pub struct MessageTrace {
    messages: Mutex<Vec<Vec<u8>>>,
}

impl MessageTrace {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            messages: Mutex::new(Vec::new()),
        })
    }

    pub fn message(&self, msg: &[u8]) {
        if msg.len() > MESSAGE_HEADER_SIZE {
            let msg = msg.to_vec();
            self.messages.lock().unwrap().push(msg)
        }
    }

    pub fn messages(&self) -> Vec<Vec<u8>> {
        self.messages.lock().unwrap().drain(..).collect()
    }
}

pub struct Tracing<R> {
    relay: R,
    trace: Option<Arc<MessageTrace>>,
}

impl<R> Tracing<R>
where
    R: Relay,
{
    pub fn new(relay: R, trace: Option<Arc<MessageTrace>>) -> Self {
        Self { relay, trace }
    }
}

impl<R> Stream for Tracing<R>
where
    R: Relay,
{
    type Item = Vec<u8>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.get_mut().relay.poll_next_unpin(cx)
    }
}

impl<R> Sink<Vec<u8>> for Tracing<R>
where
    R: Relay,
{
    type Error = MessageSendError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.get_mut().relay.poll_ready_unpin(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
        let this = self.get_mut();

        if let Some(trace) = &this.trace {
            trace.message(&item);
        }

        this.relay.start_send_unpin(item)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.get_mut().relay.poll_flush_unpin(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.get_mut().relay.poll_close_unpin(cx)
    }
}

impl<R: Relay> Relay for Tracing<R> {}
