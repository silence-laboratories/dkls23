// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::{
    collections::HashMap,
    ops::{Deref, DerefMut},
};

use bytemuck::{AnyBitPattern, NoUninit};
use zeroize::Zeroizing;

use sl_mpc_mate::coord::*;

use crate::{
    pairs::Pairs,
    proto::{
        check_abort, EncryptedMessage, EncryptionScheme, MessageTag, MsgId, Relay, SignedMessage,
        Wrap,
    },
    setup::{ProtocolParticipant, ABORT_MESSAGE_TAG},
};

/// Relay Errors
pub enum Error {
    /// Abort
    Abort(usize),
    /// Recv
    Recv,
    /// Send
    Send,
    /// InvalidMessage
    InvalidMessage,
}

/// custom message relay
pub struct FilteredMsgRelay<R> {
    relay: R,
    in_buf: Vec<(Vec<u8>, usize, MessageTag)>,
    expected: HashMap<MsgId, (usize, MessageTag)>,
}

impl<R: Relay> FilteredMsgRelay<R> {
    /// Construct a FilteredMsgRelay by wrapping up a Relay object
    pub fn new(relay: R) -> Self {
        Self {
            relay,
            expected: HashMap::new(),
            in_buf: vec![],
        }
    }

    /// Return underlying relay object
    pub fn into_inner(self) -> R {
        self.relay
    }

    /// Mark message with ID as expected and associate pair (party-id,
    /// tag) with it.
    pub async fn expect_message(
        &mut self,
        id: MsgId,
        tag: MessageTag,
        party_id: usize,
        ttl: u32,
    ) -> Result<(), MessageSendError> {
        self.relay.ask(&id, ttl).await?;
        self.expected.insert(id, (party_id, tag));

        Ok(())
    }

    fn put_back(&mut self, msg: &[u8], tag: MessageTag, party_id: usize) {
        self.expected
            .insert(msg.try_into().unwrap(), (party_id, tag));
    }

    /// Receive an expected message with given tag, and return a
    /// party-id associated with it.
    pub async fn recv(&mut self, tag: MessageTag) -> Result<(Vec<u8>, usize, bool), Error> {
        // flush output message messages.
        self.relay.flush().await.map_err(|_| Error::Recv)?;

        if let Some(idx) = self.in_buf.iter().position(|ent| ent.2 == tag) {
            let (msg, p, _) = self.in_buf.swap_remove(idx);
            return Ok((msg, p, false));
        }

        loop {
            let msg = self.relay.next().await.ok_or(Error::Recv)?;

            if let Ok(id) = <&MsgId>::try_from(msg.as_slice()) {
                if let Some(&(p, t)) = self.expected.get(id) {
                    self.expected.remove(id);
                    match t {
                        ABORT_MESSAGE_TAG => {
                            return Ok((msg, p, true));
                        }

                        _ if t == tag => {
                            return Ok((msg, p, false));
                        }

                        _ => {
                            // some expected but not required right
                            // now message.
                            self.in_buf.push((msg, p, t));
                        }
                    }
                }
            }
        }
    }

    /// Add expected messages and Ask underlying message relay to
    /// receive them.
    pub async fn ask_messages<P: ProtocolParticipant>(
        &mut self,
        setup: &P,
        tag: MessageTag,
        p2p: bool,
    ) -> Result<usize, MessageSendError> {
        self.ask_messages_from_iter(setup, tag, setup.all_other_parties(), p2p)
            .await
    }

    /// Ask set of messages with a given `tag` from a set of `parties`.
    ///
    /// Filter out own `party_index` from `parties`.
    ///
    /// Returns number of messages with the same tag.
    ///
    pub async fn ask_messages_from_iter<P, I>(
        &mut self,
        setup: &P,
        tag: MessageTag,
        from_parties: I,
        p2p: bool,
    ) -> Result<usize, MessageSendError>
    where
        P: ProtocolParticipant,
        I: IntoIterator<Item = usize>,
    {
        let my_party_index = setup.participant_index();
        let receiver = p2p.then_some(my_party_index);
        let mut count = 0;
        for sender_index in from_parties.into_iter() {
            if sender_index == my_party_index {
                continue;
            }

            count += 1;
            self.expect_message(
                setup.msg_id_from(sender_index, receiver, tag),
                tag,
                sender_index,
                setup.message_ttl().as_secs() as _,
            )
            .await?;
        }

        Ok(count)
    }

    /// The same as `ask_messages_from_iter()` by accepts slice of indices
    pub async fn ask_messages_from_slice<'a, P, I>(
        &mut self,
        setup: &P,
        tag: MessageTag,
        from_parties: I,
        p2p: bool,
    ) -> Result<usize, MessageSendError>
    where
        P: ProtocolParticipant,
        I: IntoIterator<Item = &'a usize>,
    {
        self.ask_messages_from_iter(setup, tag, from_parties.into_iter().copied(), p2p)
            .await
    }

    /// Create a round
    pub fn round(&mut self, count: usize, tag: MessageTag) -> Round<'_, R> {
        Round::new(count, tag, self)
    }
}

impl<R> Deref for FilteredMsgRelay<R> {
    type Target = R;

    fn deref(&self) -> &Self::Target {
        &self.relay
    }
}

impl<R> DerefMut for FilteredMsgRelay<R> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.relay
    }
}

/// Structure to receive a round of messages
pub struct Round<'a, R> {
    tag: MessageTag,
    count: usize,
    pub(crate) relay: &'a mut FilteredMsgRelay<R>,
}

impl<'a, R: Relay> Round<'a, R> {
    /// Create a new round with a given number of messages to receive.
    pub fn new(count: usize, tag: MessageTag, relay: &'a mut FilteredMsgRelay<R>) -> Self {
        Self { count, tag, relay }
    }

    /// Receive next message in the round.
    /// On success returns Ok(Some(message, party_index, is_abort_flag)).
    /// At the end of the round it returns Ok(None).
    ///
    pub async fn recv(&mut self) -> Result<Option<(Vec<u8>, usize, bool)>, Error> {
        Ok(if self.count > 0 {
            let msg = self.relay.recv(self.tag).await;
            #[cfg(feature = "tracing")]
            if msg.is_err() {
                for (id, (p, t)) in &self.relay.expected {
                    if t == &self.tag {
                        tracing::debug!("waiting for {:X} {} {:?}", id, p, t);
                    }
                }
            }
            let msg = msg?;
            self.count -= 1;
            Some(msg)
        } else {
            None
        })
    }

    /// It is possible to receive a invalid message with a correct ID.
    /// In this case, it have to put the message id back into
    /// relay.expected table and increment a counter of waiting
    /// messages in the round.
    pub fn put_back(&mut self, msg: &[u8], tag: MessageTag, party_id: usize) {
        self.relay.put_back(msg, tag, party_id);
        self.count += 1;

        // TODO Should we ASK it again?
    }

    /// Receiver all messages in the round, verify, decode and pass to
    /// given handler.
    pub async fn of_signed_messages<T, F, S, E>(
        mut self,
        setup: &S,
        abort_err: impl Fn(usize) -> E,
        mut handler: F,
    ) -> Result<(), E>
    where
        T: AnyBitPattern + NoUninit,
        S: ProtocolParticipant,
        F: FnMut(&T, usize) -> Result<(), E>,
        E: From<Error>,
    {
        while let Some((msg, party_idx, is_abort)) = self.recv().await? {
            if is_abort {
                check_abort(setup, &msg, party_idx, &abort_err)?;
                self.put_back(&msg, ABORT_MESSAGE_TAG, party_idx);
                continue;
            }

            let vk = setup.verifier(party_idx);
            let msg: &T = match SignedMessage::verify(&msg, vk) {
                Some(refs) => refs,
                _ => {
                    self.put_back(&msg, self.tag, party_idx);
                    continue;
                }
            };

            handler(msg, party_idx)?;
        }

        Ok(())
    }

    /// Receiver all messages in the round, decrypt, decode and pass
    /// to given handler.
    pub async fn of_encrypted_messages<T, F, P, E>(
        mut self,
        setup: &P,
        scheme: &mut dyn EncryptionScheme,
        trailer: usize,
        err: impl Fn(usize) -> E,
        mut handler: F,
    ) -> Result<(), E>
    where
        T: AnyBitPattern + NoUninit,
        P: ProtocolParticipant,
        F: FnMut(&T, usize, &[u8], &mut dyn EncryptionScheme) -> Result<Option<Vec<u8>>, E>,
        E: From<Error>,
    {
        while let Some((msg, party_index, is_abort)) = self.recv().await? {
            if is_abort {
                check_abort(setup, &msg, party_index, &err)?;
                self.put_back(&msg, ABORT_MESSAGE_TAG, party_index);
                continue;
            }

            let mut msg = Zeroizing::new(msg);

            let (msg, trailer) =
                match EncryptedMessage::<T>::decrypt(&mut msg, trailer, scheme, party_index) {
                    Some(refs) => refs,
                    _ => {
                        self.put_back(&msg, self.tag, party_index);
                        continue;
                    }
                };

            if let Some(replay) = handler(msg, party_index, trailer, scheme)? {
                self.relay.send(replay).await.map_err(|_| Error::Send)?;
            }
        }

        Ok(())
    }

    /// Broadcast 4 values and collect 4 values from others in the round
    pub async fn broadcast_4<P, T1, T2, T3, T4>(
        self,
        setup: &P,
        msg: (T1, T2, T3, T4),
    ) -> Result<
        (
            Pairs<T1, usize>,
            Pairs<T2, usize>,
            Pairs<T3, usize>,
            Pairs<T4, usize>,
        ),
        Error,
    >
    where
        P: ProtocolParticipant,
        T1: Wrap,
        T2: Wrap,
        T3: Wrap,
        T4: Wrap,
    {
        #[cfg(feature = "tracing")]
        tracing::debug!("enter broadcast {:?}", self.tag);

        let my_party_id = setup.participant_index();

        let sizes = [
            msg.0.external_size(),
            msg.1.external_size(),
            msg.2.external_size(),
            msg.3.external_size(),
        ];
        let trailer: usize = sizes.iter().sum();

        let buffer = {
            // Do not hold SignedMessage across an await point to avoid
            // forcing ProtocolParticipant::MessageSignature to be Send
            // in case if the future returned by run() have to be Send.
            let mut buffer = SignedMessage::<(), _>::new(
                &setup.msg_id(None, self.tag),
                setup.message_ttl().as_secs() as _,
                0,
                trailer,
            );

            let (_, mut out) = buffer.payload();

            out = msg.0.encode(out);
            out = msg.1.encode(out);
            out = msg.2.encode(out);
            msg.3.encode(out);

            buffer.sign(setup.signer())
        };

        self.relay.send(buffer).await.map_err(|_| Error::Send)?;

        let (mut p0, mut p1, mut p2, mut p3) = self.recv_broadcast_4(setup, &sizes).await?;

        p0.push(my_party_id, msg.0);
        p1.push(my_party_id, msg.1);
        p2.push(my_party_id, msg.2);
        p3.push(my_party_id, msg.3);

        Ok((p0, p1, p2, p3))
    }

    /// Receive broadcasted 4 values from all parties in the round and
    /// collect them into 4 Pairs vectors.
    pub async fn recv_broadcast_4<P, T1, T2, T3, T4>(
        mut self,
        setup: &P,
        sizes: &[usize; 4],
    ) -> Result<
        (
            Pairs<T1, usize>,
            Pairs<T2, usize>,
            Pairs<T3, usize>,
            Pairs<T4, usize>,
        ),
        Error,
    >
    where
        P: ProtocolParticipant,
        T1: Wrap,
        T2: Wrap,
        T3: Wrap,
        T4: Wrap,
    {
        let trailer: usize = sizes.iter().sum();

        let mut p0 = Pairs::new();
        let mut p1 = Pairs::new();
        let mut p2 = Pairs::new();
        let mut p3 = Pairs::new();

        while let Some((msg, party_id, is_abort)) = self.recv().await? {
            if is_abort {
                check_abort(setup, &msg, party_id, Error::Abort)?;
                self.put_back(&msg, ABORT_MESSAGE_TAG, party_id);
                continue;
            }

            let buf = match SignedMessage::<(), _>::verify_with_trailer(
                &msg,
                trailer,
                setup.verifier(party_id),
            ) {
                Some((_, msg)) => msg,
                None => {
                    // We got message with a right ID but with broken signature.
                    self.put_back(&msg, self.tag, party_id);
                    continue;
                }
            };

            let (buf, v1) = T1::decode(buf, sizes[0]).ok_or(Error::InvalidMessage)?;
            let (buf, v2) = T2::decode(buf, sizes[1]).ok_or(Error::InvalidMessage)?;
            let (buf, v3) = T3::decode(buf, sizes[2]).ok_or(Error::InvalidMessage)?;
            let (_bu, v4) = T4::decode(buf, sizes[3]).ok_or(Error::InvalidMessage)?;

            p0.push(party_id, v1);
            p1.push(party_id, v2);
            p2.push(party_id, v3);
            p3.push(party_id, v4);
        }

        Ok((p0, p1, p2, p3))
    }
}
