use std::sync::{Arc, Mutex};

use napi::bindgen_prelude::*;

use sl_mpc_mate::traits::{PersistentObject, Round};

use dkls23::keygen::{messages::Keyshare, KeygenError, KeygenParty, R1, R2, R3, R4, R5, R6};
use dkls23::utils::Init;

use super::KeygenPartyKeys;

// use super::*;

enum Session {
    Init(KeygenParty<Init>),
    R1(KeygenParty<R1>),
    R2(KeygenParty<R2>),
    R3(KeygenParty<R3>),
    R4(KeygenParty<R4>),
    R5(KeygenParty<R5>),
    R6(KeygenParty<R6>),

    Fini(Keyshare),
    Error(KeygenError),
}

enum State {
    WaitingMessage(Session),
    ProcessingMessage,
}

pub struct ProcessMessagesTask {
    state: SessionInner,
    session: Option<Session>,
    input: Buffer,
}

impl ProcessMessagesTask {
    fn new(session: Session, input: Buffer, state: SessionInner) -> Self {
        Self {
            session: Some(session),
            state,
            input,
        }
    }
}

#[napi]
impl Task for ProcessMessagesTask {
    type Output = Vec<u8>;
    type JsValue = Buffer;

    fn compute(&mut self) -> Result<Self::Output> {
        let (session, msg) = match self.session.take() {
            Some(Session::Init(init)) => process_message(init, &self.input, Session::R1),

            Some(Session::R1(r1)) => process_message(r1, &self.input, Session::R2),

            Some(Session::R2(r2)) => process_message(r2, &self.input, Session::R3),

            Some(Session::R3(r3)) => process_message(r3, &self.input, Session::R4),

            Some(Session::R4(r4)) => process_message(r4, &self.input, Session::R5),

            Some(Session::R5(r5)) => process_message(r5, &self.input, Session::R6),

            Some(Session::R6(r6)) => process_message(r6, &self.input, Session::Fini),

            _ => unreachable!(),
        };

        self.session = Some(session);

        Ok(msg.into())
    }

    fn resolve(&mut self, _env: Env, msg: Self::Output) -> Result<Self::JsValue> {
        Ok(msg.into())
    }

    fn finally(&mut self, _env: Env) -> Result<()> {
        *self.state.lock().unwrap() = State::WaitingMessage(
            self.session
                .take()
                .expect("session should be Some after compute()"),
        );

        Ok(())
    }
}

fn process_message<R, I, N, M, F>(round: R, input: &[u8], to_session: F) -> (Session, Buffer)
where
    R: Round<Input = Vec<I>, Output = std::result::Result<(N, M), KeygenError>>,
    I: PersistentObject,
    M: PersistentObject,
    F: FnOnce(N) -> Session,
{
    let input = match I::decode_batch(input) {
        Some(input) => input,
        None => {
            return (
                Session::Error(KeygenError::InvalidMessage),
                Buffer::from(vec![]),
            )
        }
    };

    match round.process(input) {
        Ok((next, msg)) => {
            let msg: Buffer = msg.to_bytes().expect("serialize output message").into();
            (to_session(next), msg)
        }

        Err(err) => (Session::Error(err), Buffer::from(vec![])),
    }
}

type SessionInner = Arc<Mutex<State>>;

#[napi]
pub struct KeygenSession {
    state: SessionInner,
}


#[napi]
impl KeygenSession {
    #[napi(factory)]
    pub fn create(
        keys: &KeygenPartyKeys,
        t: u32,
        n: u32,
        pid: u32,
        rank: u32,
        _ephemeral: bool,
    ) -> Result<KeygenSession> {
        let mut rng = rand::thread_rng();

        let init = KeygenParty::<Init>::new(
            t as usize,
            n as usize,
            pid as usize,
            rank as usize,
            &keys.inner,
            4, // FIXME use constant!!!
            &mut rng,
        )
        .map_err(|err| Error::from_reason(err.to_string()))?;

        Ok(Self {
            state: Arc::new(Mutex::new(State::WaitingMessage(Session::Init(init)))),
        })
    }

    #[napi]
    pub fn error_msg(&self) -> Option<String> {
        let state = self.state.lock().unwrap();

        match &*state {
            State::WaitingMessage(Session::Error(err)) => Some(err.to_string()),
            _ => None
        }
    }

    #[napi]
    pub fn status(&self) -> i32 {
        let state = self.state.lock().unwrap();

        match &*state {
            State::WaitingMessage(Session::Init(_)) => 0,
            State::WaitingMessage(Session::R1(_)) => 1,
            State::WaitingMessage(Session::R2(_)) => 2,
            State::WaitingMessage(Session::R3(_)) => 3,
            State::WaitingMessage(Session::R4(_)) => 4,
            State::WaitingMessage(Session::R5(_)) => 5,
            State::WaitingMessage(Session::R6(_)) => 6,
            State::WaitingMessage(Session::Fini(_)) => 7,
            State::WaitingMessage(Session::Error(_)) => -1,
            State::ProcessingMessage => -2,
        }
    }

    #[napi]
    pub fn process_messages(&mut self, msg: Buffer) -> Result<AsyncTask<ProcessMessagesTask>> {
        let session = {
            let mut state = self.state.lock().unwrap();
            let inner = std::mem::replace(&mut *state, State::ProcessingMessage);
            match inner {
                State::WaitingMessage(session)
                    if !matches!(session, Session::Fini(_) | Session::Error(_)) =>
                {
                    session
                }

                _ => {
                    *state = inner;
                    return Err(Error::from_reason("invalid session state"));
                }
            }
        };

        Ok(AsyncTask::new(ProcessMessagesTask::new(
            session,
            msg,
            self.state.clone(),
        )))
    }

    #[napi]
    pub fn finalize(&mut self) -> Result<super::Keyshare> {
        let state = self.state.lock().unwrap();

        match &*state {
            State::WaitingMessage(Session::Fini(share)) => Ok(super::Keyshare {
                share: share.clone(),
            }),

            _ => Err(Error::from_reason("invalid session state")),
        }
    }
}
