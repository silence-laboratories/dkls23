use std::sync::{Arc, Mutex};

use k256::sha2::{Digest, Sha256};

use sl_mpc_mate::traits::{HasFromParty, HasToParty, PersistentObject, Round};

use dkls23::sign::{Init, R2State, SignError, SignMsg2, SignMsg3, SignMsg4, SignerParty, R1, R2, R3, R5};

use super::*;

enum Session {
    Error(SignError),
    Init(SignerParty<Init>),
    R1(SignerParty<R1>),
    R2(SignerParty<R2>),
    R3(SignerParty<R3>),
    // R4(SignerParty<R4>),
    R5(SignerParty<R5>),
    Fini(Vec<u8>),
}

enum State {
    WaitingMessage(Session),
    ProcessingMessage,
}

#[napi]
pub struct SignSession {
    state: Arc<Mutex<State>>,
    hash: [u8; 32],
    init_msg: Vec<u8>,
}

pub struct ProcessMessageTask {
    state: Arc<Mutex<State>>,
    session: Option<Session>,
    input: Buffer,
    msg_hash: [u8; 32],
}

impl ProcessMessageTask {
    fn new(session: Session, input: Buffer, state: Arc<Mutex<State>>, msg_hash: [u8; 32]) -> Self {
        Self {
            session: Some(session),
            input,
            state,
            msg_hash,
        }
    }
}

fn process_message<R, I, N, M, F>(round: R, input: &[u8], to_session: F) -> (Session, Vec<u8>)
where
    R: Round<Input = Vec<I>, Output = std::result::Result<(N, M), SignError>>,
    I: PersistentObject,
    M: PersistentObject,
    F: FnOnce(N) -> Session,
{
    let input = match I::decode_batch(input) {
        Some(input) => input,
        None => return (Session::Error(SignError::InvalidMessage), vec![]),
    };

    match round.process(input) {
        Ok((next, msg)) => {
            let msg = msg.to_bytes().expect("serialize output message");
            (to_session(next), msg)
        }

        Err(err) => (Session::Error(err), vec![]),
    }
}

fn get_party_messages<M: HasToParty + HasFromParty + Clone>(
    for_party: usize,
    msgs: &[Vec<M>],
) -> Vec<M> {
    let mut msgs_for_party = vec![];
    for msg_list in msgs {
        if msg_list[0].get_pid() == for_party {
            continue;
        }
        for msg in msg_list {
            if msg.get_receiver() == for_party {
                msgs_for_party.push(msg.clone());
            }
        }
    }

    msgs_for_party
}

fn process_r2(mut round: SignerParty<R2>, input: &[u8]) -> (Session, Vec<u8>) {
    let input = match Vec::<SignMsg2>::decode_batch(input) {
        Some(input) => input,
        None => return (Session::Error(SignError::InvalidMessage), vec![]),
    };

    // let mut sign_msgs3_list = vec![];
    // let mut parties3 = vec![];

    let pid = round.get_pid();
    let msgs = get_party_messages(pid, &input);

    let sign_msgs3 = msgs
        .into_iter()
        .map(|msg| round.process_p2p(msg).unwrap())
        .collect::<Vec<_>>();

    let party3 = if let R2State::R2Complete(party3) = round.check_proceed() {
        party3
    } else {
        panic!("Party {} not ready to proceed", pid);
    };

    (Session::R3(party3), sign_msgs3.to_bytes().unwrap())
}

fn process_r3(round: SignerParty<R3>, input: &[u8], hash: [u8; 32]) -> (Session, Vec<u8>) {
    let input = match Vec::<SignMsg3>::decode_batch(input) {
        Some(input) => input,
        None => return (Session::Error(SignError::InvalidMessage), vec![]),
    };

    let pid = round.get_pid();
    let msgs = get_party_messages(pid, &input);

    let p4 = round.process(msgs).unwrap();

    let (p5, msg4) = p4.process(hash).unwrap();

    (Session::R5(p5), msg4.to_bytes().unwrap())
}

fn process_r5(round: SignerParty<R5>, input: &[u8]) -> (Session, Vec<u8>) {
    let input = match SignMsg4::decode_batch(input) {
        Some(input) => input,
        None => return (Session::Error(SignError::InvalidMessage), vec![]),
    };


    // for party in parties5 {
    let sign = round.process(input).unwrap();

    //     // println!("Signature: {:?}", sign.to_string())
    // }

    let sign = sign.to_der().as_bytes().to_vec();

    (Session::Fini(sign), vec![])
}

#[napi]
impl Task for ProcessMessageTask {
    type Output = Vec<u8>;
    type JsValue = Buffer;

    fn compute(&mut self) -> Result<Self::Output> {
        let (next, msg) = match self.session.take() {
            Some(Session::Init(init)) => process_message(init, &self.input, Session::R1),

            Some(Session::R1(r1)) => process_message(r1, &self.input, Session::R2),

            Some(Session::R2(r2)) => process_r2(r2, &self.input),

            Some(Session::R3(r3)) => process_r3(r3, &self.input, self.msg_hash),

            // Some(Session::R4(r4)) => process_message(r4, &self.input, Session::R5),

            Some(Session::R5(r5)) => process_r5(r5, &self.input),

            _ => unreachable!(),
        };

        self.session = Some(next);

        Ok(msg)
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

#[napi]
impl SignSession {
    #[napi]
    pub fn create(share: &super::Keyshare, msg: Buffer) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(&msg);
        let hash = hasher.finalize().into();

        let mut rng = rand::thread_rng();
        let init = SignerParty::new(share.share.clone(), &mut rng);
        let init_msg = init.get_public_keys().to_bytes().unwrap();

        Self {
            state: Arc::new(Mutex::new(State::WaitingMessage(Session::Init(init)))),
            hash,
            init_msg,
        }
    }

    #[napi]
    pub fn init_message(&self) -> Buffer {
        self.init_msg.clone().into()
    }

    #[napi]
    pub fn error_msg(&self) -> Option<String> {
        let state = self.state.lock().unwrap();
        match &*state {
            State::WaitingMessage(Session::Error(err)) => Some(err.to_string()),
            _ => None,
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
            // State::WaitingMessage(Session::R4(_)) => 4,
            State::WaitingMessage(Session::R5(_)) => 5,
            State::WaitingMessage(Session::Fini(_)) => 6,
            State::WaitingMessage(Session::Error(_)) => -1,
            State::ProcessingMessage => -2,
        }
    }

    #[napi]
    pub fn process_messages(&mut self, msg: Buffer) -> Result<AsyncTask<ProcessMessageTask>> {
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

        Ok(AsyncTask::new(ProcessMessageTask::new(
            session,
            msg,
            self.state.clone(),
            self.hash
        )))
    }

    #[napi]
    pub fn finalize(&mut self) -> Result<Buffer> {
        let state = self.state.lock().unwrap();

        match &*state {
            State::WaitingMessage(Session::Fini(sign)) => Ok(sign.clone().into()),

            _ => Err(Error::from_reason("invalid session state")),
        }
    }
}
