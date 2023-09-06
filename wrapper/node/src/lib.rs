#![deny(clippy::all)]

#[macro_use]
extern crate napi_derive;

use napi::bindgen_prelude::*;

use sl_mpc_mate::traits::PersistentObject;

use dkls23::keygen;

mod dkg;
mod dsg;

#[napi]
pub struct KeygenPartyKeys {
    inner: keygen::PartyKeys
}

pub struct KeygenPartyKeysTask;

#[napi]
impl Task for KeygenPartyKeysTask {
    type Output = keygen::PartyKeys;
    type JsValue = KeygenPartyKeys;

    fn compute(&mut self) -> Result<Self::Output> {
        let mut rng = rand::thread_rng();

        Ok(keygen::PartyKeys::new(&mut rng))
    }

    fn resolve(&mut self, _env: Env, keys: Self::Output) -> Result<Self::JsValue> {
        Ok(KeygenPartyKeys { inner: keys })
    }
}

#[napi]
impl KeygenPartyKeys {
    #[napi]
    pub fn create() -> AsyncTask<KeygenPartyKeysTask> {
        AsyncTask::new(KeygenPartyKeysTask)
    }

    #[napi(factory)]
    pub fn from_bytes(bytes: Buffer) -> Result<Self> {
        let inner = keygen::PartyKeys::from_bytes(&bytes)
            .ok_or_else(|| Error::from_reason("cant deserialize keygen::PartyKeys"))?;

        Ok(Self { inner })
    }

    #[napi]
    pub fn to_bytes(&self) -> Buffer {
        self.inner.to_bytes().unwrap().into()
    }

    #[napi]
    pub fn public_keys(&self) -> Buffer {
        let pk = self.inner.public_keys();

        let bytes = pk.to_bytes().expect("serialization failed");

        bytes.into()
    }
}


#[napi]
pub struct Keyshare {
    share: keygen::messages::Keyshare
}

#[napi]
impl Keyshare {
    #[napi(factory)]
    pub fn from_bytes(bytes: Buffer) -> Result<Self> {
        let share = keygen::messages::Keyshare::from_bytes(&bytes)
            .ok_or_else(|| Error::from_reason("cant deserialize Keyshare"))?;

        Ok(Self { share })
    }

    #[napi]
    pub fn to_bytes(&self) -> Buffer {
        self.share.to_bytes().unwrap().into()
    }

    #[napi]
    pub fn participant_id(&self) -> u8 {
        self.share.party_id as u8
    }

    #[napi]
    pub fn participants(&self) -> u8 {
        self.share.total_parties as u8
    }

    #[napi]
    pub fn threshold(&self) -> u8 {
        self.share.threshold as u8
    }

}

// #[napi]
// pub struct SignPartyKeys {
//     inner: sign::SignerParty
// }
