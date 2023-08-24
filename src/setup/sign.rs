#![allow(dead_code, unused_imports)]
use k256::{elliptic_curve::group::GroupEncoding, AffinePoint};

use bincode::{
    de::{read::Reader, Decoder},
    enc::{write::Writer, Encoder},
    error::{DecodeError, EncodeError},
    Decode, Encode,
};

use sl_mpc_mate::message::*;

use crate::{keygen::Keyshare, setup::Magic};

/// A key generation setup message.
///
/// struct SetupMessage {
///     uint32      algo;
///     t           u8;
///     publicKey   u8[33];  // affine point
///     pkey        opaque<32*t>;
/// }
///
#[derive(Clone)]
pub struct Setup {
    public_key: AffinePoint,
    parties: Vec<VerifyingKey>,
}

impl Encode for Setup {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        (Magic::DSG as u32).encode(encoder)?;

        (self.parties.len() as u8).encode(encoder)?;

        encoder.writer().write(&self.public_key.to_bytes())?;

        for pk in &self.parties {
            encoder.writer().write(pk.as_bytes())?;
        }

        Ok(())
    }
}

impl Decode for Setup {
    fn decode<D: Decoder>(decoder: &mut D) -> Result<Self, DecodeError> {
        let magic = u32::decode(decoder)?;

        if magic != Magic::DSG as u32 {
            return Err(DecodeError::Other("bag magic"));
        }

        let t = u8::decode(decoder)?;

        if t < 2 {
            return Err(DecodeError::Other("bad T"));
        }

        let public_key = <[u8; 33]>::decode(decoder)?;
        let public_key = AffinePoint::from_bytes(&public_key.into());
        let public_key = if bool::from(public_key.is_some()) {
            public_key.unwrap()
        } else {
            return Err(DecodeError::Other("bad keyshare PK"));
        };

        let mut parties = Vec::with_capacity(t as usize);

        for _ in 0..t {
            // let mut pk = [0u8; PUBLIC_KEY_LENGTH];
            // decoder.reader().read(&mut pk)?;

            let pk = <[u8; PUBLIC_KEY_LENGTH]>::decode(decoder)?;
            let pk =
                VerifyingKey::from_bytes(&pk).map_err(|_| DecodeError::Other("bad party PK"))?;

            parties.push(pk);
        }

        // TODO validate parties public keys

        Ok(Setup {
            parties,
            public_key,
        })
    }
}

impl Setup {
    ///
    pub fn threshold(&self) -> u8 {
        self.parties.len() as u8
    }

    /// Return Verifying key of a party by its index
    pub fn party_verifying_key(&self, party_idx: usize) -> Option<&VerifyingKey> {
        self.parties.get(party_idx)
    }
}

///
pub struct ValidatedSetup {
    instance: InstanceId,
    setup: Setup,
    signing_key: SigningKey,
    keyshare: Keyshare,
    party_idx: usize,
}

impl std::ops::Deref for ValidatedSetup {
    type Target = Setup;

    fn deref(&self) -> &Self::Target {
        &self.setup
    }
}

///
impl ValidatedSetup {
    ///
    pub fn instance(&self) -> &InstanceId {
        &self.instance
    }

    ///
    pub fn keyshare(&self) -> &Keyshare {
        &self.keyshare
    }

    ///
    pub fn party_idx(&self) -> usize {
        self.party_idx
    }

    // pub fn party_id(&self) -> u8 {
    //     self.keyshare.party_id
    // }

    ///
    pub fn other_parties_iter(&self) -> impl Iterator<Item = (usize, &VerifyingKey)> {
        self.setup
            .parties
            .iter()
            .enumerate()
            .filter(|(idx, _)| *idx != self.party_idx)
            .map(|(idx, vk)| (idx, vk))
    }

    /// Generate ID of a message from this party to some other (or broadcast)
    pub fn msg_id(&self, receiver: Option<usize>, tag: MessageTag) -> MsgId {
        let sender_vk = self.signing_key.verifying_key();
        let receiver_vk = receiver
            .and_then(|p| self.party_verifying_key(p))
            .map(|vk| vk.as_bytes());

        MsgId::new(self.instance(), sender_vk.as_bytes(), receiver_vk, tag)
    }

    /// Generate ID of a message from given party
    pub fn msg_id_from(
        &self,
        sender_vk: &VerifyingKey,
        receiver: Option<usize>,
        tag: MessageTag,
    ) -> MsgId {
        // let sender_vk = self.party_verifying_key(sender_id).unwrap();
        let receiver_vk = receiver
            .and_then(|p| self.party_verifying_key(p)) // FIXME
            .map(|vk| vk.as_bytes());

        MsgId::new(self.instance(), sender_vk.as_bytes(), receiver_vk, tag)
    }

    ///
    pub fn decode<F>(
        message_buffer: &mut [u8],
        instance: &InstanceId,
        verify_key: &VerifyingKey,
        signing_key: SigningKey,
        user_validator: F,
    ) -> Option<ValidatedSetup>
    where
        F: FnOnce(&Setup, &Message) -> Option<Keyshare>,
    {
        let setup_msg = Message::from_buffer(message_buffer).ok()?;

        // let setup = setup_msg.verify_and_decode(verify_key).ok()?;

        let reader = setup_msg.verify(verify_key).ok()?;

        let setup: Setup = MessageReader::decode(reader).ok()?;

        let vk = signing_key.verifying_key();

        // one of PK is our one
        let party_idx = setup.parties.iter().position(|pk| &vk == pk)?;

        let keyshare = user_validator(&setup, &setup_msg)?;

        Some(ValidatedSetup {
            setup,
            instance: *instance,
            signing_key,
            keyshare,
            party_idx,
        })
    }

    /// Signing key for this Setup
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }
}

///
pub struct SetupBuilder {
    public_key: AffinePoint,
    parties: Vec<VerifyingKey>,
}

impl SetupBuilder {
    /// Create new builder
    pub fn new(public_key: &AffinePoint) -> SetupBuilder {
        Self {
            public_key: public_key.clone(),
            parties: vec![],
        }
    }

    /// Add party witj given rank and public key
    pub fn add_party(mut self, vk: VerifyingKey) -> Self {
        self.parties.push(vk);
        self
    }

    ///
    pub fn build(self, id: &MsgId, ttl: u32, key: &SigningKey) -> Option<Vec<u8>> {
        let Self {
            public_key,
            parties,
        } = self;

        if parties.len() >= u8::MAX as usize {
            return None;
        }

        let t = parties.len() as u8;

        if t < 2 {
            return None;
        }

        let setup = Setup {
            public_key,
            parties,
        };

        let mut msg = Builder::<Signed>::allocate(id, ttl, &setup);

        msg.encode(&setup).ok()?;

        msg.sign(key).ok()
    }
}
