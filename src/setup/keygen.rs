//!
//!
use std::time::Duration;

use bincode::{
    de::{read::Reader, Decoder},
    enc::Encoder,
    error::{DecodeError, EncodeError},
    Decode, Encode,
};

use sl_mpc_mate::message::*;

use crate::setup::{Magic, PartyInfo};

/// Distributed key generation setup message.
///
/// struct SetupMessage {
///     uint32      algo;
///     uint8       n;
///     uint8       t;
///     uint8       ranks<2..n>;
///     pkey        opaque<64..32*n>;
/// }
///
/// A reference to this structure will be passed
/// to a user supplied validation closure.
///
#[derive(Clone)]
pub struct Setup {
    t: u8,
    parties: Vec<(u8, VerifyingKey)>,
}

impl Encode for Setup {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        (Magic::DKG as u32).encode(encoder)?;

        (self.parties.len() as u8).encode(encoder)?;
        self.t.encode(encoder)?;

        for (r, _) in &self.parties {
            r.encode(encoder)?;
        }

        for (_, pk) in &self.parties {
            Opaque::from(pk.to_bytes()).encode(encoder)?;
        }

        Ok(())
    }
}

impl Decode for Setup {
    fn decode<D: Decoder>(decoder: &mut D) -> Result<Self, DecodeError> {
        let magic = u32::decode(decoder)?;

        if magic != Magic::DKG as u32 {
            return Err(DecodeError::Other("bag magic"));
        }

        let n = u8::decode(decoder)?;
        let t = u8::decode(decoder)?;

        if t < 2 || t > n {
            return Err(DecodeError::Other("bad T and/or N"));
        }

        let mut ranks = [0u8; 256];

        decoder.reader().read(&mut ranks[..n as usize])?;

        let ranks = &ranks[..n as usize];

        let max_rank = ranks.iter().cloned().max().unwrap(); // n > 0

        if max_rank >= t {
            return Err(DecodeError::Other("invalid max rank"));
        }

        // make sure there is no holes ranks
        for r in max_rank..0 {
            ranks
                .iter()
                .find(|pr| **pr == r)
                .ok_or(DecodeError::Other("rank hole"))?;
        }

        let mut parties = Vec::with_capacity(n as usize);

        for rank in ranks {
            let pk = Opaque::<[u8; PUBLIC_KEY_LENGTH]>::decode(decoder)?.0;

            let pk = VerifyingKey::from_bytes(&pk).map_err(|_| DecodeError::Other("bad PK"))?;

            parties.push((*rank, pk));
        }

        // all public keys are unique
        for i in 0..n as usize - 1 {
            let (_, ki) = &parties[i];

            for (_, kj) in &parties[i+1..] {
                if ki == kj {
                    // panic!("ttt {}", i);
                    return Err(DecodeError::Other("PK dup"));
                }
            }
        }

        Ok(Self { t, parties })
    }
}

impl Setup {
    /// Returns totoal number of participants
    pub fn participants(&self) -> u8 {
        self.parties.len() as u8
    }

    ///
    pub fn threshold(&self) -> u8 {
        self.t
    }

    ///
    pub fn party_rank(&self, party: u8) -> Option<u8> {
        self.parties.get(party as usize).map(|(rank, _)| *rank)
    }

    ///
    pub fn party_verifying_key(&self, party: u8) -> Option<&VerifyingKey> {
        self.parties.get(party as usize).map(|(_, pk)| pk)
    }
}

/// ValidatedSetup stucture ties together a validated instance of the Setup
/// message, a SigningKey pair corresponding to one of parties PK enumerated
/// in the setup message and it party's ID, or a unique index among all
/// particupants.
///
#[derive(Clone)]
pub struct ValidatedSetup {
    setup: Setup,
    instance: InstanceId,
    signing_key: SigningKey,
    party_id: u8,
    ttl: Duration,
}

impl std::ops::Deref for ValidatedSetup {
    type Target = Setup;

    fn deref(&self) -> &Self::Target {
        &self.setup
    }
}

impl PartyInfo for ValidatedSetup {
    fn instance(&self) -> &InstanceId {
        &self.instance
    }

    fn party_id(&self) -> u8 {
        self.party_id
    }

    fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
}

impl ValidatedSetup {
    /// TTL of the setup message
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Own rank
    pub fn rank(&self) -> u8 {
        self.party_rank(self.party_id).unwrap()
    }

    ///
    pub fn all_party_ranks(&self) -> Vec<(u8, u8)> {
        self.parties
            .iter()
            .enumerate()
            // TODO: usize as u8 might be a problem if there are more than 255 parties
            .map(|(id, (rank, _))| (id as u8, *rank))
            .collect()
    }

    ///
    pub fn other_parties_iter(&self) -> impl Iterator<Item = (u8, &VerifyingKey)> {
        self.setup
            .parties
            .iter()
            .enumerate()
            .filter(|(idx, _)| *idx as u8 != self.party_id)
            .map(|(idx, (_rank, vk))| (idx as u8, vk))
    }

    /// Generate ID of a message from this party to some other (or broadcast)
    pub fn msg_id(&self, receiver: Option<u8>, tag: MessageTag) -> MsgId {
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
        receiver: Option<u8>,
        tag: MessageTag,
    ) -> MsgId {
        // let sender_vk = self.party_verifying_key(sender_id).unwrap();
        let receiver_vk = receiver
            .and_then(|p| self.party_verifying_key(p)) // FIXME
            .map(|vk| vk.as_bytes());

        MsgId::new(self.instance(), sender_vk.as_bytes(), receiver_vk, tag)
    }

    ///
    /// Decode and validate a raw setup message.
    ///
    /// Ensure that setup message contains a public key
    /// from singing_key pair passed as the second parameter.
    ///
    /// Perform all common validation, construct a Setup structure
    /// and pass it to a suer supplied validation closure.
    ///
    pub fn decode<F>(
        message_buffer: &mut [u8],
        instance: &InstanceId,
        verify_key: &VerifyingKey,
        signing_key: SigningKey,
        user_validator: F,
    ) -> Option<ValidatedSetup>
    where
        F: FnOnce(&Setup, u8, &Message) -> bool,
    {
        let hdr = MsgHdr::from(message_buffer)?;

        let setup_msg = Message::from_buffer(message_buffer).ok()?;

        let reader = setup_msg.verify(verify_key).ok()?;

        let setup: Setup = MessageReader::decode(reader).ok()?;

        let vk = signing_key.verifying_key();

        let party_id = setup.parties.iter().position(|(_, pk)| pk == &vk)? as u8;

        if !user_validator(&setup, party_id, &setup_msg) {
            return None;
        }

        Some(ValidatedSetup {
            setup,
            instance: *instance,
            signing_key,
            party_id,
            ttl: hdr.ttl,
        })
    }
}

///
#[derive(Default)]
pub struct SetupBuilder {
    parties: Vec<(u8, VerifyingKey)>,
}

impl SetupBuilder {
    /// Create new builder
    pub fn new() -> SetupBuilder {
        Self { parties: vec![] }
    }

    /// Add party witj given rank and public key
    pub fn add_party(mut self, rank: u8, vk: &VerifyingKey) -> Self {
        self.parties.push((rank, *vk));
        self
    }

    ///
    pub fn build(self, id: &MsgId, ttl: u32, t: u8, key: &SigningKey) -> Option<Vec<u8>> {
        if self.parties.len() >= u8::MAX as usize {
            return None;
        }

        let n = self.parties.len() as u8;

        if t < 2 || t > n {
            return None;
        }

        let setup = Setup {
            t,
            parties: self.parties,
        };

        let mut msg = Builder::<Signed>::allocate(id, ttl, &setup);

        msg.encode(&setup).ok()?;

        msg.sign(key).ok()
    }
}

#[cfg(test)]
mod tests {
    use std::array;

    use super::*;
    use crate::setup::SETUP_MESSAGE_TAG;

    #[test]
    fn keygen() {
        let inst = InstanceId::from([0; 32]);
        let setup_signing_key = SigningKey::from_bytes(&rand::random());

        let sk: [_; 3] = array::from_fn(|_| SigningKey::from_bytes(&rand::random()));

        let id = MsgId::broadcast(
            &inst,
            setup_signing_key.verifying_key().as_bytes(),
            SETUP_MESSAGE_TAG,
        );

        let mut msg = SetupBuilder::new()
            .add_party(0, &sk[0].verifying_key())
            .add_party(0, &sk[1].verifying_key())
            .add_party(0, &sk[2].verifying_key())
            .build(&id, 100, 2, &setup_signing_key)
            .unwrap();

        let setup = ValidatedSetup::decode(
            &mut msg,
            &inst,
            &setup_signing_key.verifying_key(),
            sk[0].clone(),
            |setup, part_id, msg| {
                msg.verify(&setup_signing_key.verifying_key()).is_ok()
                    && setup.participants() == 3
                    && setup.threshold() == 2
                    && part_id == 0
                    && setup.party_verifying_key(part_id) == Some(&sk[0].verifying_key())
            },
        )
        .unwrap();

        assert_eq!(setup.threshold(), 2);
        assert_eq!(setup.participants(), 3);
        assert_eq!(setup.party_verifying_key(0), Some(&sk[0].verifying_key()));
        assert_eq!(setup.party_verifying_key(1), Some(&sk[1].verifying_key()));
        assert_eq!(setup.party_verifying_key(2), Some(&sk[2].verifying_key()));
    }
}
