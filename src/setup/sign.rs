use std::time::Duration;
use std::{fmt::Formatter, str::FromStr};

use k256::{elliptic_curve::group::GroupEncoding, AffinePoint};
use sha2::{Digest, Sha256};

use bincode::{
    de::Decoder,
    enc::{write::Writer, Encoder},
    error::{DecodeError, EncodeError},
    Decode, Encode,
};

use sl_mpc_mate::{message::*, HashBytes};

use crate::{
    keygen::Keyshare,
    setup::{HashAlgo, Magic},
};

use derivation_path::DerivationPath;

/// A key generation setup message.
///
/// struct SetupMessage {
///     uint32      algo;
///     t           u8;
///     publicKey   u8[33];  // affine point
///     pkey        opaque<32*t>;
///     hash_also   u32;
///     message     Vec<u8>;
///     chain_path  String;
/// }
///
#[derive(Clone, Debug)]
pub struct Setup {
    public_key: AffinePoint,
    chain_path: DerivationPath,
    parties: Vec<VerifyingKey>,
    hash_algo: HashAlgo,
    message: Vec<u8>,
}

impl Encode for Setup {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        (Magic::DSG as u32).encode(encoder)?;

        (self.parties.len() as u8).encode(encoder)?;

        encoder.writer().write(&self.public_key.to_bytes())?;

        for pk in &self.parties {
            encoder.writer().write(pk.as_bytes())?;
        }

        (self.hash_algo as u32).encode(encoder)?;

        self.message.encode(encoder)?;

        self.chain_path.to_string().encode(encoder)?;

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
            let pk = <[u8; PUBLIC_KEY_LENGTH]>::decode(decoder)?;
            let pk =
                VerifyingKey::from_bytes(&pk).map_err(|_| DecodeError::Other("bad party PK"))?;

            parties.push(pk);
        }

        let hash_algo = match <u32>::decode(decoder)? {
            0 => HashAlgo::HashU32,
            1 => HashAlgo::Sha256,
            2 => HashAlgo::Sha256D,
            _ => return Err(DecodeError::Other("bad HashAlgo")),
        };

        let message = <Vec<u8>>::decode(decoder)?;

        if hash_algo == HashAlgo::HashU32 && message.len() != 32 {
            return Err(DecodeError::Other("bad message length"));
        }

        let chain_path = DerivationPath::from_str(&String::decode(decoder)?)
            .map_err(|_| DecodeError::Other("bad chain path"))?;

        Ok(Setup {
            parties,
            public_key,
            chain_path,
            hash_algo,
            message,
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

    /// Return hash algorithm
    pub fn hash_algo(&self) -> HashAlgo {
        self.hash_algo
    }

    /// Return hash on a message
    pub fn hash(&self) -> HashBytes {
        match self.hash_algo {
            HashAlgo::HashU32 => {
                let mut bytes = [0u8; 32];
                // Decode::decode() validates length of message
                bytes.copy_from_slice(&self.message[..32]);
                HashBytes::new(bytes)
            }

            HashAlgo::Sha256 => {
                HashBytes::new(Sha256::new().chain_update(&self.message).finalize().into())
            }

            _ => unimplemented!(),
        }
    }

    /// Return the public key.
    pub fn public_key(&self) -> &AffinePoint {
        &self.public_key
    }

    /// Return the chain path.
    pub fn chain_path(&self) -> &DerivationPath {
        &self.chain_path
    }
}

///
pub struct ValidatedSetup {
    instance: InstanceId,
    setup: Setup,
    signing_key: SigningKey,
    keyshare: Keyshare,
    party_idx: usize,
    ttl: Duration,
}

impl std::fmt::Debug for ValidatedSetup {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValidatedSetup")
            .field("instance", &self.instance)
            .field("party_id", &self.keyshare.party_id)
            .field("party_idx", &self.party_idx)
            .finish()
    }
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

    /// TTL of the setup message
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    ///
    pub fn keyshare(&self) -> &Keyshare {
        &self.keyshare
    }

    /// Return the chain path.
    pub fn chain_path(&self) -> &DerivationPath {
        &self.setup.chain_path
    }

    ///
    pub fn party_idx(&self) -> usize {
        self.party_idx
    }

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
        let receiver_vk = receiver
            .and_then(|p| self.party_verifying_key(p))
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
        let hdr = MsgHdr::from(message_buffer)?;

        let setup_msg = Message::from_buffer(message_buffer).ok()?;

        let reader = setup_msg.verify(verify_key).ok()?;

        let setup: Setup = MessageReader::decode(reader).ok()?;

        let vk = signing_key.verifying_key();

        // one of PK is our own
        let party_idx = setup.parties.iter().position(|pk| &vk == pk)?;

        let keyshare = user_validator(&setup, &setup_msg)?;

        Some(ValidatedSetup {
            setup,
            instance: *instance,
            signing_key,
            keyshare,
            party_idx,
            ttl: hdr.ttl,
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
    chain_path: Option<DerivationPath>,
    parties: Vec<VerifyingKey>,
    message: Vec<u8>,
    hash: Option<HashAlgo>,
}

impl SetupBuilder {
    /// Create new builder
    pub fn new(public_key: &AffinePoint) -> SetupBuilder {
        Self {
            public_key: *public_key,
            chain_path: None,
            parties: vec![],
            message: vec![],
            hash: None,
        }
    }

    /// Set derivation path
    pub fn chain_path(mut self, chain_path: Option<&DerivationPath>) -> Self {
        self.chain_path = chain_path.cloned();
        self
    }

    /// Add party witj given rank and public key
    pub fn add_party(mut self, vk: VerifyingKey) -> Self {
        self.parties.push(vk);
        self
    }

    ///
    pub fn with_hash(mut self, hash: HashBytes) -> Self {
        self.message = Vec::from(&hash[..]);
        self.hash = Some(HashAlgo::HashU32);
        self
    }

    ///
    pub fn with_sha256(mut self, message: Vec<u8>) -> Self {
        self.message = message;
        self.hash = Some(HashAlgo::Sha256);
        self
    }

    ///
    pub fn build(self, id: &MsgId, ttl: u32, key: &SigningKey) -> Option<Vec<u8>> {
        let hash_algo = self.hash?;

        let Self {
            public_key,
            chain_path,
            parties,
            message,
            ..
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
            chain_path: chain_path.unwrap_or_else(|| DerivationPath::from_str("m").unwrap()),
            parties,
            hash_algo,
            message,
        };

        let mut msg = Builder::<Signed>::allocate(id, ttl, &setup);

        msg.encode(&setup).ok()?;

        msg.sign(key).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::setup::SETUP_MESSAGE_TAG;
    use k256::{AffinePoint, Scalar};
    use sl_mpc_mate::ByteArray;
    use std::array;

    #[test]
    fn signgen() {
        let mut rng = rand::thread_rng();

        let inst = InstanceId::from([0; 32]);
        let setup_signing_key = SigningKey::from_bytes(&rand::random());

        let sk: [_; 3] = array::from_fn(|_| SigningKey::from_bytes(&rand::random()));

        let id = MsgId::broadcast(
            &inst,
            setup_signing_key.verifying_key().as_bytes(),
            SETUP_MESSAGE_TAG,
        );

        let pk = AffinePoint::GENERATOR * Scalar::generate_biased(&mut rng);

        let mut message_buffer = SetupBuilder::new(&pk.to_affine())
            .add_party(sk[0].verifying_key())
            .add_party(sk[1].verifying_key())
            .with_hash(ByteArray::random(&mut rng))
            .build(&id, 100, &setup_signing_key)
            .unwrap();

        let hdr = MsgHdr::from(&message_buffer).unwrap();

        assert_eq!(id, hdr.id);

        let setup_msg = Message::from_buffer(&mut message_buffer).unwrap();

        let reader = setup_msg
            .verify(&setup_signing_key.verifying_key())
            .unwrap();

        let setup: Setup = MessageReader::decode(reader).unwrap();

        assert_eq!(setup.threshold(), 2);
        assert_eq!(setup.party_verifying_key(0), Some(&sk[0].verifying_key()));
        assert_eq!(setup.party_verifying_key(1), Some(&sk[1].verifying_key()));
    }
}
