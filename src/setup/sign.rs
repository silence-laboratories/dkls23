use std::time::Duration;

use sl_mpc_mate::message::*;

use arrayref::array_ref;

use crate::setup::Magic;

/// A key generation setup message.
///
/// struct SetupMessage {
///     uint32      algo;
///     uint8       t;
///     partyid     u8[t]
///     pkey        opaque<32*t>;
/// }
///
pub struct Setup {
    parties: Vec<(u8, [u8; PUBLIC_KEY_LENGTH])>,
}

#[rustfmt::skip]
fn setup_payload_size(t: u8) -> usize {
    let t = t as usize;
    4 +                   // algo, setup message "magic"
    1 +                   // T
    t +                   // party IDs
    PUBLIC_KEY_LENGTH * t // public key of each party
}

impl Setup {
    ///
    pub fn threshold(&self) -> u8 {
        self.parties.len() as u8
    }

    ///
    pub fn public_key(&self, party: u8) -> Option<&[u8; PUBLIC_KEY_LENGTH]> {
        self.parties.get(party as usize).map(|(_, pk)| pk)
    }
}

///
pub struct ValidatedSetup {
    setup: Setup,
    signing_key: SigningKey,
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
    pub fn decode<F>(
        message_buffer: &mut [u8],
        signing_key: SigningKey,
        user_validator: F,
    ) -> Option<ValidatedSetup>
    where
        F: FnOnce(&Setup, u8, &Message<Signed>) -> bool,
    {
        let mut setup_msg = Message::<Signed>::from_buffer(message_buffer).ok()?;

        if setup_msg.decode::<u32>().ok()? != Magic::DSG as u32 {
            return None;
        }

        let t: u8 = setup_msg.decode().ok()?;

        if t < 2 {
            return None;
        }

        let (ids, pk) = setup_msg
            .slice(t as usize * (1 + PUBLIC_KEY_LENGTH))
            .ok()?
            .split_at(t as usize);

        let pk = |p: usize| {
            let start = p * PUBLIC_KEY_LENGTH;
            array_ref![pk, start, PUBLIC_KEY_LENGTH]
        };

        let setup = Setup {
            parties: (0..t as usize).map(|p| (ids[p], *pk(p))).collect(),
        };

        if !user_validator(&setup, 0, &setup_msg) {
            return None;
        }

        Some(ValidatedSetup { setup, signing_key })
    }

    /// Signing key for this Setup
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }
}

///
pub struct SetupBuilder {
    parties: Vec<(u8, [u8; PUBLIC_KEY_LENGTH])>,
}

impl SetupBuilder {
    /// Create new builder
    pub fn new() -> SetupBuilder {
        Self { parties: vec![] }
    }

    /// Add party witj given rank and public key
    pub fn add_party(mut self, rank: u8, pk: &[u8; PUBLIC_KEY_LENGTH]) -> Self {
        self.parties.push((rank, *pk));
        self
    }

    ///
    pub fn build(self, id: MsgId, ttl: u32, t: u8, key: &SigningKey) -> Option<Vec<u8>> {
        if self.parties.len() >= u8::MAX as usize {
            return None;
        }

        let n = self.parties.len() as u8;

        if t < 2 || t >= n {
            return None;
        }

        let mut msg =
            Builder::<Signed>::allocate(id, Duration::new(ttl as u64, 0), setup_payload_size(n));

        let magic = Magic::DKG as u32;
        msg.encode(&magic.to_le_bytes()).ok()?;
        msg.encode(&n).ok()?;
        msg.encode(&t).ok()?;

        for (rank, _) in &self.parties {
            msg.encode(rank).ok()?;
        }

        for (_, pk) in &self.parties {
            msg.encode(pk).ok()?;
        }

        msg.sign(key).ok()
    }
}
