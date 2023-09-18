#![allow(dead_code)]

use std::str::FromStr;

use rand::prelude::*;
use tracing_subscriber;

use serde::{Deserialize, Serialize};
use url::Url;

use sl_mpc_mate::message::*;

mod flags;
mod keygen;
mod serve;
mod sign;
mod utils;

use flags::{Dkls23Party, Dkls23PartyCmd};

/// Hash function used for signing.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq)]
pub enum SignHashFn {
    /// Keccak256 hash function.
    Keccak256,

    /// SHA-256 hash function.
    Sha256,

    /// Double SHA-256 hash. SHA-256 is applied twice like in Bitcoin.
    Sha256D,

    /// Sign the message directly without hashing.
    /// The message must be 32 bytes long.
    NoHash,
}

///
#[derive(Debug)]
pub struct SignHashParseError(String);

impl FromStr for SignHashFn {
    type Err = SignHashParseError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "SHA256" => Ok(SignHashFn::Sha256),
            "SHA256D" => Ok(SignHashFn::Sha256D),
            "KECCAK256" => Ok(SignHashFn::Keccak256),
            "NONE" => Ok(SignHashFn::NoHash),

            _ => Err(SignHashParseError(String::from(s))),
        }
    }
}

impl std::fmt::Display for SignHashParseError {
    fn fmt(
        &self,
        fmt: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        write!(fmt, "SignHashParseError: {}", self.0)
    }
}

fn default_coord() -> Url {
    Url::parse("wss://msg-relay.fly.dev").unwrap()
}

fn gen_party_keys(opts: flags::GenPartyKeys) -> anyhow::Result<()> {
    let mut rng = rand::thread_rng();

    let setup_sk = SigningKey::from_bytes(&rng.gen());

    std::fs::write(opts.output, &setup_sk.to_bytes())?;

    Ok(())
}

fn load_party_keys(opts: flags::LoadPartyKeys) -> anyhow::Result<()> {
    let bytes = std::fs::read(opts.input)?;
    let sk = SigningKey::from_bytes(
        &bytes
            .try_into()
            .map_err(|_| anyhow::Error::msg("bad secket key"))?,
    );

    if opts.public {
        let vk = sk.verifying_key();
        println!("{}", hex::encode(vk.to_bytes()));
    } else {
        println!("{}", hex::encode(sk.to_bytes()));
    }

    Ok(())
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let flags = Dkls23Party::from_env_or_exit();

    match flags.subcommand {
        Dkls23PartyCmd::KeygenSetup(opts) => keygen::setup(opts).await,
        Dkls23PartyCmd::GenPartyKeys(opts) => gen_party_keys(opts),
        Dkls23PartyCmd::LoadPartyKeys(opts) => load_party_keys(opts),
        Dkls23PartyCmd::KeyGen(opts) => keygen::run_keygen(opts).await,
        Dkls23PartyCmd::SharePubkey(opts) => {
            keygen::run_share_pubkey(opts)
        }
        Dkls23PartyCmd::SignSetup(opts) => sign::setup(opts).await,
        Dkls23PartyCmd::SignGen(opts) => sign::run_sign(opts).await,
        Dkls23PartyCmd::Serve(opts) => serve::run(opts).await,
    }
}
