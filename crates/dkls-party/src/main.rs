use std::str::FromStr;

use serde::{Deserialize, Serialize};
use url::Url;

mod coord;
mod flags;
mod keygen;
mod serve;
mod sign;

use coord::{Coordinator, SessionConfig};
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
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(fmt, "SignHashParseError: {}", self.0)
    }
}

fn default_coord() -> Url {
    Url::parse("https://coord.fly.dev").unwrap()
}

async fn run_keysess(opts: flags::KeySess) -> anyhow::Result<()> {
    let ids = Coordinator::register(
        opts.coordinator.unwrap_or_else(default_coord),
        opts.n,
        6 + 1,
        opts.lifetime,
        None,
    )
    .await?;

    ids.iter().for_each(|sid| println!("{sid}"));

    Ok(())
}

async fn run_signsess(opts: flags::SignSess) -> anyhow::Result<()> {
    let ids = Coordinator::register(
        opts.coordinator.unwrap_or_else(default_coord),
        opts.t,
        5,
        opts.lifetime,
        Some(opts.message),
    )
    .await?;

    ids.iter().for_each(|sid| println!("{sid}"));

    Ok(())
}

async fn run_session(opts: flags::Session) -> anyhow::Result<()> {
    let coord = Coordinator::new(
        opts.coordinator.unwrap_or_else(default_coord),
        &opts.id,
        5,
        None,
    );

    let SessionConfig {
        parties,
        rounds,
        remains,
        signmsg,
    } = coord.session_config().await?;

    println!("parties: {parties}");
    println!("rounds:  {rounds}");
    println!("remains: {remains}");
    println!("signmsg: {signmsg:?}");

    Ok(())
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let flags = Dkls23Party::from_env_or_exit();

    env_logger::init();

    match flags.subcommand {
        Dkls23PartyCmd::PartyKeys(opts) => keygen::party_keys(opts),
        Dkls23PartyCmd::KeyGen(opts) => keygen::run_keygen(opts).await,
        Dkls23PartyCmd::SharePubkey(opts) => keygen::run_share_pubkey(opts),
        Dkls23PartyCmd::SignGen(opts) => sign::run_sign(opts).await,
        Dkls23PartyCmd::KeySess(opts) => run_keysess(opts).await,
        Dkls23PartyCmd::SignSess(opts) => run_signsess(opts).await,
        Dkls23PartyCmd::Session(opts) => run_session(opts).await,
        Dkls23PartyCmd::Serve(opts) => serve::run(opts).await,
    }
}
