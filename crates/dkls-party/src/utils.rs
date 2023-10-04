use k256::{
    elliptic_curve::group::GroupEncoding, AffinePoint, CompressedPoint,
};

use std::path::PathBuf;

use hex::FromHex;

use sl_mpc_mate::message::*;

pub fn parse_instance_bytes(s: &str) -> anyhow::Result<[u8; 32]> {
    Ok(<[u8; 32]>::from_hex(s)?)
}

pub fn parse_instance_id(s: &str) -> anyhow::Result<InstanceId> {
    Ok(InstanceId::from(parse_instance_bytes(s)?))
}

pub fn parse_sign_message(s: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = <[u8; 32]>::from_hex(s)?;

    Ok(bytes)
}

pub fn load_signing_key(p: PathBuf) -> anyhow::Result<SigningKey> {
    let bytes = std::fs::read(p)?;
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
        anyhow::Error::msg("invalid length of signing key file")
    })?;

    Ok(SigningKey::from_bytes(&bytes))
}

/// Parse hex string into VerifyingKey
pub fn parse_verifying_key(s: &str) -> anyhow::Result<VerifyingKey> {
    tracing::info!("parse VK {:?}", s);
    Ok(VerifyingKey::from_bytes(&<[u8; 32]>::from_hex(s)?)?)
}

pub fn load_verifying_key(p: PathBuf) -> anyhow::Result<VerifyingKey> {
    let content = std::fs::read_to_string(p)?;

    Ok(VerifyingKey::from_bytes(&<[u8; 32]>::from_hex(
        content.trim(),
    )?)?)
}

pub fn parse_affine_point(s: &str) -> anyhow::Result<AffinePoint> {
    let bytes = CompressedPoint::from(<[u8; 33]>::from_hex(s)?);

    let pk = AffinePoint::from_bytes(&bytes);

    if bool::from(pk.is_some()) {
        Ok(pk.unwrap())
    } else {
        Err(anyhow::Error::msg("cant parse AffinePoint"))
    }
}
