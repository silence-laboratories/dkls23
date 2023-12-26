use serde::Deserialize;

use wasm_bindgen::prelude::*;

use js_sys::Uint8Array;

use derivation_path::DerivationPath;

use k256::{
    elliptic_curve::{generic_array::GenericArray, group::GroupEncoding},
    AffinePoint,
};

use sl_mpc_mate::message::*;

use dkls23::setup;

#[derive(Deserialize)]
pub struct PartyDefs {
    pub rank: Option<u8>,

    #[serde(with = "serde_bytes", rename = "publicKey")]
    pub public_key: Vec<u8>,
}

#[derive(Deserialize)]
pub struct KeygenSetupOpts {
    #[serde(with = "serde_bytes")]
    instance: Vec<u8>,

    #[serde(with = "serde_bytes", rename = "signingKey")]
    signing_key: Vec<u8>,

    parties: Vec<PartyDefs>,

    threshold: u8,

    ttl: u32,
}

#[wasm_bindgen(js_name = dkgSetupMessage)]
pub fn dkg_setup_msg(opts: JsValue) -> Result<Uint8Array, JsError> {
    let (msg, _, _, _) = dkg_setup_inner(opts)?;
    Ok(Uint8Array::from(msg.as_ref()))
}

pub fn dkg_setup_inner(
    opts: JsValue,
) -> Result<(Vec<u8>, InstanceId, MsgId, VerifyingKey), JsError> {
    let opts: KeygenSetupOpts = serde_wasm_bindgen::from_value(opts)?;

    let instance: [u8; 32] = opts
        .instance
        .try_into()
        .expect_throw("bad opts.instance size");
    let instance = InstanceId::from(instance);

    let sk = SigningKey::from_bytes(&opts.signing_key.try_into().expect_throw("SK size"));
    let vk = sk.verifying_key();

    let msg_id = MsgId::new(&instance, vk.as_bytes(), None, setup::SETUP_MESSAGE_TAG);

    let mut builder = setup::keygen::SetupBuilder::new();

    for party in opts.parties {
        let rank = party.rank.unwrap_or(0);
        let vk = party.public_key;
        let vk = VerifyingKey::from_bytes(&vk.try_into().expect_throw("party PK size"))
            .expect_throw("party PK");
        builder = builder.add_party(rank, &vk);
    }

    let msg = builder
        .build(&msg_id, opts.ttl, opts.threshold, &sk)
        .ok_or_else(|| JsError::new("cant build DKG setup message"))?;

    Ok((msg, instance, msg_id, vk))
}

#[derive(Deserialize)]
pub struct PartyVerifyingKey {
    #[serde(with = "serde_bytes", rename = "publicKey")]
    pub public_key: Vec<u8>,
}

#[derive(Deserialize)]
pub struct SignSetupOpts {
    #[serde(with = "serde_bytes")]
    instance: Vec<u8>,

    #[serde(with = "serde_bytes", rename = "signingKey")]
    signing_key: Vec<u8>,

    #[serde(with = "serde_bytes", rename = "publicKey")]
    public_key: Vec<u8>,

    parties: Vec<PartyVerifyingKey>,

    #[serde(with = "serde_bytes")]
    message: Vec<u8>,

    #[serde(rename = "chainPath")]
    chain_path: Option<String>,

    ttl: u32,
}

pub fn dsg_setup_inner(
    opts: JsValue,
) -> Result<(Vec<u8>, InstanceId, MsgId, VerifyingKey), JsError> {
    let opts: SignSetupOpts = serde_wasm_bindgen::from_value(opts)?;

    let instance: [u8; 32] = opts
        .instance
        .try_into()
        .expect_throw("bad opts.instance size");
    let instance = InstanceId::from(instance);

    let sk = SigningKey::from_bytes(&opts.signing_key.try_into().expect_throw("SK size"));
    let vk = sk.verifying_key();

    let msg_id = MsgId::new(&instance, vk.as_bytes(), None, setup::SETUP_MESSAGE_TAG);

    let public_key = GenericArray::from_slice(&opts.public_key);
    let public_key = AffinePoint::from_bytes(public_key);

    if public_key.is_none().into() {
        return Err(JsError::new("Invalid puiblic key"));
    }

    let mut builder = setup::sign::SetupBuilder::new(&public_key.unwrap());

    for party in opts.parties {
        let vk = party.public_key.try_into().expect_throw("party PK size");
        builder = builder.add_party(VerifyingKey::from_bytes(&vk).expect_throw("party PK"));
    }

    let chain_path: Option<DerivationPath> = opts.chain_path.map(|p| p.parse().unwrap_throw());

    let msg = builder
        .with_sha256(opts.message)
        .chain_path(chain_path.as_ref())
        .build(&msg_id, opts.ttl, &sk)
        .ok_or_else(|| JsError::new("cant build DSG setup message"))?;

    Ok((msg, instance, msg_id, vk))
}

#[wasm_bindgen(js_name = dsgSetupMessage)]
pub fn dsg_setup_msg(opts: JsValue) -> Result<Uint8Array, JsError> {
    let (msg, _, _, _) = dsg_setup_inner(opts)?;
    Ok(Uint8Array::from(msg.as_ref()))
}
