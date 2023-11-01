use std::{cell::RefCell, rc::Rc};

use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

use js_sys::Promise;

use k256::elliptic_curve::group::GroupEncoding;

use dkls23::{
    keygen,
    setup::{sign::DecodedSetup, SETUP_MESSAGE_TAG},
    sign,
};

use crate::{
    abort::AbortGuard,
    keyshare::Keyshare,
    relay::{msg_relay_connect, MsgRelay},
    utils::set_panic_hook,
};

use super::*;

#[wasm_bindgen]
pub struct SignSetup {
    setup: Rc<RefCell<Option<DecodedSetup>>>,
}

#[wasm_bindgen]
impl SignSetup {
    #[wasm_bindgen]
    pub fn threshold(&self) -> u8 {
        self.setup.borrow_mut().as_ref().unwrap_throw().threshold()
    }

    #[wasm_bindgen(js_name = verifyingKey)]
    pub fn verifying_key(&self, party: u32) -> Result<Uint8Array, JsError> {
        let vk = self
            .setup
            .borrow_mut()
            .as_ref()
            .unwrap_throw()
            .party_verifying_key(party as usize)
            .cloned()
            .ok_or_else(|| JsError::new("invalid party"))?;

        Ok(Uint8Array::from(vk.as_bytes().as_slice()))
    }

    #[wasm_bindgen(js_name = publicKey)]
    pub fn public_key(&self) -> Uint8Array {
        let pk = self
            .setup
            .borrow_mut()
            .as_ref()
            .unwrap_throw()
            .public_key()
            .to_bytes();

        Uint8Array::from(pk.as_ref())
    }
}

async fn validate_setup<R: Relay>(
    msg_relay: &mut BufferedMsgRelay<R>,
    instance: InstanceId,
    setup_vk: &VerifyingKey,
    validate: &js_sys::Function,
) -> (DecodedSetup, keygen::Keyshare) {
    let msg_id = MsgId::new(&instance, setup_vk.as_bytes(), None, SETUP_MESSAGE_TAG);

    let mut setup_msg = msg_relay
        .recv(&msg_id, 10)
        .await
        .expect_throw("recv setup msg");

    let decoded_setup = DecodedSetup::decode(instance, &mut setup_msg, setup_vk)
        .expect_throw("decode setup message");

    let cell = Rc::new(RefCell::new(Some(decoded_setup)));

    let js_decoded_setup = From::<SignSetup>::from(SignSetup {
        setup: Rc::clone(&cell), // create second reference
    });

    let share = JsFuture::from(
        validate
            .call1(&JsValue::null(), &js_decoded_setup)
            .expect_throw("validator failed")
            .dyn_into::<Promise>()
            .expect_throw("validator should return Promise"),
    )
    .await
    .expect_throw("validation failed");

    tracing::info!("debug(share)  = {:?}", share);

    let share = keyshare::keyshareCast(share);

    let t = cell.borrow_mut().take();

    (t.unwrap_throw(), share.clone_inner())
}

#[wasm_bindgen]
pub async fn init_dsg(
    opts: JsValue,
    signing_key: &str,
    endpoint: &str,
    seed: &str,
    keyshare: &Keyshare,
) -> Result<Uint8Array, JsError> {
    set_panic_hook();
    let (mut setup_msg, instance, _, setup_vk) = setup::dsg_setup_inner(opts)?;
    let mut abort = AbortGuard::new();

    let signing_key = SigningKey::from_bytes(&parse_instance_bytes(signing_key)?);
    let seed = parse_instance_bytes(seed)?;

    let ws = msg_relay_connect(endpoint, abort.signal()).await?;
    let mut msg_relay = MsgRelay::new(ws);

    msg_relay
        .send(setup_msg.clone())
        .await
        .expect_throw("send setup message");

    let decoded = DecodedSetup::decode(instance, &mut setup_msg, &setup_vk).unwrap();

    let setup =
        sign::ValidatedSetup::validate_decoded_setup(decoded, signing_key, keyshare.clone_inner())
            .unwrap();

    abort.deadline(setup.ttl().as_millis() as u32);

    let sign = sign::run(setup, seed, msg_relay).await?;

    Ok(Uint8Array::from(sign.to_der().as_bytes()))
}

#[wasm_bindgen]
pub async fn join_dsg(
    instance: &str,
    setup_vk: &str,
    signing_key: &str,
    endpoint: &str,
    seed: &str,
    validate: JsValue,
) -> Result<Uint8Array, JsError> {
    set_panic_hook();

    let mut abort = AbortGuard::new();

    let instance = parse_instance_id(instance)?;
    let setup_vk = VerifyingKey::from_bytes(&parse_instance_bytes(setup_vk)?).unwrap_throw();
    let signing_key = SigningKey::from_bytes(&parse_instance_bytes(signing_key)?);
    let seed = parse_instance_bytes(seed)?;

    let ws = msg_relay_connect(endpoint, abort.signal()).await?;
    let msg_relay = MsgRelay::new(ws);
    let mut msg_relay = BufferedMsgRelay::new(msg_relay);

    let validate = validate.dyn_ref().expect_throw("");

    let (decoded, share) = validate_setup(&mut msg_relay, instance, &setup_vk, validate).await;

    let setup =
        sign::ValidatedSetup::validate_decoded_setup(decoded, signing_key, share).unwrap_throw();

    abort.deadline(setup.ttl().as_millis() as u32);

    let sign = sign::run(setup, seed, msg_relay).await.unwrap_throw();

    Ok(Uint8Array::from(sign.to_der().as_bytes()))
}
