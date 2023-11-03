use std::cell::RefCell;
use std::rc::Rc;

use js_sys::Promise;
use wasm_bindgen::{prelude::*, throw_str};
use wasm_bindgen_futures::JsFuture;

use dkls23::{
    keygen,
    setup::{keygen::DecodedSetup, SETUP_MESSAGE_TAG},
};

use crate::{
    abort::AbortGuard,
    keyshare::Keyshare,
    relay::{msg_relay_connect, MsgRelay},
    utils::set_panic_hook,
};

use super::*;

#[wasm_bindgen]
pub struct KeygenSetup {
    setup: Rc<RefCell<*mut DecodedSetup>>,
}

#[wasm_bindgen]
impl KeygenSetup {
    fn _ref(&self) -> Option<&DecodedSetup> {
        let ptr = unsafe { *self.setup.as_ptr() };
        if ptr.is_null() {
            None
        } else {
            Some(unsafe { &*ptr })
        }
    }

    #[wasm_bindgen]
    pub fn threshold(&self) -> u8 {
        self._ref().unwrap_throw().threshold()
    }

    #[wasm_bindgen]
    pub fn participants(&self) -> u8 {
        self._ref().unwrap_throw().participants()
    }

    #[wasm_bindgen(js_name = verifyingKey)]
    pub fn verifying_key(&self, party: u8) -> Result<Uint8Array, JsError> {
        let vk = self
            ._ref()
            .unwrap_throw()
            .party_verifying_key(party)
            .ok_or_else(|| JsError::new("invalid party"))?;

        Ok(Uint8Array::from(vk.as_bytes().as_slice()))
    }

    #[wasm_bindgen]
    pub fn rank(&self, party: u8) -> Result<u8, JsError> {
        self._ref()
            .unwrap_throw()
            .party_rank(party)
            .ok_or_else(|| JsError::new("invalid party id"))
    }
}

#[wasm_bindgen]
pub async fn init_dkg(
    opts: JsValue,
    signing_key: &str,
    endpoint: &str,
    seed: &str,
) -> Result<Keyshare, JsError> {
    set_panic_hook();

    let (mut setup_msg, instance, _, setup_vk) = setup::dkg_setup_inner(opts)?;

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

    let setup = keygen::ValidatedSetup::validate_decoded_setup(decoded, signing_key).unwrap();

    abort.deadline(setup.ttl().as_millis() as u32);

    let keyshare = keygen::run(setup, seed, msg_relay).await?;

    Ok(Keyshare::new(keyshare))
}

async fn validate_setup<R: Relay>(
    msg_relay: &mut BufferedMsgRelay<R>,
    instance: InstanceId,
    setup_vk: &VerifyingKey,
    validate: Option<&js_sys::Function>,
) -> DecodedSetup {
    let msg_id = MsgId::new(&instance, setup_vk.as_bytes(), None, SETUP_MESSAGE_TAG);

    let mut setup_msg = msg_relay
        .recv(&msg_id, 10)
        .await
        .expect_throw("recv setup msg");

    let mut decoded_setup = DecodedSetup::decode(instance, &mut setup_msg, setup_vk)
        .expect_throw("decode setup message");

    if let Some(validate) = validate {
        // cell contains mutable pointer to stack value
        let cell = Rc::new(RefCell::new(&mut decoded_setup as *mut DecodedSetup));

        let js_decoded_setup = From::<KeygenSetup>::from(KeygenSetup {
            setup: Rc::clone(&cell), // create second reference
        });

        struct DropGuard(Rc<RefCell<*mut DecodedSetup>>);
        impl Drop for DropGuard {
            fn drop(&mut self) {
                // set pointer in the cell to null, so decoded_setup is not
                // referenced anymore.
                *self.0.borrow_mut() = std::ptr::null_mut();
            }
        }

        let _ = DropGuard(cell);

        let ok = JsFuture::from(
            validate
                .call1(&JsValue::null(), &js_decoded_setup)
                .expect_throw("validation failed")
                .dyn_into::<Promise>()
                .expect_throw("validator should return Promise"),
        )
        .await;

        let ok = ok.expect_throw("validation failed").is_truthy();

        if !ok {
            throw_str("DKG setup message validation failed");
        };
    }

    decoded_setup
}

#[wasm_bindgen]
pub async fn join_dkg(
    instance: &str,
    setup_vk: &str,
    signing_key: &str,
    endpoint: &str,
    seed: &str,
    validate: JsValue,
) -> Result<Keyshare, JsError> {
    set_panic_hook();

    let mut abort = AbortGuard::new();

    let instance = parse_instance_id(instance)?;
    let setup_vk =
        VerifyingKey::from_bytes(&parse_instance_bytes(setup_vk)?).expect_throw("parse setup VK");
    let signing_key = SigningKey::from_bytes(&parse_instance_bytes(signing_key)?);
    let seed = parse_instance_bytes(seed)?;

    let ws = msg_relay_connect(endpoint, abort.signal()).await?;
    let msg_relay = MsgRelay::new(ws);
    let mut msg_relay = BufferedMsgRelay::new(msg_relay);

    let validate = validate.dyn_ref();

    let decoded = validate_setup(&mut msg_relay, instance, &setup_vk, validate).await;

    let setup = keygen::ValidatedSetup::validate_decoded_setup(decoded, signing_key)
        .expect_throw("parse setup msg");

    abort.deadline(setup.ttl().as_millis() as u32);

    let keyshare = keygen::run(setup, seed, msg_relay).await?;

    Ok(Keyshare::new(keyshare))
}
