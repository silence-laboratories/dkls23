use std::rc::Rc;
use std::time::Duration;
use wasm_bindgen::prelude::*;

use web_sys::{AbortController, AbortSignal};

use super::*;
use dkls23::proto;

#[wasm_bindgen]
extern "C" {
    fn setTimeout(closure: &Closure<dyn FnMut()>, millis: u32) -> i32;
    fn clearTimeout(token: i32);
}

/// Wraps AbortController and call .abort() when object goes out of
/// scope.
pub struct AbortGuard {
    controller: Rc<AbortController>,
    closure: Option<Closure<dyn FnMut()>>,
    timer: i32,
}

impl AbortGuard {
    ///
    pub fn new() -> Self {
        Self {
            controller: Rc::new(
                AbortController::new().expect_throw("new AbortController() failed"),
            ),
            timer: 0,
            closure: None,
        }
    }

    /// Get `signal` field of the AbortController object.
    pub fn signal(&self) -> AbortSignal {
        self.controller.signal()
    }

    /// Call self.controller.abort() after millis ms
    pub fn deadline(&mut self, millis: u32) {
        let controller = self.controller.clone();

        let f = Closure::<dyn FnMut()>::new(move || {
            log("AbortGuard.deadline timeout");
            controller.abort();
        });

        self.timer = setTimeout(&f, millis);
        self.closure = Some(f);
    }
}

impl Drop for AbortGuard {
    fn drop(&mut self) {
        self.controller.abort();

        if self.timer > 0 {
            clearTimeout(self.timer);
            self.closure = None; // drop closure
        }
    }
}

#[wasm_bindgen(js_name = createAbortMessage)]
pub fn create_abort_message(
    instance: &str,
    ttl: u32,
    signing_key: &str,
) -> Result<Uint8Array, JsValue> {
    Ok(Uint8Array::from(
        proto::create_abort_message(
            &parse_instance_id(instance)?,
            Duration::from_millis(ttl as u64),
            &SigningKey::from_bytes(&parse_instance_bytes(signing_key)?),
        )
        .as_ref(),
    ))
}
