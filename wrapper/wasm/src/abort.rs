use std::rc::Rc;
use wasm_bindgen::prelude::*;

use web_sys::{AbortController, AbortSignal};

use super::*;

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
