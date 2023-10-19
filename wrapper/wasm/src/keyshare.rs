use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;

use k256::elliptic_curve::group::GroupEncoding;

use dkls23::keygen;
use sl_mpc_mate::bincode;

#[wasm_bindgen]
pub struct Keyshare {
    share: keygen::Keyshare,
}

impl Keyshare {
    pub fn new(share: keygen::Keyshare) -> Self {
        Self { share }
    }
}

#[wasm_bindgen]
impl Keyshare {
    /// Return public key as compressed encoding of the public key.
    #[wasm_bindgen(js_name = publicKey)]
    pub fn public_key(&self) -> Uint8Array {
        Uint8Array::from(self.share.public_key.to_affine().to_bytes().as_slice())
    }

    /// Serialize the keyshare into array of bytes.
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Uint8Array {
        let keyshare =
            bincode::encode_to_vec(&self.share, bincode::config::standard()).unwrap_throw();

        Uint8Array::from(keyshare.as_ref())
    }

    /// Deserialize keyshare from the array of bytes.
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: Uint8Array) -> Result<Keyshare, JsValue> {
        let bytes: Vec<u8> = bytes.to_vec();

        let (share, _) = bincode::decode_from_slice(&bytes, bincode::config::standard())
            .map_err(|_| JsValue::from_str(""))?;

        Ok(Keyshare { share })
    }
}
