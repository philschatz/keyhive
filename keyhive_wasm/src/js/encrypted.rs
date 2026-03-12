use super::change_id::JsChangeId;
use keyhive_core::crypto::encrypted::EncryptedContent;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Encrypted)]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct JsEncrypted(pub(crate) EncryptedContent<Vec<u8>, JsChangeId>);

#[wasm_bindgen(js_class = Encrypted)]
impl JsEncrypted {
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<JsEncrypted, CannotDeserializeEncryptedError> {
        bincode::deserialize(bytes)
            .map(JsEncrypted)
            .map_err(CannotDeserializeEncryptedError::from)
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Result<Vec<u8>, CannotSerializeEncryptedError> {
        bincode::serialize(self).map_err(CannotSerializeEncryptedError)
    }

    #[wasm_bindgen(getter)]
    pub fn ciphertext(&self) -> Vec<u8> {
        self.0.ciphertext.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn nonce(&self) -> Vec<u8> {
        self.0.nonce.as_bytes().to_vec()
    }

    #[wasm_bindgen(getter)]
    pub fn pcs_key_hash(&self) -> Vec<u8> {
        self.0.pcs_key_hash.raw.as_bytes().to_vec()
    }

    #[wasm_bindgen(getter)]
    pub fn content_ref(&self) -> Vec<u8> {
        self.0.content_ref.bytes().to_vec()
    }

    #[wasm_bindgen(getter)]
    pub fn pred_refs(&self) -> Vec<u8> {
        self.0.pred_refs.raw.as_bytes().to_vec()
    }
}

impl From<EncryptedContent<Vec<u8>, JsChangeId>> for JsEncrypted {
    fn from(encrypted: EncryptedContent<Vec<u8>, JsChangeId>) -> Self {
        JsEncrypted(encrypted)
    }
}

#[derive(Debug, Error)]
#[error("Cannot deserialize Encrypted: {0}")]
pub struct CannotDeserializeEncryptedError(#[from] bincode::Error);

impl From<CannotDeserializeEncryptedError> for JsValue {
    fn from(err: CannotDeserializeEncryptedError) -> Self {
        let err = js_sys::Error::new(&err.to_string());
        err.set_name("CannotDeserializeEncryptedError");
        err.into()
    }
}

#[derive(Debug, Error)]
#[error("Cannot serialize Encrypted: {0}")]
pub struct CannotSerializeEncryptedError(#[from] bincode::Error);

impl From<CannotSerializeEncryptedError> for JsValue {
    fn from(err: CannotSerializeEncryptedError) -> Self {
        let err = js_sys::Error::new(&err.to_string());
        err.set_name("CannotSerializeEncryptedError");
        err.into()
    }
}
