use std::fmt::{Display, Formatter};
use wasm_bindgen::prelude::*;

use crate::js::identifier::CannotParseIdentifier;
use keyhive_core::principal::identifier::Identifier;

#[wasm_bindgen(js_name = GroupId)]
#[derive(Debug)]
pub struct JsGroupId(pub(crate) keyhive_core::principal::group::id::GroupId);

#[wasm_bindgen(js_class = GroupId)]
impl JsGroupId {
    /// Construct a `GroupId` from raw 32-byte verifying-key bytes. Mirrors
    /// `Identifier`'s constructor so a JS consumer can persist a group id and
    /// later look up the `Group` via `kh.getGroup(GroupId.fromBytes(persistedBytes))`.
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: Vec<u8>) -> Result<JsGroupId, CannotParseIdentifier> {
        let arr: [u8; 32] = bytes.try_into().map_err(|_| CannotParseIdentifier)?;
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&arr).map_err(|_| CannotParseIdentifier)?;
        Ok(JsGroupId(keyhive_core::principal::group::id::GroupId::new(
            Identifier::from(vk),
        )))
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    #[wasm_bindgen(js_name = toString)]
    pub fn to_js_string(&self) -> String {
        self.0.to_string()
    }
}

impl Display for JsGroupId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}
