#![cfg(target_arch = "wasm32")]

use crate::keys::{AccountId, FullViewingKey, Scope, SpendingKey};
use alloc::vec::Vec;
use core::convert::TryFrom;
use wasm_bindgen::prelude::*;

/// Derive an Orchard spending key from a ZIP32 seed.
#[wasm_bindgen]
pub fn derive_spending_key(seed: &[u8], coin_type: u32, account: u32) -> Result<Vec<u8>, JsValue> {
    let account_id =
        AccountId::try_from(account).map_err(|_| JsValue::from_str("Invalid account index"))?;
    let sk = SpendingKey::from_zip32_seed(seed, coin_type, account_id)
        .map_err(|e| JsValue::from_str(&format!("ZIP32 error: {:?}", e)))?;
    Ok(sk.to_bytes().to_vec())
}

/// Parse a raw Orchard spending key.
#[wasm_bindgen]
pub fn spending_key_from_bytes(bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
    if bytes.len() != 32 {
        return Err(JsValue::from_str("Invalid spending key length"));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    let sk_opt = SpendingKey::from_bytes(arr);
    if sk_opt.is_some().into() {
        let sk = sk_opt.unwrap();
        Ok(sk.to_bytes().to_vec())
    } else {
        Err(JsValue::from_str("Invalid spending key bytes"))
    }
}

/// Derive the full viewing key from an Orchard spending key.
#[wasm_bindgen]
pub fn derive_full_viewing_key(sk_bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
    if sk_bytes.len() != 32 {
        return Err(JsValue::from_str("Invalid spending key length"));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(sk_bytes);
    let sk_opt = SpendingKey::from_bytes(arr);
    if sk_opt.is_some().into() {
        let sk = sk_opt.unwrap();
        let fvk = FullViewingKey::from(&sk);
        Ok(fvk.to_bytes().to_vec())
    } else {
        Err(JsValue::from_str("Invalid spending key bytes"))
    }
}

/// Parse a raw Orchard full viewing key.
#[wasm_bindgen]
pub fn full_viewing_key_from_bytes(bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
    if bytes.len() != 96 {
        return Err(JsValue::from_str("Invalid full viewing key length"));
    }
    let mut arr = [0u8; 96];
    arr.copy_from_slice(bytes);
    if let Some(fvk) = FullViewingKey::from_bytes(&arr) {
        Ok(fvk.to_bytes().to_vec())
    } else {
        Err(JsValue::from_str("Invalid full viewing key bytes"))
    }
}

/// Derive the incoming viewing key from a full viewing key.
#[wasm_bindgen]
pub fn derive_incoming_viewing_key(fvk_bytes: &[u8], scope: u8) -> Result<Vec<u8>, JsValue> {
    if fvk_bytes.len() != 96 {
        return Err(JsValue::from_str("Invalid full viewing key length"));
    }
    let mut arr = [0u8; 96];
    arr.copy_from_slice(fvk_bytes);
    let fvk =
        FullViewingKey::from_bytes(&arr).ok_or(JsValue::from_str("Invalid full viewing key"))?;
    let scope = if scope == 0 {
        Scope::External
    } else {
        Scope::Internal
    };
    let ivk = fvk.to_ivk(scope);
    Ok(ivk.to_bytes().to_vec())
}

/// Derive the outgoing viewing key from a full viewing key.
#[wasm_bindgen]
pub fn derive_outgoing_viewing_key(fvk_bytes: &[u8], scope: u8) -> Result<Vec<u8>, JsValue> {
    if fvk_bytes.len() != 96 {
        return Err(JsValue::from_str("Invalid full viewing key length"));
    }
    let mut arr = [0u8; 96];
    arr.copy_from_slice(fvk_bytes);
    let fvk =
        FullViewingKey::from_bytes(&arr).ok_or(JsValue::from_str("Invalid full viewing key"))?;
    let scope = if scope == 0 {
        Scope::External
    } else {
        Scope::Internal
    };
    let ovk = fvk.to_ovk(scope);
    Ok(ovk.as_ref().to_vec())
}

/// Derive an Orchard payment address (raw encoding) from a full viewing key.
///
/// Always uses External scope. Returns the 43-byte raw address: 11-byte diversifier + 32-byte public key.
#[wasm_bindgen]
pub fn derive_address(fvk_bytes: &[u8], diversifier_index: u32) -> Result<Vec<u8>, JsValue> {
    if fvk_bytes.len() != 96 {
        return Err(JsValue::from_str("Invalid full viewing key length"));
    }
    let mut arr = [0u8; 96];
    arr.copy_from_slice(fvk_bytes);
    let fvk =
        FullViewingKey::from_bytes(&arr).ok_or(JsValue::from_str("Invalid full viewing key"))?;
    let address = fvk.address_at(diversifier_index, Scope::External);
    Ok(address.to_raw_address_bytes().to_vec())
}
