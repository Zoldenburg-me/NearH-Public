//! Throwaway caller for the PRIV2-S spike. It asks outlayer.testnet to run one
//! pinned WASM build (WasmUrl + SHA-256 the contract stores itself) with the
//! owner's encrypted secret profile, and records what the callback hands back.
//!
//! OutLayer's callback carries only the guest's stdout. To check a result on
//! chain, the signed worker (../worker-signed) signs its fields with an
//! OutLayer signing key bound to (wasm sha256, this contract); the owner pins
//! that public key here once (`set_worker_pk`, after checking the bootstrap
//! run's TDX attestation off-chain) and every later result is checked with
//! `env::ed25519_verify` against a nonce this contract chose.
use near_sdk::serde_json::{self, json, Value};
use near_sdk::store::LookupMap;
use near_sdk::{env, log, near, require, AccountId, Gas, NearToken, Promise, PromiseResult};

const REQUEST_GAS: Gas = Gas::from_tgas(150);
const CALLBACK_GAS: Gas = Gas::from_tgas(20);

#[near(contract_state)]
pub struct Caller {
    outlayer: AccountId,
    wasm_url: String,
    wasm_hash: String,
    secrets_owner: AccountId,
    secrets_profile: String,
    /// hex of the worker's 32-byte ed25519 key; None = results are not checked
    worker_pk: Option<String>,
    next_id: u64,
    results: LookupMap<u64, String>,
}

impl Default for Caller {
    fn default() -> Self {
        env::panic_str("not initialized")
    }
}

/// The exact bytes the signed worker signs.
pub fn signed_message(nonce: &str, v: &Value) -> String {
    let s = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or_default().to_owned();
    let found = v.get("found").and_then(Value::as_bool).unwrap_or(false);
    format!(
        "nearh-priv2s:v1|{nonce}|{}|{found}|{}|{}",
        s("payee"),
        s("country"),
        s("commitment")
    )
}

fn unhex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != 2 * N {
        return None;
    }
    let mut out = [0u8; N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

/// Check a callback value against the pinned key and the nonce we sent.
pub fn verify(pk_hex: &str, nonce: &str, payee: &str, v: &Value) -> Result<(), &'static str> {
    let pk = unhex::<32>(pk_hex).ok_or("bad pinned key")?;
    let sig = v
        .get("sig")
        .and_then(Value::as_str)
        .and_then(unhex::<64>)
        .ok_or("no signature")?;
    if v.get("nonce").and_then(Value::as_str) != Some(nonce) {
        return Err("nonce mismatch");
    }
    if v.get("payee").and_then(Value::as_str) != Some(payee) {
        return Err("payee mismatch");
    }
    if !env::ed25519_verify(&sig, signed_message(nonce, v).as_bytes(), &pk) {
        return Err("bad signature");
    }
    Ok(())
}

#[near]
impl Caller {
    #[init]
    pub fn new(
        outlayer: AccountId,
        wasm_url: String,
        wasm_hash: String,
        secrets_owner: AccountId,
        secrets_profile: String,
    ) -> Self {
        Self {
            outlayer,
            wasm_url,
            wasm_hash,
            secrets_owner,
            secrets_profile,
            worker_pk: None,
            next_id: 0,
            results: LookupMap::new(b"r"),
        }
    }

    /// Owner pins the worker key it checked off-chain (bootstrap attestation).
    pub fn set_worker_pk(&mut self, pk_hex: String) {
        require!(env::predecessor_account_id() == self.secrets_owner, "owner only");
        require!(unhex::<32>(&pk_hex).is_some(), "pk must be 64 hex chars");
        self.worker_pk = Some(pk_hex);
    }

    /// Ask OutLayer for the derived value of one payee. The caller pays; the
    /// unused deposit is refunded by OutLayer to the signer.
    #[payable]
    pub fn lookup(&mut self, payee: String) -> Promise {
        let id = self.next_id;
        self.next_id += 1;
        let nonce = format!("{}:{}", env::current_account_id(), id);
        let args = json!({
            "source": { "WasmUrl": {
                "url": self.wasm_url,
                "hash": self.wasm_hash,
                "build_target": "wasm32-wasip2",
            }},
            "resource_limits": {
                "max_instructions": 1_000_000_000u64,
                "max_memory_mb": 128,
                "max_execution_seconds": 30,
            },
            "input_data": json!({ "payee": payee, "nonce": nonce }).to_string(),
            "secrets_ref": { "profile": self.secrets_profile, "account_id": self.secrets_owner },
            "response_format": "Json",
            "payer_account_id": env::signer_account_id(),
        });
        log!("lookup {} requested at block {}", id, env::block_height());
        Promise::new(self.outlayer.clone())
            .function_call(
                "request_execution",
                serde_json::to_vec(&args).unwrap(),
                env::attached_deposit(),
                REQUEST_GAS,
            )
            .then(
                Promise::new(env::current_account_id()).function_call(
                    "on_result",
                    serde_json::to_vec(&json!({
                        "id": id,
                        "nonce": nonce,
                        "payee": payee,
                        "requested_at": env::block_height(),
                    }))
                    .unwrap(),
                    NearToken::from_yoctonear(0),
                    CALLBACK_GAS,
                ),
            )
    }

    /// Everything the contract gets from OutLayer is this promise result: the
    /// guest's stdout as JSON (or null on failure). No hash, quote or signature
    /// from OutLayer itself; `verified` comes from the worker's own signature.
    #[private]
    pub fn on_result(&mut self, id: u64, nonce: String, payee: String, requested_at: u64) -> Value {
        #[allow(deprecated)]
        let value = match env::promise_result(0) {
            PromiseResult::Successful(bytes) => {
                serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null)
            }
            PromiseResult::Failed => Value::Null,
        };
        let verified = match &self.worker_pk {
            None => "unchecked (no pinned key)".to_owned(),
            Some(pk) => match verify(pk, &nonce, &payee, &value) {
                Ok(()) => "ok".to_owned(),
                Err(why) => format!("REJECTED: {why}"),
            },
        };
        log!(
            "lookup {} resolved at block {} ({} blocks after request), verified: {}: {}",
            id,
            env::block_height(),
            env::block_height() - requested_at,
            verified,
            value
        );
        let record = json!({ "verified": verified, "value": value });
        self.results.insert(id, record.to_string());
        record
    }

    pub fn get_result(&self, id: u64) -> Option<String> {
        self.results.get(&id).cloned()
    }

    pub fn get_pin(&self) -> (String, String, Option<String>) {
        (self.wasm_url.clone(), self.wasm_hash.clone(), self.worker_pk.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn signed(key: &SigningKey, nonce: &str) -> Value {
        let mut v = json!({ "nonce": nonce, "payee": "payee-1", "found": true,
            "country": "ZZ", "commitment": "ab".repeat(32) });
        let sig = key.sign(signed_message(nonce, &v).as_bytes());
        v["sig"] = Value::String(hex(&sig.to_bytes()));
        v
    }

    #[test]
    fn accepts_a_signed_result() {
        let k = SigningKey::from_bytes(&[7u8; 32]);
        let pk = hex(k.verifying_key().as_bytes());
        assert_eq!(verify(&pk, "c:0", "payee-1", &signed(&k, "c:0")), Ok(()));
    }

    #[test]
    fn rejects_tampered_field() {
        let k = SigningKey::from_bytes(&[7u8; 32]);
        let pk = hex(k.verifying_key().as_bytes());
        let mut v = signed(&k, "c:0");
        v["commitment"] = Value::String("cd".repeat(32));
        assert_eq!(verify(&pk, "c:0", "payee-1", &v), Err("bad signature"));
        let mut v = signed(&k, "c:0");
        v["found"] = Value::Bool(false);
        assert_eq!(verify(&pk, "c:0", "payee-1", &v), Err("bad signature"));
    }

    #[test]
    fn rejects_replay_wrong_payee_other_key_and_unsigned() {
        let k = SigningKey::from_bytes(&[7u8; 32]);
        let pk = hex(k.verifying_key().as_bytes());
        // a result signed for an earlier request is not accepted for this one
        assert_eq!(verify(&pk, "c:1", "payee-1", &signed(&k, "c:0")), Err("nonce mismatch"));
        assert_eq!(verify(&pk, "c:0", "payee-2", &signed(&k, "c:0")), Err("payee mismatch"));
        // a different worker build derives a different key
        let other = SigningKey::from_bytes(&[8u8; 32]);
        assert_eq!(verify(&pk, "c:0", "payee-1", &signed(&other, "c:0")), Err("bad signature"));
        let mut v = signed(&k, "c:0");
        v.as_object_mut().unwrap().remove("sig");
        assert_eq!(verify(&pk, "c:0", "payee-1", &v), Err("no signature"));
        assert_eq!(verify(&pk, "c:0", "payee-1", &Value::Null), Err("no signature"));
    }
}
