//! OutLayer worker for the PRIV2-S spike. Reads a payee id on stdin, looks it
//! up in the FAKE IBAN map that OutLayer injects from the encrypted secret
//! profile, and prints only derived values: whether the payee exists, the
//! country prefix, and a salted SHA-256 commitment. The IBAN itself never
//! leaves the TEE.
use sha2::{Digest, Sha256};
use std::io::Read;

fn main() {
    let mut input = String::new();
    let _ = std::io::stdin().read_to_string(&mut input);
    let payee = serde_json::from_str::<serde_json::Value>(&input)
        .ok()
        .and_then(|v| v.get("payee").and_then(|p| p.as_str()).map(str::to_owned))
        .unwrap_or_default();

    let map: serde_json::Value = std::env::var("IBAN_MAP")
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(serde_json::Value::Null);
    let salt = std::env::var("IBAN_SALT").unwrap_or_default();
    let secrets_loaded = !map.is_null() && !salt.is_empty();

    let out = match map.get(&payee).and_then(|v| v.as_str()) {
        Some(iban) => {
            let digest = Sha256::new()
                .chain_update(salt.as_bytes())
                .chain_update(iban.as_bytes())
                .finalize();
            serde_json::json!({
                "payee": payee,
                "found": true,
                "country": &iban[..2.min(iban.len())],
                "commitment": hex(&digest),
                "secrets_loaded": secrets_loaded,
            })
        }
        None => serde_json::json!({ "payee": payee, "found": false, "secrets_loaded": secrets_loaded }),
    };
    print!("{out}");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
