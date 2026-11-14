//! PRIV2-S worker, signed variant. Same lookup as ../worker, plus an ed25519
//! signature from an OutLayer signing key derived from (this wasm's sha256,
//! the calling contract). The caller contract checks it with ed25519_verify.
//! Signed message (fields composed here, never caller-supplied bytes):
//!   "nearh-priv2s:v1|{nonce}|{payee}|{found}|{country}|{commitment}"
use outlayer::signing_keys;
use sha2::{Digest, Sha256};
use std::io::Read;

#[cfg(target_family = "wasm")]
#[used]
#[link_section = "outlayer.manifest"]
static OUTLAYER_MANIFEST: [u8; include_bytes!("../manifest.json").len()] =
    *include_bytes!("../manifest.json");

const KEY: &str = "priv2s";

fn main() {
    let mut input = String::new();
    let _ = std::io::stdin().read_to_string(&mut input);
    let v: serde_json::Value = serde_json::from_str(&input).unwrap_or_default();
    let field = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or_default().to_owned();
    let (payee, nonce) = (field("payee"), field("nonce"));

    // Fail closed: without both secrets, sign nothing. A signed `found:false`
    // here would be an authenticated false negative for a known payee.
    let (found, country, commitment) =
        match lookup(&payee, std::env::var("IBAN_MAP").ok(), std::env::var("IBAN_SALT").ok()) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(1);
            }
        };
    let msg = format!("nearh-priv2s:v1|{nonce}|{payee}|{found}|{country}|{commitment}");
    let (pk, sig, err) = match (signing_keys::public_key(KEY, None), signing_keys::sign(KEY, None, msg.as_bytes())) {
        (Ok(pk), Ok(sig)) => (hex(&pk), hex(&sig), String::new()),
        (a, b) => (String::new(), String::new(), format!("{:?} {:?}", a.err(), b.err())),
    };
    let out = serde_json::json!({
        "nonce": nonce, "payee": payee, "found": found, "country": country,
        "commitment": commitment, "pk": pk, "sig": sig, "sign_error": err,
    });
    print!("{out}");
}

/// (found, country, commitment) for `payee`, or an error if a secret is
/// missing, empty or malformed.
fn lookup(payee: &str, map: Option<String>, salt: Option<String>) -> Result<(bool, String, String), String> {
    let salt = salt.filter(|s| !s.is_empty()).ok_or("IBAN_SALT missing or empty")?;
    let map: serde_json::Map<String, serde_json::Value> = map
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .ok_or("IBAN_MAP missing or not a JSON object")?;
    match map.get(payee) {
        None => Ok((false, String::new(), String::new())),
        Some(serde_json::Value::String(iban)) => {
            let d = Sha256::new().chain_update(salt.as_bytes()).chain_update(iban.as_bytes()).finalize();
            Ok((true, iban[..2.min(iban.len())].to_owned(), hex(&d)))
        }
        Some(_) => Err("IBAN_MAP entry is not a string".into()),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::lookup;

    const MAP: &str = r#"{"payee-1":"ZZ00FAKE"}"#;

    #[test]
    fn known_and_unknown_payee() {
        let (found, country, c) = lookup("payee-1", Some(MAP.into()), Some("s".into())).unwrap();
        assert!(found);
        assert_eq!(country, "ZZ");
        assert_eq!(c.len(), 64);
        assert_eq!(lookup("payee-9", Some(MAP.into()), Some("s".into())), Ok((false, String::new(), String::new())));
    }

    #[test]
    fn missing_or_empty_salt_fails_closed() {
        assert!(lookup("payee-1", Some(MAP.into()), None).is_err());
        assert!(lookup("payee-1", Some(MAP.into()), Some(String::new())).is_err());
        assert!(lookup("payee-9", Some(MAP.into()), None).is_err());
    }

    #[test]
    fn missing_or_malformed_map_fails_closed() {
        assert!(lookup("payee-1", None, Some("s".into())).is_err());
        assert!(lookup("payee-1", Some("not json".into()), Some("s".into())).is_err());
        assert!(lookup("payee-1", Some("[]".into()), Some("s".into())).is_err());
        assert!(lookup("payee-1", Some(r#"{"payee-1":1}"#.into()), Some("s".into())).is_err());
    }
}
