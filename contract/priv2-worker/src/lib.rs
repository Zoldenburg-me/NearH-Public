//! PRIV2 worker, template side. Inside OutLayer's TEE the worker gets the contract's
//! [`Input`] (no IBAN) and its encrypted secrets (`SUPPLIERS`: supplier id → IBAN and salt).
//! It opens the supplier's commitment, renders the Monerium order text from the fixed
//! template, and answers only the EIP-191 digest of that text with a signature over
//! [`signed_message`]. The text and the IBAN never leave the worker in its answer, which
//! OutLayer posts on chain. The template, the commitment and the signed message must match
//! the contract byte for byte (`contract/src/shapes/payout.rs`,
//! `contract/src/shapes/private_payout.rs`); the tests pin the same vectors on both sides.

use serde::Deserialize;
use sha2::{Digest, Sha256};
use sha3::Keccak256;

/// As `IBAN_COMMITMENT_DOMAIN` in the contract.
pub const IBAN_COMMITMENT_DOMAIN: &[u8] = b"nearh:iban-commitment:v1";
/// As `WORKER_MESSAGE_DOMAIN` in the contract.
pub const WORKER_MESSAGE_DOMAIN: &str = "nearh-priv2:v1";

/// The contract's `WorkerInput`. Unknown fields are refused.
#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub nonce: String,
    pub supplier: String,
    pub iban_commitment: String,
    pub amount: String,
    pub at: String,
}

/// One supplier's entry in the `SUPPLIERS` secret.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SupplierSecret {
    iban: String,
    /// `0x` plus 64 hex digits.
    salt: String,
}

/// What the worker builds for one input. Only `digest` (and a signature over
/// `signed_message`) goes into the answer; `text` is for the rail, off chain.
#[derive(Debug, PartialEq, Eq)]
pub struct Built {
    pub text: String,
    /// `0x` plus 64 lowercase hex digits.
    pub digest: String,
    pub signed_message: String,
}

/// `Send EUR {amount} to {iban} at {at}`, the shape 3 template.
pub fn payout_text(amount: &str, iban: &str, at: &str) -> String {
    format!("Send EUR {amount} to {iban} at {at}")
}

/// `keccak256("\x19Ethereum Signed Message:\n" || len || text)`.
pub fn eip191_digest(text: &str) -> [u8; 32] {
    Keccak256::new()
        .chain_update(b"\x19Ethereum Signed Message:\n")
        .chain_update(text.len().to_string().as_bytes())
        .chain_update(text.as_bytes())
        .finalize()
        .into()
}

/// `0x` + hex of `sha256(IBAN_COMMITMENT_DOMAIN || salt || iban)`.
pub fn iban_commitment(iban: &str, salt: &[u8; 32]) -> String {
    let d = Sha256::new()
        .chain_update(IBAN_COMMITMENT_DOMAIN)
        .chain_update(salt)
        .chain_update(iban.as_bytes())
        .finalize();
    format!("0x{}", hex(&d))
}

/// `nearh-priv2:v1|{nonce}|{supplier}|{iban_commitment}|{amount}|{at}|{digest}`.
pub fn signed_message(
    nonce: &str,
    supplier: &str,
    iban_commitment: &str,
    amount: &str,
    at: &str,
    digest: &str,
) -> String {
    format!("{WORKER_MESSAGE_DOMAIN}|{nonce}|{supplier}|{iban_commitment}|{amount}|{at}|{digest}")
}

/// Checks `input` and `suppliers` (the `SUPPLIERS` secret as JSON), opens the commitment and
/// builds the text, digest and signed message. Fails closed: any malformed field, unknown
/// supplier or commitment that the stored IBAN and salt do not open is an error, and nothing
/// is built.
pub fn build(input: &Input, suppliers: &str) -> Result<Built, String> {
    if !is_lower_hex(&input.nonce, 64) {
        return Err("nonce must be 64 lowercase hex digits".into());
    }
    if !is_id(&input.supplier) {
        return Err("supplier must be 1-64 chars of [A-Za-z0-9._:-]".into());
    }
    let commitment_hex = input.iban_commitment.strip_prefix("0x").unwrap_or("");
    if !is_lower_hex(commitment_hex, 64) {
        return Err("iban_commitment must be 0x plus 64 lowercase hex digits".into());
    }
    if !is_canonical_amount(&input.amount) {
        return Err("amount must be a canonical D9 amount".into());
    }
    if !is_utc_second(&input.at) {
        return Err("at must be YYYY-MM-DDTHH:MM:SSZ".into());
    }
    let map: std::collections::BTreeMap<String, SupplierSecret> =
        serde_json::from_str(suppliers).map_err(|_| "SUPPLIERS secret is malformed")?;
    let secret = map
        .get(&input.supplier)
        .ok_or("supplier not in SUPPLIERS")?;
    if !is_iban(&secret.iban) {
        return Err("stored IBAN is malformed".into());
    }
    let salt = parse_salt(&secret.salt).ok_or("stored salt is malformed")?;
    if iban_commitment(&secret.iban, &salt) != input.iban_commitment {
        return Err("stored IBAN and salt do not open iban_commitment".into());
    }
    let text = payout_text(&input.amount, &secret.iban, &input.at);
    let digest = format!("0x{}", hex(&eip191_digest(&text)));
    let signed_message = signed_message(
        &input.nonce,
        &input.supplier,
        &input.iban_commitment,
        &input.amount,
        &input.at,
        &digest,
    );
    Ok(Built {
        text,
        digest,
        signed_message,
    })
}

/// The worker's whole answer for `input_json`: `{"nonce","digest","sig"}` with `sig` the
/// 64-byte ed25519 signature `sign` makes over the signed message (OutLayer's
/// `signing_keys::sign` in the TEE). `suppliers` is `None` when the secret is missing.
/// Returns the answer and the text for the rail. Any error means no answer is signed.
pub fn respond(
    input_json: &str,
    suppliers: Option<&str>,
    sign: impl FnOnce(&[u8]) -> Result<[u8; 64], String>,
) -> Result<(String, String), String> {
    let input: Input = serde_json::from_str(input_json).map_err(|_| "input is malformed")?;
    let suppliers = suppliers
        .filter(|s| !s.is_empty())
        .ok_or("SUPPLIERS secret missing")?;
    let built = build(&input, suppliers)?;
    let sig = sign(built.signed_message.as_bytes())?;
    let answer = serde_json::json!({
        "nonce": input.nonce,
        "digest": built.digest,
        "sig": hex(&sig),
    });
    Ok((answer.to_string(), built.text))
}

/// As the contract's `is_iban`: 15–34 chars, 2 uppercase letters, 2 digits, then uppercase
/// letters and digits.
pub fn is_iban(iban: &str) -> bool {
    let b = iban.as_bytes();
    (15..=34).contains(&b.len())
        && b[..2].iter().all(u8::is_ascii_uppercase)
        && b[2..4].iter().all(u8::is_ascii_digit)
        && b[4..]
            .iter()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
}

/// The contract's canonical form (D9): `0` or no leading zero, at most 2 decimals, no
/// trailing zero or dot, not zero.
pub fn is_canonical_amount(a: &str) -> bool {
    let (int, frac) = a.split_once('.').unwrap_or((a, ""));
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit());
    let int_ok = digits(int) && (int == "0" || !int.starts_with('0'));
    let frac_ok = if a.contains('.') {
        digits(frac) && frac.len() <= 2 && !frac.ends_with('0')
    } else {
        true
    };
    int_ok && frac_ok && !(int == "0" && frac.is_empty())
}

/// `YYYY-MM-DDTHH:MM:SSZ` by shape (digits in place, month 01–12, day 01–31, hour 00–23,
/// minute and second 00–59).
pub fn is_utc_second(at: &str) -> bool {
    let b = at.as_bytes();
    let num = |r: std::ops::Range<usize>| -> Option<u32> {
        let s = at.get(r)?;
        s.bytes()
            .all(|c| c.is_ascii_digit())
            .then(|| s.parse().ok())?
    };
    b.len() == 20
        && b[4] == b'-'
        && b[7] == b'-'
        && b[10] == b'T'
        && b[13] == b':'
        && b[16] == b':'
        && b[19] == b'Z'
        && num(0..4).is_some()
        && num(5..7).is_some_and(|m| (1..=12).contains(&m))
        && num(8..10).is_some_and(|d| (1..=31).contains(&d))
        && num(11..13).is_some_and(|h| h <= 23)
        && num(14..16).is_some_and(|m| m <= 59)
        && num(17..19).is_some_and(|s| s <= 59)
}

fn is_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn parse_salt(s: &str) -> Option<[u8; 32]> {
    let h = s.strip_prefix("0x").filter(|h| h.len() == 64)?;
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(h.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The documentation IBAN (docs/interfaces.md), not an account of ours.
    const IBAN: &str = "DE89370400440532013000";
    const SALT: [u8; 32] = [7; 32];
    /// `iban_commitment(IBAN, &SALT)`, as the contract's `COMMITMENT_VECTOR`.
    const COMMITMENT: &str = "0xf25228a0f9b20cc772b0242f5d953fe133dbb836567ed012313df511df670cb1";

    fn suppliers() -> String {
        format!(
            r#"{{"acme":{{"iban":"{IBAN}","salt":"0x{}"}}}}"#,
            "07".repeat(32)
        )
    }

    fn input() -> Input {
        Input {
            nonce: "ab".repeat(32),
            supplier: "acme".into(),
            iban_commitment: COMMITMENT.into(),
            amount: "42.5".into(),
            at: "2026-11-03T10:00:00Z".into(),
        }
    }

    #[test]
    fn text_and_digest_match_the_contracts_vector() {
        // contract/src/shapes/payout.rs `matches_the_interfaces_reservation_example`.
        let b = build(&input(), &suppliers()).unwrap();
        assert_eq!(
            b.text,
            "Send EUR 42.5 to DE89370400440532013000 at 2026-11-03T10:00:00Z"
        );
        assert_eq!(
            b.digest,
            "0x7292cb34abf39914f4e4b4ad39d14974b6311ebc7cebce59c89d35d8f2834659"
        );
    }

    #[test]
    fn commitment_matches_the_contracts_vector() {
        assert_eq!(iban_commitment(IBAN, &SALT), COMMITMENT);
    }

    #[test]
    fn signed_message_vector() {
        // The same literal is asserted in contract/src/shapes/private_payout.rs.
        let b = build(&input(), &suppliers()).unwrap();
        assert_eq!(
            b.signed_message,
            format!(
                "nearh-priv2:v1|{}|acme|{COMMITMENT}|42.5|2026-11-03T10:00:00Z|0x7292cb34abf39914f4e4b4ad39d14974b6311ebc7cebce59c89d35d8f2834659",
                "ab".repeat(32)
            )
        );
    }

    #[test]
    fn answer_carries_the_digest_and_signature_but_never_the_iban_or_text() {
        let mut signed = Vec::new();
        let (answer, text) = respond(
            &format!(
                r#"{{"nonce":"{}","supplier":"acme","iban_commitment":"{COMMITMENT}","amount":"42.5","at":"2026-11-03T10:00:00Z"}}"#,
                "ab".repeat(32)
            ),
            Some(&suppliers()),
            |m| {
                signed = m.to_vec();
                Ok([9; 64])
            },
        )
        .unwrap();
        assert!(
            !answer.contains(IBAN) && !answer.contains("Send EUR"),
            "{answer}"
        );
        assert!(text.contains(IBAN));
        let v: serde_json::Value = serde_json::from_str(&answer).unwrap();
        assert_eq!(v["nonce"], "ab".repeat(32));
        assert_eq!(v["digest"], build(&input(), &suppliers()).unwrap().digest);
        assert_eq!(v["sig"], "09".repeat(64));
        assert_eq!(
            signed,
            build(&input(), &suppliers())
                .unwrap()
                .signed_message
                .into_bytes()
        );
    }

    #[test]
    fn a_commitment_the_secret_does_not_open_is_refused() {
        let mut i = input();
        i.iban_commitment = iban_commitment("GB33BUKB20201555555555", &SALT);
        assert!(build(&i, &suppliers()).is_err());
        let other_salt = format!(
            r#"{{"acme":{{"iban":"{IBAN}","salt":"0x{}"}}}}"#,
            "08".repeat(32)
        );
        assert!(build(&input(), &other_salt).is_err());
        let mut i = input();
        i.supplier = "beta".into();
        assert_eq!(
            build(&i, &suppliers()),
            Err("supplier not in SUPPLIERS".into())
        );
    }

    #[test]
    fn malformed_secrets_fail_closed() {
        let never = |_: &[u8]| -> Result<[u8; 64], String> { panic!("must not sign") };
        let json = serde_json::to_string(&serde_json::json!({
            "nonce": "ab".repeat(32), "supplier": "acme", "iban_commitment": COMMITMENT,
            "amount": "42.5", "at": "2026-11-03T10:00:00Z",
        }))
        .unwrap();
        assert!(respond(&json, None, never).is_err());
        assert!(respond(&json, Some(""), never).is_err());
        for bad in [
            "not json".to_string(),
            "[]".into(),
            r#"{"acme":"DE89370400440532013000"}"#.into(),
            format!(
                r#"{{"acme":{{"iban":"de89370400440532013000","salt":"0x{}"}}}}"#,
                "07".repeat(32)
            ),
            r#"{"acme":{"iban":"DE89370400440532013000","salt":"07"}}"#.into(),
        ] {
            assert!(respond(&json, Some(&bad), never).is_err(), "{bad}");
        }
    }

    #[test]
    fn malformed_input_fails_closed() {
        let mut cases = vec![];
        let mut i = input();
        i.amount = "42.50".into(); // not canonical: the contract always sends 42.5
        cases.push(i);
        let mut i = input();
        i.amount = "0".into();
        cases.push(i);
        let mut i = input();
        i.at = "2026-11-03 10:00:00Z".into();
        cases.push(i);
        let mut i = input();
        i.at = "2026-13-03T10:00:00Z".into();
        cases.push(i);
        let mut i = input();
        i.nonce = "AB".repeat(32);
        cases.push(i);
        let mut i = input();
        i.iban_commitment = COMMITMENT.to_ascii_uppercase();
        cases.push(i);
        let mut i = input();
        i.supplier = "acme|x".into();
        cases.push(i);
        for i in cases {
            assert!(build(&i, &suppliers()).is_err(), "{i:?}");
        }
        // An extra field (say an IBAN smuggled in by a caller) is refused.
        let extra = format!(
            r#"{{"nonce":"{}","supplier":"acme","iban_commitment":"{COMMITMENT}","amount":"42.5","at":"2026-11-03T10:00:00Z","iban":"X"}}"#,
            "ab".repeat(32)
        );
        assert!(respond(&extra, Some(&suppliers()), |_| Ok([0; 64])).is_err());
    }

    #[test]
    fn signing_error_gives_no_answer() {
        let json = serde_json::to_string(&serde_json::json!({
            "nonce": "ab".repeat(32), "supplier": "acme", "iban_commitment": COMMITMENT,
            "amount": "42.5", "at": "2026-11-03T10:00:00Z",
        }))
        .unwrap();
        assert_eq!(
            respond(&json, Some(&suppliers()), |_| Err("keystore down".into())),
            Err("keystore down".into())
        );
    }

    #[test]
    fn canonical_amounts_match_d9() {
        for ok in ["0.01", "0.5", "1", "1.5", "7.05", "42.5", "100.1", "10"] {
            assert!(is_canonical_amount(ok), "{ok}");
        }
        for bad in [
            "", "0", "00", "01", "1.50", "1.", ".5", "1.505", "-1", "1e2", " 1", "0.00",
        ] {
            assert!(!is_canonical_amount(bad), "{bad:?}");
        }
    }
}
