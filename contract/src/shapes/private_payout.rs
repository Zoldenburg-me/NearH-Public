//! The opt-in private SEPA path (PRIV2). The request carries shape 3's fields without the
//! IBAN and salt. The contract runs the same AP1 checks as shape 3 (`payout::check_payable`,
//! `payout::check_terms`), then asks the pinned OutLayer worker to open the commitment from
//! its encrypted secrets and build the order text from the fixed template. The worker
//! returns only the EIP-191 digest of that text, signed with the ed25519 key OutLayer derives
//! from (worker code hash, this contract). The contract checks that signature against the
//! pinned `worker_pk` over a message it rebuilds from its own fields, and only then asks the
//! MPC to sign the digest. On this path the contract never sees the message text.

use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::{borsh, env, AccountId, Gas, NearToken};

use super::payout::{check_payable, check_terms};
use super::BuiltRequest;
use crate::errors::ContractError;
use crate::state::is_id;
use crate::types::{Mandate, PrivatePayoutRequest, PrivateSepaConfig, RequestKey, Supplier};

/// First field of the message the worker signs.
pub const WORKER_MESSAGE_DOMAIN: &str = "nearh-priv2:v1";
/// Domain tag of [`worker_nonce`].
const WORKER_NONCE_DOMAIN: &str = "nearh:priv2-nonce:v1";
/// Longest worker result the callback reads; the real one is about 250 bytes.
pub const MAX_WORKER_RESPONSE_LEN: usize = 1024;
/// Gas forwarded to OutLayer's `request_execution` (spikes/outlayer: about 12 Tgas burnt for
/// the whole receipt tree; the rest is refunded).
pub const OUTLAYER_REQUEST_GAS: Gas = Gas::from_tgas(150);
/// Gas for `on_worker_result`: its own checks plus the MPC `sign` call and `on_signature`.
pub const WORKER_CALLBACK_GAS: Gas = Gas::from_tgas(
    crate::request::MPC_SIGN_GAS.as_tgas() + crate::request::SIGNATURE_CALLBACK_GAS.as_tgas() + 10,
);
/// Attached to `request_execution` from this contract's balance; OutLayer charged about
/// 0.00102 NEAR per run in the spike and refunds the rest to `payer_account_id` (this contract).
pub const OUTLAYER_DEPOSIT: NearToken = NearToken::from_millinear(10);
/// Longest `PrivateSepaConfig::wasm_url`.
const MAX_WASM_URL_LEN: usize = 512;

/// Shape 3's checks on a request that names the commitment instead of opening it, in this
/// order: the supplier is listed (`ERR_UNKNOWN_SUPPLIER`); `iban_commitment` is `0x` plus 64
/// hex digits (`ERR_INVALID_COMMITMENT`) and the supplier's payable one
/// (`ERR_BANK_CHANGE_COOLING_OFF`, `ERR_IBAN_NOT_ALLOWED`); then `payout::check_terms`. The
/// digest is left zero: the worker supplies it. The caller checks and dedupes the invoice id.
pub fn build_private_payout(
    req: &PrivatePayoutRequest,
    mandate: &Mandate,
    supplier: Option<&Supplier>,
    now_secs: u64,
) -> Result<BuiltRequest, ContractError> {
    let supplier = supplier.ok_or(ContractError::UnknownSupplier)?;
    let commitment = parse_commitment(&req.iban_commitment)?;
    check_payable(supplier, &commitment)?;
    let terms = check_terms(
        &req.amount,
        &req.invoice_amount,
        req.timestamp,
        mandate,
        supplier,
        now_secs,
    )?;
    Ok(terms.into_built([0; 32], supplier, commitment, &req.invoice_id))
}

/// `0x` plus 64 hex digits, lowercased (`ERR_INVALID_COMMITMENT`).
fn parse_commitment(c: &str) -> Result<String, ContractError> {
    let ok = c.len() == 66 && c.starts_with("0x") && c[2..].bytes().all(|b| b.is_ascii_hexdigit());
    ok.then(|| c.to_ascii_lowercase())
        .ok_or(ContractError::InvalidCommitment)
}

/// The nonce one request sends the worker and the worker signs back, so a result signed for
/// one request is never accepted for another: 64 hex digits of
/// `keccak256(borsh((WORKER_NONCE_DOMAIN, key)))`. Request keys are never reused.
pub fn worker_nonce(key: &RequestKey) -> String {
    let preimage = borsh::to_vec(&(WORKER_NONCE_DOMAIN, key))
        .unwrap_or_else(|_| env::panic_str("borsh worker nonce preimage"));
    hex::encode(env::keccak256_array(&preimage))
}

/// The exact bytes the worker signs:
/// `nearh-priv2:v1|{nonce}|{supplier}|{iban_commitment}|{amount}|{at}|{digest}`, with the
/// canonical amount, `at` as `YYYY-MM-DDTHH:MM:SSZ` and `digest` as `0x` plus 64 lowercase
/// hex digits. No field can contain `|` (ids, hex, digits and the fixed time format).
pub fn worker_message(
    nonce: &str,
    supplier: &str,
    iban_commitment: &str,
    amount: &str,
    at: &str,
    digest: &str,
) -> String {
    format!("{WORKER_MESSAGE_DOMAIN}|{nonce}|{supplier}|{iban_commitment}|{amount}|{at}|{digest}")
}

/// The worker's input (`input_data`): everything it needs except the IBAN and salt, which it
/// reads from its secrets by `supplier`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "near_sdk::serde")]
pub struct WorkerInput {
    pub nonce: String,
    pub supplier: String,
    pub iban_commitment: String,
    /// Canonical (D9).
    pub amount: String,
    /// `YYYY-MM-DDTHH:MM:SSZ`.
    pub at: String,
}

/// The worker's stdout as the OutLayer callback delivers it. Extra fields are ignored.
#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde")]
struct WorkerOutput {
    nonce: String,
    digest: String,
    sig: String,
}

/// The digest from a worker result, or why it is refused: unreadable, the wrong nonce, a
/// malformed digest or signature, or a signature that does not verify against `worker_pk`
/// over [`worker_message`] rebuilt from `input`. Never panics.
pub fn verify_worker_result(
    worker_pk: &str,
    input: &WorkerInput,
    output: &[u8],
) -> Result<[u8; 32], &'static str> {
    let out: WorkerOutput =
        near_sdk::serde_json::from_slice(output).map_err(|_| "unreadable worker result")?;
    if out.nonce != input.nonce {
        return Err("nonce mismatch");
    }
    let digest = out
        .digest
        .strip_prefix("0x")
        .filter(|h| is_lower_hex(h))
        .and_then(unhex::<32>)
        .ok_or("malformed digest")?;
    let sig = unhex::<64>(&out.sig).ok_or("malformed signature")?;
    let pk = unhex::<32>(worker_pk).ok_or("malformed worker_pk")?;
    let msg = worker_message(
        &input.nonce,
        &input.supplier,
        &input.iban_commitment,
        &input.amount,
        &input.at,
        &out.digest,
    );
    if !env::ed25519_verify(&sig, msg.as_bytes(), &pk) {
        return Err("bad worker signature");
    }
    Ok(digest)
}

fn is_lower_hex(s: &str) -> bool {
    s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn unhex<const N: usize>(s: &str) -> Option<[u8; N]> {
    let mut out = [0u8; N];
    hex::decode_to_slice(s, &mut out).ok()?;
    Some(out)
}

/// Validates a worker config and returns it in stored form (hex lowercase), or
/// `ERR_INVALID_WORKER_CONFIG` naming the field: `code_hash` and `worker_pk` are 64 hex
/// digits, `wasm_url` is an `https://` URL of at most 512 printable ASCII bytes,
/// `secrets_profile` is 1–64 chars of `[A-Za-z0-9._:-]`, and `outlayer` is not this contract.
pub fn normalize_config(mut cfg: PrivateSepaConfig, me: &AccountId) -> PrivateSepaConfig {
    let bad = |field: &str| -> ! { ContractError::InvalidWorkerConfig.panic(field) };
    let hex32 = |s: &str| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit());
    if !hex32(&cfg.code_hash) {
        bad("code_hash must be 64 hex digits (sha256 of the worker wasm)");
    }
    if !hex32(&cfg.worker_pk) {
        bad("worker_pk must be 64 hex digits (ed25519 public key)");
    }
    let url_ok = cfg.wasm_url.starts_with("https://")
        && cfg.wasm_url.len() <= MAX_WASM_URL_LEN
        && cfg.wasm_url.bytes().all(|b| b.is_ascii_graphic());
    if !url_ok {
        bad("wasm_url must be an https URL of at most 512 printable ASCII bytes");
    }
    if !is_id(&cfg.secrets_profile) {
        bad("secrets_profile must be 1-64 chars of [A-Za-z0-9._:-]");
    }
    if &cfg.outlayer == me {
        bad("outlayer cannot be this contract");
    }
    cfg.code_hash.make_ascii_lowercase();
    cfg.worker_pk.make_ascii_lowercase();
    cfg
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shapes::payout::iban_commitment;
    use crate::types::Caller;

    #[test]
    fn worker_message_matches_the_worker_vector() {
        // The same literal is asserted in contract/priv2-worker (signed_message_vector).
        assert_eq!(
            worker_message(
                &"ab".repeat(32),
                "acme",
                &iban_commitment("DE89370400440532013000", &[7; 32]),
                "42.5",
                "2026-11-03T10:00:00Z",
                "0x7292cb34abf39914f4e4b4ad39d14974b6311ebc7cebce59c89d35d8f2834659",
            ),
            format!(
                "nearh-priv2:v1|{}|acme|{}|42.5|2026-11-03T10:00:00Z|0x7292cb34abf39914f4e4b4ad39d14974b6311ebc7cebce59c89d35d8f2834659",
                "ab".repeat(32),
                COMMITMENT_VECTOR
            )
        );
    }

    /// `iban_commitment("DE89370400440532013000", &[7; 32])`, also asserted by the worker.
    const COMMITMENT_VECTOR: &str =
        "0xf25228a0f9b20cc772b0242f5d953fe133dbb836567ed012313df511df670cb1";

    #[test]
    fn commitment_vector_is_the_contracts() {
        assert_eq!(
            iban_commitment("DE89370400440532013000", &[7; 32]),
            COMMITMENT_VECTOR
        );
    }

    #[test]
    fn nonce_is_per_request_key() {
        let k = |caller: Caller, id: &str| RequestKey {
            agent: "agent-a".into(),
            caller,
            request_id: id.into(),
        };
        let a = worker_nonce(&k(Caller::Agent, "p-1"));
        assert_eq!(a.len(), 64);
        assert_eq!(a, worker_nonce(&k(Caller::Agent, "p-1")));
        assert_ne!(a, worker_nonce(&k(Caller::Agent, "p-2")));
        assert_ne!(a, worker_nonce(&k(Caller::Owner, "p-1")));
    }
}
