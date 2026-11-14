//! PRIV2 unit tests: the opt-in private SEPA path. The worker pin is set only with the owner
//! passkey; a private payout runs the same AP1 checks as shape 3; the contract asks the MPC to
//! sign only a worker digest signed by the pinned key for this request, and fails closed on
//! anything else. The owner is a passkey here (assertions signed as in c2_owner.rs); the
//! worker's derived ed25519 key is a fixed software key.

mod mock_mpc;

use std::panic::{catch_unwind, AssertUnwindSafe};

use ed25519_dalek::SigningKey as WorkerKey;
use mandate::owner::owner_challenge;
use mandate::shapes::eip191_digest;
use mandate::shapes::payout::iban_commitment;
use mandate::shapes::private_payout::{worker_message, WorkerInput};
use mandate::types::*;
use mandate::Contract;
use near_sdk::base64::engine::general_purpose::URL_SAFE_NO_PAD;
use near_sdk::base64::Engine;
use near_sdk::json_types::{Base64VecU8, U128};
use near_sdk::mock::MockAction;
use near_sdk::serde_json::{self, json, Value};
use near_sdk::test_utils::{get_created_receipts, get_logs, VMContextBuilder};
use near_sdk::{
    borsh, env, testing_env, AccountId, NearToken, PromiseOrValue, PromiseResult, PublicKey,
};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};

const CONTRACT: &str = "mandate-demo.testnet";
const MPC: &str = "v1.signer-prod.testnet";
const OUTLAYER: &str = "outlayer.testnet";
const RELAY: &str = "relay.testnet";
const WALLET: &str = "sme-owner.testnet";
const RP_ID: &str = "localhost";
const ORIGIN: &str = "http://localhost:5173";
const USDC: &str = "0x036cbd53842c5426634e7929541ec2318f3dcf7e";
const EURE: &str = "0x29f37f6adca168b79b8d9567eab9be3fbf21db85";
const AGENT: &str = "agent-a";
/// Setup time; suppliers become payable one cooling-off (24 h) later, at `T`.
const NOW: u64 = 1_793_599_700;
const T: u64 = NOW + 86_400;
const EURE_UNIT: u128 = 1_000_000_000_000_000_000;
/// The documentation IBAN (docs/interfaces.md), never in any argument here.
const IBAN: &str = "DE89370400440532013000";
const SALT: [u8; 32] = [7; 32];
const HASH_A: &str = "9e4ac160790d564d54711f34c9828fdff66dffd600db63905061fea3619e8f6f";
const HASH_B: &str = "c33c5a59a8710fccaf35b3e0edd7308b4df8db60ef919a12bd13091594d45e28";

// ---------- environment ----------

fn acc(s: &str) -> AccountId {
    s.parse().unwrap()
}

fn key(n: u8) -> PublicKey {
    format!("ed25519:{}", near_sdk::bs58::encode([n; 32]).into_string())
        .parse()
        .unwrap()
}

fn call_at(predecessor: &str, signer_pk: PublicKey, now: u64, results: Vec<PromiseResult>) {
    let deposit = if predecessor == WALLET { 1 } else { 0 };
    let ctx = VMContextBuilder::new()
        .current_account_id(acc(CONTRACT))
        .predecessor_account_id(acc(predecessor))
        .signer_account_id(acc(predecessor))
        .signer_account_pk(signer_pk)
        .attached_deposit(NearToken::from_yoctonear(deposit))
        .block_timestamp(now * 1_000_000_000)
        .build();
    testing_env!(
        ctx,
        near_sdk::test_vm_config(),
        near_sdk::RuntimeFeesConfig::test(),
        Default::default(),
        results
    );
}

fn agent_at(now: u64) {
    call_at(CONTRACT, key(1), now, vec![])
}

fn callback_at(now: u64, result: PromiseResult) {
    call_at(CONTRACT, key(201), now, vec![result]);
}

fn expect_err<R>(code: &str, f: impl FnOnce() -> R) -> String {
    let err = match catch_unwind(AssertUnwindSafe(f)) {
        Ok(_) => panic!("expected {code}, but the call succeeded"),
        Err(e) => e,
    };
    let msg = err
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| err.downcast_ref::<&str>().map(|s| s.to_string()))
        .unwrap_or_default();
    let msg = match msg.split_once("panic_msg: \"") {
        Some((_, rest)) => rest.trim_end_matches("\" })").to_string(),
        None => msg,
    };
    assert!(
        msg.starts_with(&format!("{code}: ")),
        "expected {code}, got {msg:?}"
    );
    msg
}

// ---------- the passkey owner ----------

fn owner_key() -> SigningKey {
    SigningKey::from_slice(&[0x11; 32]).unwrap()
}

/// Submits owner calls with fresh passkey assertions, as the dashboard does.
struct Owner {
    nonce: u64,
}

impl Owner {
    /// An assertion over (`method`, borsh `args`) with the next nonce, at block time `now`.
    fn sign(&mut self, method: &str, args: Vec<u8>, now: u64) -> OwnerAssertion {
        self.nonce += 1;
        let expires_at = now + 300;
        let challenge = URL_SAFE_NO_PAD.encode(owner_challenge(
            CONTRACT, "testnet", method, &args, self.nonce, expires_at,
        ));
        let mut auth_data = env::sha256_array(RP_ID.as_bytes()).to_vec();
        auth_data.push(0x05);
        auth_data.extend_from_slice(&0u32.to_be_bytes());
        let cdj = format!(
            r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"{ORIGIN}","crossOrigin":false}}"#
        );
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&env::sha256_array(cdj.as_bytes()));
        let sig: Signature = Signer::sign(&owner_key(), &signed);
        // Any account may submit a passkey call; the relayer does here.
        call_at(RELAY, key(200), now, vec![]);
        OwnerAssertion {
            authenticator_data: Base64VecU8(auth_data),
            client_data_json: cdj,
            signature: Base64VecU8(sig.to_bytes().to_vec()),
            owner_nonce: self.nonce,
            expires_at,
        }
    }
}

fn args<A: borsh::BorshSerialize>(a: &A) -> Vec<u8> {
    borsh::to_vec(a).unwrap()
}

// ---------- fixtures ----------

fn worker_a() -> WorkerKey {
    WorkerKey::from_bytes(&[0xa1; 32])
}

/// The key OutLayer would derive for another build (another code hash).
fn worker_b() -> WorkerKey {
    WorkerKey::from_bytes(&[0xb2; 32])
}

fn config(code_hash: &str, worker: &WorkerKey) -> PrivateSepaConfig {
    PrivateSepaConfig {
        outlayer: acc(OUTLAYER),
        wasm_url: format!("https://test.fastfs.io/owner.testnet/outlayer.testnet/{code_hash}.wasm"),
        code_hash: code_hash.into(),
        worker_pk: hex::encode(worker.verifying_key().as_bytes()),
        secrets_owner: acc(WALLET),
        secrets_profile: "priv2".into(),
    }
}

fn commitment() -> String {
    iban_commitment(IBAN, &SALT)
}

fn mandate() -> Mandate {
    let rail = |max: u128, budget: u128| RailMandate {
        amount_range: AmountRange {
            min: U128(1),
            max: U128(max),
        },
        budget: U128(budget),
        period_secs: 604_800,
    };
    Mandate {
        x402: rail(10_000, 25_000),
        sepa: rail(50 * EURE_UNIT, 200 * EURE_UNIT),
        usdc_address: USDC.into(),
        eure_address: EURE.into(),
        chain_id: 84532,
        float_cap: FloatCap {
            usdc: U128(25_000_000),
            eure: U128(250 * EURE_UNIT),
        },
        max_validity_secs: 300,
    }
}

fn supplier(id: &str, cap: u128) -> Payee {
    Payee::Sepa {
        supplier: id.into(),
        name: "Acme GmbH".into(),
        iban_commitment: commitment(),
        cap: U128(cap),
    }
}

/// Passkey contract; agent A (key 1) with the mandate; suppliers `acme` (cap €50, opted in)
/// and `beta` (cap €10, opted in) payable from `T`; worker A pinned.
fn setup() -> (Contract, Owner) {
    call_at("deployer.testnet", key(200), NOW, vec![]);
    let mut c = Contract::new(
        OwnerMode::Passkey {
            public_key: Base64VecU8(
                owner_key()
                    .verifying_key()
                    .to_encoded_point(true)
                    .as_bytes()
                    .to_vec(),
            ),
            rp_id: RP_ID.into(),
            origin: ORIGIN.into(),
        },
        "testnet".into(),
        acc(MPC),
    );
    let mut o = Owner { nonce: 0 };
    let sc = SweepConfig {
        safe_address: "0x5afe000000000000000000000000000000000001".into(),
        usdc_address: USDC.into(),
        eure_address: EURE.into(),
        chain_id: 84532,
    };
    let evm = mock_mpc::agent_evm();
    let a = o.sign(
        "add_agent",
        args(&(&AGENT.to_string(), &key(1), &sc, &evm)),
        NOW,
    );
    let _ = c.add_agent(AGENT.into(), key(1), sc, evm, Some(a));
    callback_at(NOW, PromiseResult::Successful(vec![]));
    assert!(c.on_agent_key_added(AGENT.into(), key(1)));
    let a = o.sign("set_mandate", args(&(&AGENT.to_string(), &mandate())), NOW);
    c.set_mandate(AGENT.into(), mandate(), Some(a));
    for (id, cap) in [("acme", 50 * EURE_UNIT), ("beta", 10 * EURE_UNIT)] {
        let p = supplier(id, cap);
        let a = o.sign("add_payee", args(&(&AGENT.to_string(), &p)), NOW);
        c.add_payee(AGENT.into(), p, Some(a));
        set_private(&mut c, &mut o, id, true, NOW);
    }
    pin(&mut c, &mut o, Some(config(HASH_A, &worker_a())), NOW);
    (c, o)
}

fn set_private(c: &mut Contract, o: &mut Owner, id: &str, private: bool, now: u64) {
    let a = o.sign(
        "set_supplier_private",
        args(&(&AGENT.to_string(), &id.to_string(), &private)),
        now,
    );
    c.set_supplier_private(AGENT.into(), id.into(), private, Some(a));
}

fn pin(c: &mut Contract, o: &mut Owner, cfg: Option<PrivateSepaConfig>, now: u64) {
    let a = o.sign("set_private_sepa_config", args(&(&cfg,)), now);
    c.set_private_sepa_config(cfg, Some(a));
}

fn private_req(supplier: &str, amount: &str, invoice: &str) -> Shape {
    Shape::PrivatePayout(PrivatePayoutRequest {
        supplier: supplier.into(),
        iban_commitment: commitment(),
        amount: amount.into(),
        invoice_id: invoice.into(),
        invoice_amount: "1000".into(),
        timestamp: T,
    })
}

fn rkey(id: &str) -> RequestKey {
    RequestKey {
        agent: AGENT.into(),
        caller: Caller::Agent,
        request_id: id.into(),
    }
}

/// Agent A requests `shape` at `T`; returns the worker input sent to OutLayer.
fn request(c: &mut Contract, id: &str, shape: Shape) -> WorkerInput {
    agent_at(T);
    let _ = c.request_signature(id.into(), shape);
    let receipts = get_created_receipts();
    let call = receipts
        .iter()
        .find(|r| r.receiver_id == acc(OUTLAYER))
        .expect("request_execution receipt");
    let [MockAction::FunctionCallWeight {
        method_name,
        args,
        attached_deposit,
        ..
    }] = &call.actions[..]
    else {
        panic!("unexpected actions {:?}", call.actions)
    };
    assert_eq!(method_name, b"request_execution");
    assert_eq!(*attached_deposit, NearToken::from_millinear(10));
    let args: Value = serde_json::from_slice(args).unwrap();
    serde_json::from_str(args["input_data"].as_str().unwrap()).unwrap()
}

/// What the real worker prints for `input`: the digest of the template text, signed by `key`.
fn worker_output(key: &WorkerKey, input: &WorkerInput) -> Value {
    let text = format!("Send EUR {} to {IBAN} at {}", input.amount, input.at);
    let digest = format!("0x{}", hex::encode(eip191_digest(&text)));
    signed_output(key, input, &digest)
}

fn signed_output(key: &WorkerKey, input: &WorkerInput, digest: &str) -> Value {
    let msg = worker_message(
        &input.nonce,
        &input.supplier,
        &input.iban_commitment,
        &input.amount,
        &input.at,
        digest,
    );
    let sig = ed25519_dalek::Signer::sign(key, msg.as_bytes());
    json!({ "nonce": input.nonce, "digest": digest, "sig": hex::encode(sig.to_bytes()) })
}

/// The OutLayer callback for request `id` delivering `result`, at `now`.
fn deliver(
    c: &mut Contract,
    id: &str,
    code_hash: &str,
    result: PromiseResult,
    now: u64,
) -> PromiseOrValue<Reservation> {
    callback_at(now, result);
    c.on_worker_result(rkey(id), code_hash.into())
}

fn ok(v: &Value) -> PromiseResult {
    PromiseResult::Successful(serde_json::to_vec(v).unwrap())
}

fn mpc_sign_digest() -> Option<String> {
    get_created_receipts()
        .iter()
        .filter(|r| r.receiver_id == acc(MPC))
        .find_map(|r| match &r.actions[..] {
            [MockAction::FunctionCallWeight {
                method_name, args, ..
            }] if method_name == b"sign" => {
                let v: Value = serde_json::from_slice(args).unwrap();
                v["request"]["payload_v2"]["Ecdsa"]
                    .as_str()
                    .map(String::from)
            }
            _ => None,
        })
}

fn status(c: &Contract, id: &str) -> RequestStatus {
    c.get_request(rkey(id)).unwrap().status
}

fn assert_refused(c: &mut Contract, id: &str, code_hash: &str, result: PromiseResult) {
    let out = deliver(c, id, code_hash, result, T + 15);
    assert!(matches!(out, PromiseOrValue::Value(_)), "must not sign");
    drop(out);
    assert_eq!(mpc_sign_digest(), None, "no MPC sign call");
    let res = c.get_request(rkey(id)).unwrap();
    assert_eq!(res.status, RequestStatus::Unknown);
    assert_eq!(res.digest, "");
    assert!(get_logs()
        .iter()
        .any(|l| l.contains(r#""reason":"worker_unverified""#)));
}

// ---------- the worker pin: passkey only ----------

#[test]
fn pin_is_set_with_the_passkey_and_shown_in_the_config() {
    let (c, _) = setup();
    let cfg = c.get_config().private_sepa.unwrap();
    assert_eq!(cfg, config(HASH_A, &worker_a()));
}

#[test]
fn setting_the_pin_without_the_passkey_is_refused() {
    let (mut c, mut o) = setup();
    // Passkey mode, no assertion.
    call_at(WALLET, key(200), T, vec![]);
    expect_err("ERR_ASSERTION_REQUIRED", || {
        c.set_private_sepa_config(Some(config(HASH_B, &worker_b())), None)
    });
    // An assertion the owner signed for other arguments (the old pin) does not carry over.
    let a = o.sign(
        "set_private_sepa_config",
        args(&(&Some(config(HASH_A, &worker_a())),)),
        T,
    );
    expect_err("ERR_ASSERTION_BAD_CHALLENGE", || {
        c.set_private_sepa_config(Some(config(HASH_B, &worker_b())), Some(a))
    });
    // An assertion for another owner method does not either.
    let a = o.sign(
        "set_relayer",
        args(&(&Some(config(HASH_B, &worker_b())),)),
        T,
    );
    expect_err("ERR_ASSERTION_BAD_CHALLENGE", || {
        c.set_private_sepa_config(Some(config(HASH_B, &worker_b())), Some(a))
    });
    assert_eq!(c.get_config().private_sepa.unwrap().code_hash, HASH_A);
}

#[test]
fn a_wallet_owner_cannot_set_the_pin() {
    call_at("deployer.testnet", key(200), NOW, vec![]);
    let mut c = Contract::new(
        OwnerMode::Wallet {
            account: acc(WALLET),
        },
        "testnet".into(),
        acc(MPC),
    );
    call_at(WALLET, key(200), NOW, vec![]);
    expect_err("ERR_PASSKEY_REQUIRED", || {
        c.set_private_sepa_config(Some(config(HASH_A, &worker_a())), None)
    });
    assert_eq!(c.get_config().private_sepa, None);
}

#[test]
fn malformed_pin_is_refused() {
    let (mut c, mut o) = setup();
    let mut bad = vec![];
    let mut b = config(HASH_B, &worker_b());
    b.code_hash = HASH_B[..62].into();
    bad.push(b);
    let mut b = config(HASH_B, &worker_b());
    b.code_hash = format!("{}zz", &HASH_B[..62]);
    bad.push(b);
    let mut b = config(HASH_B, &worker_b());
    b.worker_pk = "00".repeat(31);
    bad.push(b);
    let mut b = config(HASH_B, &worker_b());
    b.wasm_url = "http://insecure.example/w.wasm".into();
    bad.push(b);
    let mut b = config(HASH_B, &worker_b());
    b.secrets_profile = "a b".into();
    bad.push(b);
    let mut b = config(HASH_B, &worker_b());
    b.outlayer = acc(CONTRACT);
    bad.push(b);
    for cfg in bad {
        let a = o.sign("set_private_sepa_config", args(&(&Some(cfg.clone()),)), T);
        expect_err("ERR_INVALID_WORKER_CONFIG", || {
            c.set_private_sepa_config(Some(cfg.clone()), Some(a))
        });
    }
    // Uppercase hex is stored lowercase.
    let mut up = config(HASH_B, &worker_b());
    up.code_hash = HASH_B.to_ascii_uppercase();
    pin(&mut c, &mut o, Some(up), T);
    assert_eq!(c.get_config().private_sepa.unwrap().code_hash, HASH_B);
}

// ---------- the happy path ----------

#[test]
fn verified_worker_digest_is_sent_to_the_mpc_and_no_iban_leaves_the_contract() {
    let (mut c, _) = setup();
    let input = request(&mut c, "priv-1", private_req("acme", "42.50", "INV-1"));
    assert_eq!(
        input,
        WorkerInput {
            nonce: input.nonce.clone(),
            supplier: "acme".into(),
            iban_commitment: commitment(),
            amount: "42.5".into(),
            at: "2026-11-03T06:08:20Z".into(),
        }
    );
    let res = c.get_request(rkey("priv-1")).unwrap();
    assert_eq!(res.status, RequestStatus::Pending);
    assert_eq!(res.shape, ShapeKind::PrivatePayout);
    assert_eq!(res.digest, "");
    assert_eq!(res.amount, U128(42 * EURE_UNIT + EURE_UNIT / 2));
    assert_eq!(
        c.get_budget(AGENT.into(), Rail::Sepa).unwrap().reserved,
        res.amount
    );
    assert!(c.is_invoice_paid("acme".into(), "INV-1".into()));
    // Neither the OutLayer call nor any log carries the IBAN.
    for r in get_created_receipts() {
        assert!(!format!("{r:?}").contains(IBAN));
    }
    assert!(get_logs().iter().all(|l| !l.contains(IBAN)));

    let out = worker_output(&worker_a(), &input);
    let digest = out["digest"].as_str().unwrap().to_string();
    let result = deliver(&mut c, "priv-1", HASH_A, ok(&out), T + 15);
    assert!(matches!(result, PromiseOrValue::Promise(_)));
    drop(result); // a Promise is scheduled when dropped
    assert_eq!(mpc_sign_digest().as_deref(), Some(&digest[2..]));
    assert!(get_logs().iter().all(|l| !l.contains(IBAN)));
    let res = c.get_request(rkey("priv-1")).unwrap();
    assert_eq!(res.digest, digest);

    // The MPC callback then records the agent's signature as for any shape.
    callback_at(
        T + 20,
        PromiseResult::Successful(mock_mpc::sign_response(&digest)),
    );
    let res = c.on_signature(rkey("priv-1"));
    assert_eq!(res.status, RequestStatus::Signed);
    assert!(format!("{:?}", c.get_request(rkey("priv-1")))
        .find(IBAN)
        .is_none());
}

// ---------- unverified results fail closed ----------

#[test]
fn missing_or_failed_worker_result_is_refused() {
    let (mut c, _) = setup();
    request(&mut c, "p-1", private_req("acme", "1", "INV-1"));
    assert_refused(&mut c, "p-1", HASH_A, PromiseResult::Failed);
    request(&mut c, "p-2", private_req("acme", "2", "INV-2"));
    // OutLayer's yield timeout delivers `null`.
    assert_refused(&mut c, "p-2", HASH_A, ok(&Value::Null));
    request(&mut c, "p-3", private_req("acme", "3", "INV-3"));
    assert_refused(
        &mut c,
        "p-3",
        HASH_A,
        PromiseResult::Successful(b"not json".to_vec()),
    );
    // No promise result at all.
    request(&mut c, "p-4", private_req("acme", "4", "INV-4"));
    call_at(CONTRACT, key(201), T + 15, vec![]);
    assert!(matches!(
        c.on_worker_result(rkey("p-4"), HASH_A.into()),
        PromiseOrValue::Value(_)
    ));
    assert_eq!(status(&c, "p-4"), RequestStatus::Unknown);
}

#[test]
fn unverified_worker_result_is_refused() {
    let (mut c, _) = setup();
    // Unsigned.
    let input = request(&mut c, "p-1", private_req("acme", "1", "INV-1"));
    let mut v = worker_output(&worker_a(), &input);
    v.as_object_mut().unwrap().remove("sig");
    assert_refused(&mut c, "p-1", HASH_A, ok(&v));
    // A digest other than the one signed (an operator rewriting the result).
    let input = request(&mut c, "p-2", private_req("acme", "2", "INV-2"));
    let mut v = worker_output(&worker_a(), &input);
    v["digest"] = json!(format!("0x{}", "11".repeat(32)));
    assert_refused(&mut c, "p-2", HASH_A, ok(&v));
    // Signed over other fields (another amount) than the contract sent.
    let input = request(&mut c, "p-3", private_req("acme", "3", "INV-3"));
    let mut other = input.clone();
    other.amount = "40".into();
    let mut v = worker_output(&worker_a(), &other);
    v["nonce"] = json!(input.nonce);
    assert_refused(&mut c, "p-3", HASH_A, ok(&v));
    // A result for another request (replay): wrong nonce.
    let first = request(&mut c, "p-4", private_req("acme", "4", "INV-4"));
    let input = request(&mut c, "p-5", private_req("acme", "5", "INV-5"));
    let replay = worker_output(&worker_a(), &first);
    assert_ne!(first.nonce, input.nonce);
    assert_refused(&mut c, "p-5", HASH_A, ok(&replay));
    // Malformed digest and signature encodings.
    let input = request(&mut c, "p-6", private_req("acme", "6", "INV-6"));
    let upper = format!("0x{}", "AB".repeat(32));
    assert_refused(
        &mut c,
        "p-6",
        HASH_A,
        ok(&signed_output(&worker_a(), &input, &upper)),
    );
    let input = request(&mut c, "p-7", private_req("acme", "7", "INV-7"));
    let mut v = worker_output(&worker_a(), &input);
    v["sig"] = json!("00");
    assert_refused(&mut c, "p-7", HASH_A, ok(&v));
}

#[test]
fn result_from_a_build_with_another_code_hash_is_refused() {
    let (mut c, mut o) = setup();
    // Another build derives another key: its signature does not verify against the pin.
    let input = request(&mut c, "p-1", private_req("acme", "1", "INV-1"));
    assert_refused(
        &mut c,
        "p-1",
        HASH_A,
        ok(&worker_output(&worker_b(), &input)),
    );

    // The owner re-pins to build B while a request for build A is out: the A result is
    // refused (the pin changed), and so is a B-signed one for that request.
    let input = request(&mut c, "p-2", private_req("acme", "2", "INV-2"));
    pin(&mut c, &mut o, Some(config(HASH_B, &worker_b())), T + 5);
    assert_refused(
        &mut c,
        "p-2",
        HASH_A,
        ok(&worker_output(&worker_a(), &input)),
    );
    let input = request(&mut c, "p-3", private_req("acme", "3", "INV-3"));
    pin(&mut c, &mut o, Some(config(HASH_A, &worker_a())), T + 5);
    assert_refused(
        &mut c,
        "p-3",
        HASH_B,
        ok(&worker_output(&worker_b(), &input)),
    );

    // Turning the path off refuses results still in flight.
    let input = request(&mut c, "p-4", private_req("acme", "4", "INV-4"));
    pin(&mut c, &mut o, None, T + 5);
    assert_refused(
        &mut c,
        "p-4",
        HASH_A,
        ok(&worker_output(&worker_a(), &input)),
    );
    agent_at(T);
    expect_err("ERR_PRIVATE_SEPA_OFF", || {
        c.request_signature("p-5".into(), private_req("acme", "5", "INV-5"))
    });
}

#[test]
fn late_result_after_expiry_is_never_signed() {
    let (mut c, _) = setup();
    let input = request(&mut c, "p-1", private_req("acme", "1", "INV-1"));
    call_at("anyone.testnet", key(202), T + 301, vec![]);
    c.expire_pending(rkey("p-1"));
    let out = deliver(
        &mut c,
        "p-1",
        HASH_A,
        ok(&worker_output(&worker_a(), &input)),
        T + 302,
    );
    assert!(matches!(out, PromiseOrValue::Value(_)));
    assert_eq!(mpc_sign_digest(), None);
    assert_eq!(status(&c, "p-1"), RequestStatus::Unknown);
}

#[test]
fn result_after_revoke_or_opt_out_is_refused() {
    let (mut c, mut o) = setup();
    let input = request(&mut c, "p-1", private_req("acme", "1", "INV-1"));
    set_private(&mut c, &mut o, "acme", false, T + 5);
    assert_refused(
        &mut c,
        "p-1",
        HASH_A,
        ok(&worker_output(&worker_a(), &input)),
    );
    set_private(&mut c, &mut o, "acme", true, T + 5);

    let input = request(&mut c, "p-2", private_req("acme", "2", "INV-2"));
    let a = o.sign("revoke", args(&(&AGENT.to_string(),)), T + 5);
    let _ = c.revoke(AGENT.into(), Some(a));
    assert_refused(
        &mut c,
        "p-2",
        HASH_A,
        ok(&worker_output(&worker_a(), &input)),
    );
}

// ---------- AP1 rules on the private path ----------

#[test]
fn private_path_needs_an_opted_in_supplier() {
    let (mut c, mut o) = setup();
    set_private(&mut c, &mut o, "acme", false, T);
    agent_at(T);
    expect_err("ERR_SUPPLIER_NOT_PRIVATE", || {
        c.request_signature("p-1".into(), private_req("acme", "1", "INV-1"))
    });
    // A refused request uses up no invoice id.
    assert!(!c.is_invoice_paid("acme".into(), "INV-1".into()));
    expect_err("ERR_UNKNOWN_SUPPLIER", || {
        let a = o.sign(
            "set_supplier_private",
            args(&(&AGENT.to_string(), &"nobody".to_string(), &true)),
            T,
        );
        c.set_supplier_private(AGENT.into(), "nobody".into(), true, Some(a))
    });
}

#[test]
fn cooling_off_applies_on_the_private_path() {
    let (mut c, mut o) = setup();
    // Before the first IBAN's cooling-off ends.
    agent_at(T - 61);
    let mut r = private_req("acme", "1", "INV-1");
    if let Shape::PrivatePayout(p) = &mut r {
        p.timestamp = T - 61;
    }
    expect_err("ERR_BANK_CHANGE_COOLING_OFF", || {
        c.request_signature("p-1".into(), r)
    });
    // A bank change: the new commitment cools off, the old one stays payable.
    let new = iban_commitment("GB33BUKB20201555555555", &SALT);
    let a = o.sign(
        "change_supplier_iban",
        args(&(&AGENT.to_string(), &"acme".to_string(), &new)),
        T,
    );
    c.change_supplier_iban(AGENT.into(), "acme".into(), new.clone(), Some(a));
    let mut r = private_req("acme", "2", "INV-2");
    if let Shape::PrivatePayout(p) = &mut r {
        p.iban_commitment = new.to_ascii_uppercase().replacen("0X", "0x", 1);
    }
    agent_at(T);
    expect_err("ERR_BANK_CHANGE_COOLING_OFF", || {
        c.request_signature("p-2".into(), r)
    });
    request(&mut c, "p-3", private_req("acme", "3", "INV-3"));
    // An unknown commitment.
    let mut r = private_req("acme", "4", "INV-4");
    if let Shape::PrivatePayout(p) = &mut r {
        p.iban_commitment = format!("0x{}", "cd".repeat(32));
    }
    agent_at(T);
    expect_err("ERR_IBAN_NOT_ALLOWED", || {
        c.request_signature("p-4".into(), r)
    });
    let mut r = private_req("acme", "5", "INV-5");
    if let Shape::PrivatePayout(p) = &mut r {
        p.iban_commitment = "0x12".into();
    }
    expect_err("ERR_INVALID_COMMITMENT", || {
        c.request_signature("p-5".into(), r)
    });
}

#[test]
fn invoice_is_paid_exactly_once_across_both_paths() {
    let (mut c, _) = setup();
    request(&mut c, "p-1", private_req("acme", "1", "INV-1"));
    agent_at(T);
    let msg = expect_err("ERR_DUPLICATE_INVOICE", || {
        c.request_signature("p-2".into(), private_req("acme", "2", "inv-1"))
    });
    assert!(msg.contains("already paid"));
    // Paid on the private path: shape 3 refuses it too, and the reverse.
    let shape3 = |invoice: &str| {
        Shape::Payout(PayoutRequest {
            supplier: "acme".into(),
            iban: IBAN.into(),
            salt: format!("0x{}", hex::encode(SALT)),
            amount: "3".into(),
            invoice_id: invoice.into(),
            invoice_amount: "1000".into(),
            timestamp: T,
        })
    };
    expect_err("ERR_DUPLICATE_INVOICE", || {
        c.request_signature("p-3".into(), shape3("INV-1"))
    });
    agent_at(T);
    let _ = c.request_signature("p-4".into(), shape3("INV-9"));
    agent_at(T);
    expect_err("ERR_DUPLICATE_INVOICE", || {
        c.request_signature("p-5".into(), private_req("acme", "4", "INV-9"))
    });
}

#[test]
fn caps_and_budget_apply_on_the_private_path() {
    let (mut c, _) = setup();
    agent_at(T);
    // beta's supplier cap is €10.
    expect_err("ERR_OVER_SUPPLIER_CAP", || {
        c.request_signature("p-1".into(), private_req("beta", "10.01", "INV-1"))
    });
    // The mandate's per-payment cap is €50.
    expect_err("ERR_OVER_PER_PAYMENT_CAP", || {
        c.request_signature("p-2".into(), private_req("acme", "50.01", "INV-2"))
    });
    let mut r = private_req("acme", "20", "INV-3");
    if let Shape::PrivatePayout(p) = &mut r {
        p.invoice_amount = "19.99".into();
    }
    expect_err("ERR_OVER_INVOICE_AMOUNT", || {
        c.request_signature("p-3".into(), r)
    });
    expect_err("ERR_INVALID_AMOUNT", || {
        c.request_signature("p-4".into(), private_req("acme", "1.234", "INV-4"))
    });
    let mut r = private_req("acme", "5", "INV-5");
    if let Shape::PrivatePayout(p) = &mut r {
        p.timestamp = T + 61;
    }
    expect_err("ERR_TIMESTAMP_FUTURE", || {
        c.request_signature("p-5".into(), r)
    });
    // A supplier that is not listed cannot be opted in, so it is refused first as not private.
    expect_err("ERR_SUPPLIER_NOT_PRIVATE", || {
        c.request_signature("p-6".into(), private_req("nobody", "1", "INV-6"))
    });
    // The SEPA budget is €200 per week: four €50 payouts fit, the fifth does not.
    for i in 0..4 {
        let mut r = private_req("acme", "50", &format!("B-{i}"));
        if let Shape::PrivatePayout(p) = &mut r {
            p.timestamp = T - i; // D3 refuses the same (payee, amount, timestamp) twice
        }
        request(&mut c, &format!("b-{i}"), r);
    }
    agent_at(T);
    expect_err("ERR_OVER_BUDGET", || {
        c.request_signature("b-4".into(), private_req("acme", "0.01", "B-4"))
    });
    assert_eq!(
        c.get_budget(AGENT.into(), Rail::Sepa).unwrap().reserved,
        U128(200 * EURE_UNIT)
    );
}

#[test]
fn removing_a_supplier_opts_it_out() {
    let (mut c, mut o) = setup();
    let p = supplier("acme", 50 * EURE_UNIT);
    let a = o.sign("remove_payee", args(&(&AGENT.to_string(), &p)), T);
    c.remove_payee(AGENT.into(), p, Some(a));
    assert!(!c.is_supplier_private(AGENT.into(), "acme".into()));
    assert!(c.is_supplier_private(AGENT.into(), "beta".into()));
}

#[test]
fn revoking_the_agent_opts_its_suppliers_out() {
    let (mut c, mut o) = setup();
    let a = o.sign("revoke", args(&(&AGENT.to_string(),)), T);
    let _ = c.revoke(AGENT.into(), Some(a));
    assert!(c.get_suppliers(AGENT.into()).is_empty());
    assert!(!c.is_supplier_private(AGENT.into(), "acme".into()));
    assert!(!c.is_supplier_private(AGENT.into(), "beta".into()));
}

fn shape3(amount: &str, invoice: &str) -> Shape {
    Shape::Payout(PayoutRequest {
        supplier: "acme".into(),
        iban: IBAN.into(),
        salt: format!("0x{}", hex::encode(SALT)),
        amount: amount.into(),
        invoice_id: invoice.into(),
        invoice_amount: "1000".into(),
        timestamp: T,
    })
}

#[test]
fn private_order_is_not_signed_again_on_shape_3() {
    let (mut c, _) = setup();
    request(&mut c, "p-1", private_req("acme", "5", "INV-A"));
    agent_at(T);
    expect_err("ERR_DUPLICATE_PAYOUT", || {
        c.request_signature("p-2".into(), shape3("5", "INV-B"))
    });
    // Another amount is another order.
    agent_at(T);
    let _ = c.request_signature("p-3".into(), shape3("6", "INV-C"));
}

#[test]
fn shape_3_order_is_not_signed_again_on_the_private_path() {
    let (mut c, _) = setup();
    agent_at(T);
    let _ = c.request_signature("p-1".into(), shape3("5", "INV-A"));
    agent_at(T);
    expect_err("ERR_DUPLICATE_PAYOUT", || {
        c.request_signature("p-2".into(), private_req("acme", "5", "INV-B"))
    });
    request(&mut c, "p-3", private_req("acme", "6", "INV-C"));
}
