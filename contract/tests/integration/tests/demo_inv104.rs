//! The AP1 INV-104 demo in the sandbox, printed as a transcript: register supplier `acme` at
//! IBAN A, pay INV-104, a "we changed banks" email moves acme to IBAN B (owner passkey), a
//! payout to B is held for the 60 s cooling-off, INV-104 again is refused as a duplicate. Every
//! contract event of every step is printed with its reason code, on lines starting `DEMO `.
//!
//! `demo/ap1-inv104.ts --local` runs this test and keeps those lines. The owner passkey is the
//! harness's software P-256 key and the MPC is the mock signer: a local run, not testnet.
//! The IBANs are fixture values (country `XX`) and only their last 4 are printed.

use mandate::types::{Payee, PayoutRequest, RequestKey, RequestStatus, Shape};
use mandate_integration::fixtures::{self, agent_request};
use mandate_integration::Harness;
use near_sdk::json_types::U128;
use near_sdk::serde_json::{json, Value};
use near_workspaces::result::ExecutionFinalResult;

const AGENT: &str = "agent-1";
const IBAN_A: &str = "XX00FIXTURE0003000";
const IBAN_B: &str = "XX00FIXTURE0005555";
const COOLING_OFF_SECS: u64 = 60;

fn masked(iban: &str) -> String {
    format!("****{}", &iban[iban.len() - 4..])
}

fn invoice_payout(iban: &str, amount: &str, invoice_id: &str, timestamp: u64) -> Shape {
    Shape::Payout(PayoutRequest {
        supplier: fixtures::SUPPLIER.into(),
        iban: iban.into(),
        salt: fixtures::salt_hex(),
        amount: amount.into(),
        invoice_id: invoice_id.into(),
        invoice_amount: amount.into(),
        timestamp,
    })
}

/// Prints the step's outcome and every `EVENT_JSON` log of its receipts (failed ones too: a
/// refused payout logs `payout_refused` before it panics). Returns the outcome line.
fn print_outcome(result: &ExecutionFinalResult) -> String {
    let outcome = match result.clone().into_result() {
        Ok(_) => "OK".to_string(),
        Err(e) => {
            let text = format!("{e:?}");
            let code = text
                .find("ERR_")
                .map(|i| {
                    text[i..]
                        .chars()
                        .take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == '_')
                        .collect::<String>()
                })
                .unwrap_or(text);
            format!("REFUSED {code}")
        }
    };
    for log in result.outcomes().iter().flat_map(|o| o.logs.iter()) {
        let Some(event) = log
            .strip_prefix("EVENT_JSON:")
            .and_then(|j| near_sdk::serde_json::from_str::<Value>(j).ok())
        else {
            continue;
        };
        let reason = event["data"]["reason"].as_str().unwrap_or("-");
        println!(
            "DEMO   event {:<24} reason={:<28} data={}",
            event["event"].as_str().unwrap_or("?"),
            reason,
            event["data"]
        );
    }
    println!("DEMO   outcome: {outcome}");
    outcome
}

fn step(n: u32, title: &str) {
    println!("DEMO");
    println!("DEMO [{n}] {title}");
}

/// Sends a payout the contract should approve, answers the mock MPC, and returns the
/// finished tx (its logs) and the reservation status.
async fn approved_payout(
    h: &Harness,
    agent: &near_workspaces::Account,
    request_id: &str,
    shape: &Shape,
) -> anyhow::Result<(ExecutionFinalResult, RequestStatus)> {
    let tx = h.request_signature(agent, request_id, shape).await?;
    let key: RequestKey = agent_request(AGENT, request_id);
    let mut reserved = false;
    for _ in 0..60 {
        if h.get_request(&key).await?.is_some() {
            reserved = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    anyhow::ensure!(reserved, "{request_id} was never reserved");
    let res = h.respond_for(&key).await?;
    Ok((tx.await?, res.status))
}

#[tokio::test]
async fn demo_inv104_transcript() -> anyhow::Result<()> {
    let h = Harness::new().await?;
    let agent = h.setup_agent(AGENT).await?;
    println!("DEMO AP1 INV-104 demo: LOCAL SANDBOX RUN (near-workspaces), NOT TESTNET");
    println!(
        "DEMO contract {} | agent {AGENT} | owner: software P-256 passkey | MPC: mock signer",
        h.mandate.id()
    );
    println!(
        "DEMO IBAN A {} | IBAN B {} (fixture IBANs, last 4 only)",
        masked(IBAN_A),
        masked(IBAN_B)
    );

    step(
        1,
        "Owner sets the demo bank-change cooling-off to 60 s (passkey)",
    );
    let r = h
        .owner_call(
            "set_bank_change_cooling_off",
            near_sdk::borsh::to_vec(&(COOLING_OFF_SECS,))?,
            json!({ "secs": COOLING_OFF_SECS }),
        )
        .await?;
    assert_eq!(print_outcome(&r), "OK");

    step(
        2,
        &format!(
            "Owner registers supplier acme (Acme GmbH, cap 50 EUR) at IBAN A {} (passkey)",
            masked(IBAN_A)
        ),
    );
    let payee = Payee::Sepa {
        supplier: fixtures::SUPPLIER.into(),
        name: "Acme GmbH".into(),
        iban_commitment: fixtures::commitment(IBAN_A),
        cap: U128(50 * 10u128.pow(18)),
    };
    let r = h
        .owner_call(
            "add_payee",
            near_sdk::borsh::to_vec(&(&AGENT.to_string(), &payee))?,
            json!({ "agent": AGENT, "payee": payee }),
        )
        .await?;
    assert_eq!(print_outcome(&r), "OK");
    h.advance_secs(COOLING_OFF_SECS + 1).await?;
    println!("DEMO   (waited out the first IBAN's {COOLING_OFF_SECS} s cooling-off)");

    step(3, "Agent pays INV-104, EUR 42.50, to IBAN A");
    let now = h.now_secs().await?;
    let (r, status) = approved_payout(
        &h,
        &agent,
        "inv-104-a",
        &invoice_payout(IBAN_A, "42.50", "INV-104", now),
    )
    .await?;
    assert_eq!(print_outcome(&r), "OK");
    assert_eq!(status, RequestStatus::Signed);
    println!("DEMO   reservation: {status:?} (payout order signed by the MPC)");

    step(
        4,
        &format!(
            "\"We changed banks\" email: owner moves acme to IBAN B {} (passkey)",
            masked(IBAN_B)
        ),
    );
    let r = h
        .change_supplier_iban(AGENT, fixtures::SUPPLIER, &fixtures::commitment(IBAN_B))
        .await?;
    assert_eq!(print_outcome(&r), "OK");
    let suppliers: Value = h
        .mandate
        .view("get_suppliers")
        .args_json(json!({ "agent": AGENT }))
        .await?
        .json()?;
    println!("DEMO   get_suppliers: {suppliers}");

    step(
        5,
        "Agent pays INV-105, EUR 10, to IBAN B during the cooling-off",
    );
    let now = h.now_secs().await?;
    let r = h
        .request_tx(
            &agent,
            "inv-105-b",
            &invoice_payout(IBAN_B, "10", "INV-105", now),
        )
        .transact()
        .await?;
    assert_eq!(print_outcome(&r), "REFUSED ERR_BANK_CHANGE_COOLING_OFF");

    step(6, "Agent pays INV-104 again, EUR 42.50, to IBAN A");
    let r = h
        .request_tx(
            &agent,
            "inv-104-b",
            &invoice_payout(IBAN_A, "42.50", "INV-104", now),
        )
        .transact()
        .await?;
    assert_eq!(print_outcome(&r), "REFUSED ERR_DUPLICATE_INVOICE");
    let paid: bool = h
        .mandate
        .view("is_invoice_paid")
        .args_json(json!({ "supplier": fixtures::SUPPLIER, "invoice_id": "INV-104" }))
        .await?
        .json()?;
    println!("DEMO   is_invoice_paid(acme, INV-104) = {paid}");
    assert!(paid);

    println!("DEMO");
    println!("DEMO Result: INV-104 paid once; the new IBAN held during the cooling-off (ERR_BANK_CHANGE_COOLING_OFF); INV-104 again refused (ERR_DUPLICATE_INVOICE).");
    Ok(())
}
