# Evidence

## IronClaw live run (NEAR AI Cloud, NEAR testnet, PayPal sandbox)

[ironclaw-live.md](ironclaw-live.md) and [ironclaw-live.jsonl](ironclaw-live.jsonl): IronClaw on the owner's agent.near.ai instance drives the buyer MCP over `--http`. One payment paid, a lookalike and an over-cap invoice held, the contract's cap refusal, the owner's revoke, and IronClaw's next attempt failing. Ids only, payees masked.

### Screen recording of a second run (Nov 14)

[ironclaw-live-nov14.mp4](ironclaw-live-nov14.mp4): the owner typed the same five prompts into the IronClaw WebUI and recorded the screen. The file is a 78 s cut of a 6 min 10 s recording: waits are sped up (the factor is shown), a caption band is added on top, and the sandbox payee address is masked. Fresh agent `ironclaw-2` on the same contract (`nearh-ph2-1794482268.testnet`) and mandate, the same four sandbox invoices, nearh-paypal's buyer MCP.

- **Paid once:** USD 84, request `pay-83c626ab-b2fc-415e-842f-5f2689f705df`, NEAR tx `6SPZHJLqr5AMGcC2qfDdDL9XQ27o5apn3bqjeNszqQ9W`, PayPal payout batch `FFCVAN3VK6P6U` (PENDING when recorded). As on Nov 13, IronClaw's first call ended in its own `network_error` after about 30 s while the payout was running, and its retry was blocked with `DUPLICATE_INVOICE`.
- **Held by the scam check, nothing signed:** the lookalike shop, USD 39 (`pay-78ebb877-c2f7-483d-8deb-c5bb98f5c32d`, "unknown payee"), and the USD 149 invoice (`pay-b606ff94-3e16-4581-a4c6-723c99178d1d`, "changed PayPal payee").
- **After the revoke:** the USD 12 request (`pay-917729c0-c503-47e5-b321-96921633127a`) was created at 16:52:58Z and passed the scam check; the owner's revoke landed at 16:53:09Z (NEAR tx `Yntcg3HKhs6uqaKqN6mCkbXiVbyCGrBc1JSiYRVVpJg`) and deleted the agent's key, so NEAR rejected the agent's transaction with `AccessKeyNotFound`. The receipt is `unknown` / `uncertain`; nothing was submitted to PayPal.
- **Not in the video:** the owner steps ran from a script between prompts 4 and 5. The USD 149 payment sent straight to the contract with the agent's key was refused with `ERR_OVER_PER_PAYMENT_CAP` (NEAR tx `3qcPEgRdgDvCdsdFntCbppvRtxGJ44Gr5CXMuMKnrX9H`), then the revoke.
- **Limits:** there is no jsonl transcript for this run; the video and the transactions above are the record. The holds are the scam check's, not the contract's.

## Scam check model run (NEAR AI Cloud, NEAR testnet, Monerium sandbox)

[scam-check-model-live.json](scam-check-model-live.json): `pay_sepa` through the buyer MCP with the scam check on (`deepseek-ai/DeepSeek-V4.1-Flash-1017`), contract `nearh-e2e-1794644865.testnet`, agent-5, EUR 1.00 each to one approved supplier. Each record has the invoice text sent, the status, and for held requests the check's verdict with its reason and model. IBANs are masked to their last 4.

- **With payment history** (run `6c03c907…`): a normal invoice got `ok`, was signed and submitted to the Monerium sandbox. Three scam invoices to the same IBAN and amount were held with `suspicious`, each verdict carrying the model's name and reason: a request to pay a different account confidentially without calling, a prompt injection telling the agent to skip all checks, and a "CEO gift cards" request. Nothing was signed for them (`signing_started: false`). None contains a word from the keyword list in `scamcheck/src/check.ts`, and the payee and amount pass the local rules, so these verdicts come from the model.
- **Without payment history** (run `276b6620…`): the model held the same legitimate first payment three times out of three ("no payee history"). The first payment in the other run was therefore made with the check skipped (`scam_check: "skipped"`), which is what created the history. In the E1 run below the model passed two first payments, so its answer to a first payment is not stable.
- **After the prompt change** (run `76c1a42e…`, agent-6): the prompt now tells the model that `payee_known` means the owner approved the payee and that a first payment to such a payee is not a red flag by itself. With the check on from the start, the first payment got `ok` and was submitted, a prompt-injection invoice and a pay-a-different-account invoice were held, and a second normal invoice got `ok`. An offline probe with this prompt gave `ok` for 10 of 10 first payments and 3 of 3 normal invoices with history, and `suspicious` for 15 of 15 scam invoices. The new red-flag lines in the prompt name secrecy and instructions to the agent, which is what two of these test invoices contain, so this is not an independent test set.
- **What the model is sent:** since that change, the request without the salt and with every IBAN masked to its last 4 characters, in the payment data, the memo and the invoice text (`promptPaymentData` in `scamcheck/src/check.ts`, with a test). The two earlier runs above sent the sandbox IBAN and its salt to NEAR AI.
- **Limits:** one live attempt per scam invoice (an offline probe of the same three texts gave `suspicious` three times each, and `ok` three times for the normal one). `signature_verified` is `false`: nearH's check does not verify NEAR AI's response signature. Three earlier requests, sent before the supplier's cooling-off had ended, were held by the local "unknown payee" rule and are not in the file.
- Afterwards the owner revoked agent-5 and the relayer swept its remaining EURe back to the Safe (`cleanup` in the file).

## E1 live run (NEAR testnet, Base Sepolia, Monerium sandbox)

[e1-d1ca04a8-4ef4-4a6d-8f9a-faccd15173a3.json](e1-d1ca04a8-4ef4-4a6d-8f9a-faccd15173a3.json): `pnpm demo --run`, `complete: true`, on contract `nearh-e2e-1794644865.testnet` with agent-4 and the AI scam check on (`NEAR_AI_API_KEY` set, model `deepseek-ai/DeepSeek-V4.1-Flash-1017`). An earlier run of the same day with agent-3 and the scam check skipped is [e1-4522641b-ff25-4d33-9e0a-b32850f5975a.json](e1-4522641b-ff25-4d33-9e0a-b32850f5975a.json). Each record carries its NEAR or Base Sepolia tx hash, request id or Monerium order id; no keys, tokens or IBANs.

- Owner: `set_mandate`, then USDC and EURe top-ups from the Safe `0x262F…83AF` to the agent EOA.
- Agent: one x402 purchase, settled in USDC; one EUR 1.00 SEPA payout order submitted to the Monerium sandbox (not bank settlement).
- Held by the scam check: a SEPA payout to a changed bank account with urgent wording (`poisoned-invoice`, `held`); nothing was signed and no request reached the contract. The verdict, "urgency wording in invoice text", is kept in the private held queue and receipt, not in the evidence file. It comes from the check's local keyword rule (`deterministicCheck`), which runs before the model, so the model was not asked about this invoice. The model answered `ok` for the two real payments above (`scam_check: "ok"` in their private receipts).
- Refused by the contract: a payment to an unlisted payee (`ERR_PAYEE_NOT_ALLOWED`), a second request while the first was still pending (`ERR_OVER_BUDGET`), and a payment after the owner's revoke.
- Sweeps: the agent's USDC (owner-requested, submitted by the relayer) and EURe (relayer-requested, gas funded by the relayer) back to the Safe.

How it differs from the target setup: owner NEAR calls were signed with the software owner key from `pnpm keygen`, not a browser passkey; the Safe is an ordinary Safe v1.4.1 whose top-ups were executed by a throwaway EOA added as an owner, not the passkey Safe of scripts/owner/safe; the relayer NEAR account is the submitter account. With the scam check first switched on, every payment was held with "Empty response from NEAR AI": the reasoning model spent the 200-token limit before answering. The request now sends `max_tokens: 1024` and `reasoning_effort: "none"`. In the agent-3 run, a first attempt stopped at the SEPA step because M1 read the reservation at `final` before the MPC signature was final (`M1_NOT_SIGNED`); M1 now re-reads a pending reservation for up to ~10 s.

## AP2 accountant export: fixture data, not a testnet run

The sample export is built from **fixture events**, not from NEAR testnet receipts (the AP1 testnet run below has not been exported).

| File | What it is |
|---|---|
| `ap2-fixture-recording.json` | `source: "fixture"`. Eight contract receipts (block height, timestamp, status, `EVENT_JSON` logs) in the shapes of docs/interfaces.md §5, following the sandbox test `inv_104_bank_change_is_held_and_the_invoice_paid_once` with a 60 s cooling-off. Tx hashes and receipt ids are `FIXTURE-…` placeholders. |
| `ap2-fixture-salt-book.jsonl` | The owner's salt book for the fixture: two fake IBANs (country `XX`, `XX00FIXTURE000…`) with fixed salts, so no real or documentation IBAN is committed; only their last 4 reach the CSV. A real salt book stays outside the repo (`~/.config/nearh/`). |
| `ap2-fixture-export.csv` | `pnpm export-csv` output for the two files above. Its first line says it is fixture data. |

Rebuild it from `scripts/owner/near`:

```sh
pnpm export-csv ../../../demo/evidence/ap2-fixture-recording.json \
  --salts ../../../demo/evidence/ap2-fixture-salt-book.jsonl \
  --out ../../../demo/evidence/ap2-fixture-export.csv
```

`test/export.test.ts` checks that the committed CSV equals this output.

For a testnet run, `pnpm record-receipts <sender.testnet> <tx hash>...` (with `CONTRACT_ID` set) reads each tx's receipts on the contract from testnet RPC and prints a `source: "testnet"` recording to feed `export-csv`. Receipts replay in (block height, `index_in_block`) order; RPC gives no order between two txs' receipts in one block, so `export-csv` refuses those until `index_in_block` is set on them. It has not been run against testnet yet.

## AP1 INV-104 demo: one command

`pnpm demo:inv104` runs the AP1 story and prints every contract event of every step with its reason code:

1. the owner sets the bank-change cooling-off to the demo's 60 s (passkey);
2. the owner registers supplier `acme` (Acme GmbH, cap 50 EUR) at IBAN A (passkey), and the first IBAN's cooling-off passes;
3. the agent pays INV-104, EUR 42.50, to IBAN A: `payout_approved`, signed;
4. "we changed banks": the owner moves acme to IBAN B (passkey): `supplier_iban_pending` with `effective_at`;
5. the agent pays INV-105 to IBAN B during the cooling-off: `payout_refused`, `ERR_BANK_CHANGE_COOLING_OFF`;
6. the agent pays INV-104 again to IBAN A: `payout_refused`, `ERR_DUPLICATE_INVOICE`.

IBANs are printed as their last 4 only, and `--write` refuses to save a transcript with an unmasked IBAN-shaped string.

### Local sandbox run: `ap1-inv104-local-sandbox.txt` (not testnet)

`pnpm demo:inv104 --local --write` runs `contract/tests/integration/tests/demo_inv104.rs` in the near-workspaces sandbox: the contract built from this commit, the harness's software P-256 key as the owner passkey, the mock MPC signer and fixture IBANs (`XX00FIXTURE…`). Nothing touches NEAR testnet or Monerium. On an Intel Mac set `NEAR_SANDBOX_BIN_PATH` first (`contract/tests/integration/src/lib.rs`). The test asserts each outcome too, so it fails if a rule stops holding.

### Testnet run: owner runbook

Run once: [ap1-inv104-testnet.txt](ap1-inv104-testnet.txt) (contract `nearh-e2e-1794644865.testnet`, IBANs printed as last 4 only). The script never deploys and never creates keys; the owner does steps 1–3 once, then one command does the rest (about 3 minutes, most of it the 60 s cooling-off and MPC signing).

1. **Accounts and wasm** (scripts/owner/near README, Setup): two fresh faucet accounts, `<contract>.testnet` and `<submitter>.testnet`, and `(cd contract && cargo near build non-reproducible-wasm)` from current `main`. A contract deployed before the AP1 change does not work (the state layout changed); the preflight says so.
2. **Deploy with the owner key** (in `scripts/owner/near`, with `CONTRACT_ID`, `SUBMITTER_ACCOUNT_ID` and `SAFE_ADDRESS` exported): `pnpm keygen`, `pnpm deploy-contract`, `pnpm add-agent agent-1`, `pnpm set-mandate agent-1 examples/mandate.json`. `keygen` makes the owner's P-256 key in `$OWNER_KEY_DIR/<contract>/owner-p256.json`; on testnet the owner scripts sign with it in place of the passkey (the browser passkey is DB1). `add-agent` writes the agent's function-call key to `$OWNER_KEY_DIR/<contract>/agents/agent-1.json`.
3. **Demo config**: `cp demo/.env.example demo/.env` and fill in `CONTRACT_ID`, `SUBMITTER_ACCOUNT_ID`, `AP1_IBAN_A` and `AP1_IBAN_B` (and `OWNER_KEY_DIR` if not `~/.nearh-owner`). Use fixture IBANs such as `XX00FIXTURE0003000` / `XX00FIXTURE0005555` or Monerium sandbox ones, never a real IBAN: a payout request carries the IBAN in its public tx arguments (docs/interfaces.md, PRIV1 "Honest limit"). The agent key comes from the `add-agent` file; `AGENT_NEAR_PRIVATE_KEY` in `demo/.env` overrides it. Never pass a key on the command line.
4. **Preflight**: `pnpm demo:inv104 --testnet --check` reads the contract (read-only, sends nothing) and lists what is still missing, marking the steps that need the **owner passkey** (owner key) or the **agent key**.
5. **Run**: `pnpm demo:inv104 --testnet --write`. Each run registers a fresh supplier id (`acme-<unix time>`, or `AP1_SUPPLIER`), so INV-104 is unpaid at the start. The salts go to the owner's salt book (`~/.config/nearh/supplier-salts.jsonl`), never into the output. It stops at the first outcome that differs from the story and writes `ap1-inv104-testnet.txt` (tx hashes, events, last-4 IBANs). Read it before committing it.
6. **Optional, AP2 CSV**: the last line lists each tx with its sender for `pnpm record-receipts` (scripts/owner/near).

Payouts are signed by the MPC, not sent to Monerium.
