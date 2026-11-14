# Threat model

What protects the money and the bank details in nearH, where in the code each protection is enforced, and which test proves it. If something isn't enforced, this document says "not covered". Every claim here comes from reading the code at the commit this file was added in. Where the code and [PLAN.md](../PLAN.md) disagree, the code wins.

Scope: NEAR testnet, Base Sepolia and the Monerium sandbox only. Nothing here has been checked against mainnet or real bank settlement.

Test locations:
- **Unit and contract tests:** `cargo test --locked` in `contract/` runs `contract/src/**` and `contract/tests/*.rs`.
- **Sandbox integration suite:** `contract/tests/integration/tests/*.rs` is a separate workspace, run with `cargo test --manifest-path contract/tests/integration/Cargo.toml`. It needs the near-workspaces sandbox, which is downloaded on Linux and Apple Silicon Macs; on an Intel Mac set `NEAR_SANDBOX_BIN_PATH` to a local build (`contract/tests/integration/src/lib.rs`).
- **TypeScript packages:** `pnpm -r test`.

## 1. Assets

| Asset | Where it lives | Why it matters |
|---|---|---|
| **Agent spending account** | **Float:** USDC or EURe in the agent EOA on Base Sepolia, an address derived by Chain Signatures from (contract, agent id). **Reserve:** the owner's Safe. | Whoever gets a valid signature from the EOA moves the float. The Safe is outside the agent's reach (`sweep` always pays into it). |
| **Owner passkey** | The owner's authenticator. The contract stores only the P-256 public key, `rp_id` and `origin` (`OwnerMode::Passkey`). | It authorizes every owner method: mandates, payees, IBAN changes, revoke, the PRIV2 worker pin and `resolve_reservation`. There is no recovery and no upgrade key. |
| **Agent key** | A NEAR function-call key on the contract's own account, held in the agent's untracked `.env`. | It can call only `request_signature`, `sweep` and `revoke_self` (`AGENT_METHOD_NAMES`), with a gas allowance of `AGENT_KEY_ALLOWANCE` = 1 NEAR. |
| **Supplier book / IBAN commitments** | **On chain:** `Supplier { iban_commitment, pending }` per agent, holding only `sha256("nearh:iban-commitment:v1" ‖ salt ‖ iban)` (PRIV1). **Off chain:** the IBANs themselves. | Changing a commitment changes where SEPA money can go. |
| **Salts** | The owner's salt book, `~/.config/nearh/supplier-salts.jsonl` (mode 0600, outside the repo). Also the agent's `pay_sepa` input, and the PRIV2 worker's encrypted `SUPPLIERS` secret. | A salt and an IBAN together open a commitment. Lose the salt and the supplier can't be paid until its IBAN is re-committed. Leak it and the commitment no longer hides the IBAN. |
| **Rail credentials** | **Monerium:** the client id and secret, held by the M1 service (`rails/monerium`) and by the owner's sandbox link client (`scripts/owner/monerium`). **Relayer:** its NEAR and Base keys. **NEAR AI:** its API key. | Monerium credentials are what turn a signed order into a bank payment. |

## 2. Actors and how far each is trusted

| Actor | Trusted for | Not trusted for |
|---|---|---|
| **Owner** (passkey holder) | Everything the contract lets an owner do. | Nothing is enforced against the owner. A compromised passkey is a full compromise (§4.12). |
| **Agent, compromised or prompt-injected** | Nothing. PLAN: "a prompt-injected model is exactly the threat". | All of it: the agent key, the MCP process and its local checks. Assume the attacker calls `request_signature` directly with the key and skips the MCP, the scam check and the policy pre-checks. |
| **Malicious seller (x402)** | Nothing. | The payment requirements it returns, its redirects, and its delivery of what was paid for. |
| **Malicious supplier / invoice sender** | Nothing. | Invoice text, invoice ids, amounts, and "our bank details changed" requests. |
| **Relayer** (`set_relayer` account, `relayer/`) | Submitting transactions and paying gas. | Not trusted to choose destinations, amounts or owner call arguments; the contract and the relayer's own checks bound what it can do (§4.10). |
| **Monerium** (sandbox) | Holding EURe and executing orders the agent EOA signed. | It is a custodian outside the contract's control. |
| **NEAR AI scam check** (`scamcheck/`) | Nothing; it is advisory. | Its verdict is not attested (`signature_verified: false`) and it runs inside the agent's own process. |
| **OutLayer** (PRIV2 TEE) | Running the pinned worker code honestly, and keeping its secrets. | The contract checks that the worker's signature is from the pinned key over request-bound fields. It cannot check that the digest is of the right IBAN (§4.8). |
| **NEAR MPC** (`v1.signer-prod.testnet`) | Signing only what the contract asks for, under the agent's derivation path. | Each signature is checked by `ecrecover` against the agent EOA before the contract records it. |

## 3. What enforces what, at a glance

| Threat | Enforced by | Status |
|---|---|---|
| Overspend per payment or per period | contract (`x402::build_x402`, `payout::check_terms`, `Contract::reserve_budget`) | covered |
| Payment to an unlisted payee | contract (`build_x402`, `payout::check_payable`) plus an M1 re-check | covered |
| Stopping an agent | contract (`revoke`, `revoke_self`, `Contract::revoke_agent`) | covered; signatures issued before revoke stay valid until they expire |
| x402 replay / double sign | contract (`eip3009_nonce`, `assert_new_request`) plus USDC's on-chain nonce | covered |
| SEPA replay / double sign | contract (D3 dedupe) plus M1 (`request_id` claim) plus Monerium (duplicate refusal) | covered for exact replays; see §4.4 |
| Bank-detail change fraud (AP1) | contract (cooling-off in `add_payee` / `change_supplier_iban`, `check_payable`) | covered |
| Invoice paid twice | contract (`paid_invoices`, `payout::invoice_key`) | covered for the same id; other spellings are not |
| IBAN privacy (PRIV1) | contract state, views and events | covered; **the shape-3 transaction arguments carry the IBAN in plaintext** |
| IBAN privacy (PRIV2) | OutLayer worker plus contract `verify_worker_result` | covered for state and arguments; residual digest guessing (§5) |
| Salt book loss or corruption | `scripts/owner/near/src/supplier.ts` `recordSalt` | covered, with one accepted race (§5) |
| Scam detection | `scamcheck` in the agent process | fails closed on errors, **fails open with no API key**, bypassable by a compromised agent |
| Relayer misbehaviour | contract caller checks plus the relayer's own verification | bounded; the relayer can delay but cannot redirect funds |

## 4. Threats

### 4.1 Spend caps (compromised agent overspends)
**Threat.** An agent with a stolen or injected key asks for as much as it can get signed.

**Enforced by.** Every payment shape is checked against the mandate as it stands at request time, and its amount is reserved before the MPC call:
- **Per-payment range:** `contract/src/shapes/x402.rs` `build_x402` (`ERR_BELOW_MINIMUM`, `ERR_OVER_PER_PAYMENT_CAP`), and `contract/src/shapes/payout.rs` `check_terms` for SEPA, which also enforces the supplier `cap` and `invoice_amount`.
- **Per-period budget per rail:** `contract/src/request.rs` `Contract::reserve_budget` sums the reservations in the current window (`budget_window`, `contract/src/state.rs`). Pending and `unknown` reservations keep counting. Only an owner `resolve_reservation(.., Released)` after `release_after` frees one (`Contract::resolve`).
- **Mandate sanity:** `contract/src/state.rs` `normalize_mandate` requires min ≥ 1, min ≤ max, `period_secs` ≤ 366 days and `max_validity_secs` within 120–300 s, and requires the mandate's addresses and chain to match the sweep config.
- **Request-count cap:** `MAX_AGENT_REQUESTS` = 64 stored requests per agent (`Contract::count_agent_request`), so a key cannot make the contract pay unbounded MPC fees.
- **Float cap (off chain only):** `scripts/owner/safe/src/float.ts` refuses a top-up that would take the EOA above `float_cap`. The contract stores `float_cap` but does not check it.

**Tests.**
- `contract/tests/c3_request.rs`: `request_over_the_rail_budget_is_rejected`, `pending_and_unknown_reservations_keep_counting`, `budget_window_rolls_forward_and_a_reservation_counts_in_its_own_window`, `rails_have_separate_budgets`, `amount_over_invoice_or_supplier_cap_is_refused`, `released_is_refused_before_release_after`, `released_after_release_after_frees_the_budget`.
- `contract/src/shapes/x402.rs`: `over_per_payment_cap_rejected`.
- `contract/src/shapes/payout.rs`: `over_cap_is_refused`, `below_minimum_is_refused`, `over_supplier_cap_and_over_invoice_are_refused`.
- `contract/tests/sec1_hardening.rs`: `agent_requests_past_the_cap_are_rejected`, `the_cap_is_per_agent`.
- `contract/tests/sec4_hardening.rs`: `period_secs_above_366_days_is_rejected`, `zero_amount_range_min_is_rejected`.
- `contract/tests/integration/tests/t2_adversarial.rs`: `pending_request_keeps_its_budget_for_the_next_one`, `policy_change_while_pending_keeps_the_reservation`, `set_mandate_does_not_restart_the_period`.
- `scripts/owner/safe/test/float.test.ts`: "a top-up above float_cap is refused".

**What is left.** A compromised agent can spend up to the full budget per period on each rail, to listed payees only. That is the design bound. `invoice_amount` is declared by the agent, so on SEPA it bounds nothing against a lying agent; the supplier cap and the budget do.

### 4.2 Revoke
**Threat.** The owner must be able to stop an agent at once, and the agent itself must be able to stop.

**Enforced by.**
- **`contract/src/lib.rs` `Contract::revoke` (owner) and `Contract::revoke_self` (agent key), both through `Contract::revoke_agent`:** `contract/src/state.rs` `clear_agent` removes the mandate, x402 payees, suppliers, PRIV2 opt-ins and the key-to-agent entry, and marks the record revoked. Then a `DeleteKey` of the agent key runs in a second receipt; `on_agent_key_deleted` never panics. A failed `DeleteKey` is retried by the next `revoke`, and its key is held in `undeleted_key_set` so `add_agent` cannot hand it to a new agent.
- **After revoke:** `live_agent_record` refuses every agent request (`ERR_AGENT_REVOKED`), and `calling_agent` refuses the deleted key (`ERR_UNKNOWN_AGENT_KEY`). A PRIV2 worker result for a revoked agent is never signed (`verified_worker_digest`, "agent revoked"). M1 refuses a revoked agent (`rails/monerium/src/payout.ts`, `M1_AGENT_REVOKED`).
- **Anyone may submit an owner-signed revoke and pay its gas** (passkey mode, `assert_owner`), so the relayer cannot block one. `pnpm owner:revoke` in `scripts/owner/near` is the owner's own path (`src/cli/revoke.ts`), and `revoke-check.ts` confirms the key is gone.

**Tests.**
- `contract/tests/c2_owner.rs`: `revoke_by_owner_clears_state_and_deletes_the_key`, `revoke_by_the_agent_itself`, `failed_delete_key_is_retried_by_the_next_revoke`, `key_waiting_for_delete_key_cannot_go_to_a_new_agent`, `agent_a_key_cannot_revoke_or_act_for_b`, `revoked_agent_takes_no_new_mandate_or_payee`, `revoked_agent_id_is_never_reused`.
- `contract/tests/c3_request.rs`: `request_after_revoke_fails`, `request_after_revoke_self_fails`, `callback_after_revoke_records_revoked_with_the_signature`.
- `contract/tests/priv2_private_sepa.rs`: `result_after_revoke_or_opt_out_is_refused`, `revoking_the_agent_opts_its_suppliers_out`.
- `contract/tests/integration/tests/t2_adversarial.rs`: `owner_revoke`, `self_revoke`, `sweep_after_owner_revoke_and_self_revoke`.
- `agent/mcp/test/buyer.test.ts`: "self-revoke uses no agent argument and reports state even when key deletion fails".
- `scripts/owner/near/test/revoke-check.test.ts`.

**What is left.**
- **Signatures issued before revoke stay valid until they expire:** for x402, at most `max_validity_secs` (≤ 300 s) via `valid_before`. A SEPA order has no expiry field: only M1 enforces `valid_before` before submitting, and Monerium's own timestamp tolerance is not measured.
- **An MPC callback that lands after revoke is still recorded,** with status `revoked` and the signature in public state (`record_signature`). M1 submits only `signed` payouts, so the SEPA order is not sent through M1. An x402 authorization recorded this way is a valid EIP-3009 signature that anyone can read and submit until `valid_before`.
- **The float stays in the EOA until someone sweeps it.** `sweep` works after revoke for the owner and the relayer.

This matches the PLAN wording: "One NEAR tx stops new signing on every rail. Authorizations already issued stay valid until they expire, and short windows bound that."

### 4.3 x402 replay and payee substitution
**Threat.** The agent's signed authorization is reused, or a seller swaps `payTo`, the asset or the network.

**Enforced by.**
- **`contract/src/shapes/x402.rs` `build_x402`:** `payTo` must be on the agent's x402 allowlist; the `asset` must be the mandate's USDC and the `network` the mandate's chain; the scheme must be `exact`; the validity is clamped to `max_validity_secs`.
- **Unique nonce:** the EIP-3009 nonce is `keccak256(borsh(agent, caller, shape tag, request_id))` (`contract/src/shapes/mod.rs` `eip3009_nonce`). `request_id` is deduped per (agent, caller) (`Contract::assert_new_request`), so the contract never signs the same nonce twice. USDC itself refuses a used nonce on chain (EIP-3009 `authorizationState`; that check is USDC's, not ours).
- **Agent MCP (`agent/mcp/src/policy.ts` `sellerUrl`, `agent/mcp/src/buyer.ts`):** only operator-allowed seller origins, no redirects, the resource URL must match, and one signature per payment operation. These checks are convenience only (§2).

**Tests.**
- `contract/src/shapes/x402.rs`: `pay_to_not_allowlisted_rejected`, `wrong_asset_rejected`, `wrong_network_rejected`, `wrong_scheme_rejected`, `long_timeout_clamped_to_max_validity`, `mandate_below_skew_never_signs_long_window`, `nonce_differs_by_caller_and_changes_digest`.
- `contract/tests/c3_request.rs`: `reused_request_id_is_rejected`, `request_id_is_deduped_per_agent`.
- `contract/tests/integration/tests/t2_adversarial.rs`: `same_request_id_from_relayer_and_agent_gets_different_nonces`.
- `agent/mcp/test/buyer.test.ts`: "scam ok cannot bypass contract rejection of swapped payTo", "x402 cannot follow a redirect, return a fake paid result, or auto retry a signature", "seller resource URL mismatch fails before signing".

**Not covered.** A listed seller that takes payment and does not deliver. The amount is still bounded by the per-payment cap.

### 4.4 SEPA payout limits and replay
**Threat.** A signed order is replayed, re-signed, sent to another IBAN, or submitted after it expires.

**Enforced by.**
- **`contract/src/shapes/payout.rs` `build_payout` / `check_terms`:**
  - the supplier must be listed;
  - (iban, salt) must open its payable commitment;
  - the amount must be canonical (D9) and within the SEPA range, the supplier cap and `invoice_amount`;
  - `timestamp` must be within `[now − (max_validity − 60 s), now + 60 s]`, so the window in which a given order can be signed is at most `max_validity_secs`.
- **`contract/src/lib.rs` `Contract::approve_payout`, D3:** the contract never signs the same (agent, iban, amount, timestamp) twice. It records both the commitment and the plaintext IBAN key (`payout_dedupe_key`), on both the shape-3 and the private path.
- **`rails/monerium/src/payout.ts` (M1) before calling Monerium:**
  - the reservation is a `signed` `payout` of a live agent;
  - the order text rebuilt from the given IBAN hashes to the signed digest;
  - the signature recovers to the agent EOA;
  - the order is not past `valid_before`;
  - the supplier is still listed with the same commitment.

  Each `request_id` is claimed once, in a file store that survives a restart.
- **Monerium:** in the sandbox spike (`spikes/monerium/RESULT.md`), resubmitting the identical signed order returned `400 Duplicate order`. M1 maps that to `MONERIUM_DUPLICATE_ORDER`.

**Tests.**
- `contract/src/shapes/payout.rs`: `stale_timestamp_is_refused`, `future_timestamp_is_refused`, `signing_window_never_exceeds_max_validity`, `dedupe_key_is_per_agent_and_fields_cannot_shift`, `canonical_amount_follows_d9`.
- `contract/tests/c3_request.rs`: `payout_is_deduped_per_agent`, `payout_is_checked_by_shape_3_and_reserved_on_sepa`.
- `contract/tests/integration/tests/t2_adversarial.rs`: `duplicate_payout_is_rejected`, `two_agents_may_sign_the_same_payout`, `payout_checks_end_to_end`.
- `rails/monerium/test/payout.test.ts`: "an attacker IBAN the contract did not sign never reaches Monerium", "a signed order to an IBAN that is not on the agent's payees never reaches Monerium", "a second submission of the same request_id is refused…", "concurrent submissions of one request_id post once", "the file store survives a restart…", "only a signed, live payout of a live agent is submitted", "Monerium's 400 Duplicate order maps to MONERIUM_DUPLICATE_ORDER…", "the service needs the payout agent's own bearer token…".

**What is left.**
- **The signature is public once the callback lands.** Whoever holds the Monerium credentials (M1's operator) can submit it, within its validity.
- **Monerium's duplicate refusal was seen once,** for an exact replay in the sandbox. Other replay variants are untested.
- **D3 is per agent by design:** two agents may each sign the same order once.

### 4.5 Bank-detail change cooling-off (AP1)
**Threat.** A fraudster (a fake "our bank details changed" email, or a compromised supplier) gets a new IBAN paid at once.

**Enforced by.**
- **Owner-only changes:** a new supplier (`Contract::add_payee`) or a changed IBAN (`Contract::change_supplier_iban`) is an owner call. The agent key cannot call either.
- **Cooling-off:** the new commitment stays `pending` for `cooling_off_secs`, 24 h by default and 60 s–30 days via `set_bank_change_cooling_off`.
  - `Supplier::settled` (`contract/src/types.rs`) promotes it only once `now ≥ effective_at`.
  - Until then, `payout::check_payable` refuses it with `ERR_BANK_CHANGE_COOLING_OFF`; the old IBAN stays payable.
  - The owner can cancel the change (`cancel_supplier_iban_change`).
  - Removing and re-adding a supplier starts a new cooling-off.
- **The same check applies on the private path** (`private_payout::build_private_payout`), and again at callback time (`verified_worker_digest`: "supplier commitment changed").
- **Scam check:** it flags "bank details changed" and similar phrases (`URGENCY_KEYWORDS`) and a changed IBAN versus payment history. This is advisory only.

**Tests.**
- `contract/tests/c3_request.rs`: `new_supplier_is_held_during_cooling_off_and_allowed_after`, `changed_iban_is_held_during_cooling_off_and_allowed_after`, `cancelled_bank_change_is_never_payable`, `remove_and_re_add_does_not_skip_the_cooling_off`, `cooling_off_is_configurable_within_bounds`, `supplier_changes_need_the_owner`.
- `contract/tests/c2_owner.rs`: `bank_detail_change_without_passkey_is_refused`.
- `contract/src/shapes/payout.rs`: `pending_iban_is_held_until_effective`.
- `contract/tests/priv2_private_sepa.rs`: `cooling_off_applies_on_the_private_path`.
- `contract/tests/integration/tests/t2_adversarial.rs`: `inv_104_bank_change_is_held_and_the_invoice_paid_once`.
- `contract/tests/integration/tests/demo_inv104.rs`: `demo_inv104_transcript`, the `pnpm demo:inv104` story, which asserts each outcome.
- `scamcheck/src/check.test.ts`: "deterministic: urgency wording is suspicious".

**What is left.** The cooling-off only helps if someone looks during the window. Nothing alerts the owner except the `supplier_iban_pending` event and the dashboard. A passkey holder can lower the cooling-off to 60 s for later changes.

### 4.6 Invoice paid exactly once
**Threat.** The same invoice is paid twice: by one agent, by two agents, or on both SEPA paths.

**Enforced by.**
- **`Contract::approve_payout`** inserts `payout::invoice_key(supplier, uppercase(invoice_id))` into `paid_invoices`; this is contract-wide, across all agents and both paths.
- **The id is used up once requested.** A refused request panics and reverts, so it uses up nothing. But once a reservation exists, the id stays used whatever becomes of the reservation.
- **The PRIV2 preconditions** (`private_sepa_for`) are checked before any state change.

**Tests.**
- `contract/tests/c3_request.rs`: `duplicate_invoice_is_refused_for_every_agent`.
- `contract/src/shapes/payout.rs`: `invoice_key_is_per_supplier_and_invoice`.
- `contract/tests/priv2_private_sepa.rs`: `invoice_is_paid_exactly_once_across_both_paths`, `private_order_is_not_signed_again_on_shape_3`, `shape_3_order_is_not_signed_again_on_the_private_path`.

**What is left.** The agent declares the invoice id, and the contract cannot read the invoice. Other spellings (`INV-104.`, `INV:104`) are other ids; only the supplier cap and the budget bound that. Exactly-once is per supplier id, so the same IBAN listed under two suppliers is two invoice namespaces (§5).

### 4.7 Private payout, PRIV1 (commitments)
**Threat.** The contract's public state shows suppliers' IBANs.

**Enforced by.**
- **Commitments only:** the contract stores, views and logs only the salted commitment (`payout::iban_commitment`). The payout reservation payload holds the commitment, not the IBAN (`PayoutTerms::into_built`).
- **Owner scripts** compute the commitment locally (`scripts/owner/near/src/supplier.ts` `ibanCommitment`, with a fresh 32-byte `newSalt` per IBAN).
- **M1 redacts IBANs** to their last 4 characters in its results and logs.

**Tests.**
- `contract/tests/c3_request.rs`: `no_plaintext_iban_in_contract_state_views_or_events` (it checks storage, views and logs), `wrong_salt_or_wrong_iban_is_refused`.
- `contract/src/shapes/payout.rs`: `commitment_is_salted_sha256_of_the_iban`, `wrong_salt_is_refused`.
- `scripts/owner/near/test/supplier.test.ts`.

**Not covered.** On shape 3, the IBAN **and** its salt are arguments of the agent's `request_signature` transaction, and NEAR transaction arguments are public. So PRIV1 keeps the IBAN out of contract state, not off chain. The agent and its host also see every IBAN and salt it pays (`agent/mcp/src/policy.ts` `sepaInput`).

### 4.8 Private payout, PRIV2 (OutLayer worker)
**Threat.** The IBAN must never appear on chain, and the worker's answer must not be forged or swapped.

**Enforced by.**
- **No IBAN in the request:** `PrivatePayoutRequest` names only the commitment. `private_payout::build_private_payout` runs the same `check_payable` and `check_terms` as shape 3.
- **Owner-controlled worker:**
  - The worker is pinned by `set_private_sepa_config`, which works in passkey mode only (`ERR_PASSKEY_REQUIRED`), with `code_hash`, `worker_pk` and an `https` `wasm_url` (`normalize_config`).
  - Each supplier is opted in by the owner (`set_supplier_private`). Removing a supplier or revoking the agent opts it out.
- **Callback checks (`Contract::on_worker_result` → `verified_worker_digest`):** the MPC is asked to sign only if all of these hold:
  - the reservation is still `pending`;
  - the agent is live;
  - the pinned `code_hash` is unchanged;
  - the supplier is still opted in;
  - its payable commitment is unchanged;
  - `private_payout::verify_worker_result` accepts an ed25519 signature by the pinned `worker_pk` over `nearh-priv2:v1|nonce|supplier|commitment|amount|at|digest`, rebuilt from the contract's own fields. The nonce is per request key (`worker_nonce`).

  Otherwise the reservation becomes `unknown` (`worker_unverified`), and the callback never panics.

**Tests.**
- `contract/tests/priv2_private_sepa.rs`: all 18 tests, especially `verified_worker_digest_is_sent_to_the_mpc_and_no_iban_leaves_the_contract`, `unverified_worker_result_is_refused`, `result_from_a_build_with_another_code_hash_is_refused`, `late_result_after_expiry_is_never_signed`, `setting_the_pin_without_the_passkey_is_refused`, `a_wallet_owner_cannot_set_the_pin`, `caps_and_budget_apply_on_the_private_path`.
- `contract/src/shapes/private_payout.rs`: `worker_message_matches_the_worker_vector`, `nonce_is_per_request_key`.
- `contract/priv2-worker/src/lib.rs` tests: the same vectors on the worker side.

**Not covered.**
- **The contract cannot check what the worker's digest hashes;** it never sees the order text. `verify_worker_result` checks only that the digest is 32 bytes of hex and that the pinned `worker_pk` signed it with the request fields; `mpc_sign` then signs it on the agent's derivation path (path = agent id, `domain_id` 0). That is the same key as the agent EOA that signs x402 and sweep payloads and holds the USDC/EURe float. So whoever holds the worker key can, after one in-mandate private payout request, get the MPC to sign **any** 32-byte digest for the agent EOA, for example an EIP-712 USDC `TransferWithAuthorization` of the whole float. The amount, cap, budget and invoice checks bind the request, not the digest. The bound is trust in the worker key: OutLayer's TEE running the pinned code, and the owner's off-chain check of its attestation. At most the agent EOA's float is at risk, which the owner keeps at or under `float_cap` (§4.1).
- **Planned fix (not built):** sign PRIV2 orders on a separate MPC path, i.e. a separate EOA that holds only EURe for private payouts, or have the worker return the order fields so the contract rebuilds the EIP-191 `Send EUR` digest itself.
- **Nothing on chain checks `worker_pk` against an attestation;** the owner must verify it off chain (`spikes/outlayer/verify_attestation.py` is a spike, not wired in).
- **No rail submits private orders yet.** M1 refuses any shape other than `payout` (`M1_NOT_A_PAYOUT`).

### 4.9 Salt-book locking
**Threat.** Concurrent owner scripts lose a salt line, or the book is world-readable or lands in the repo.

**Enforced by.** `scripts/owner/near/src/supplier.ts` `recordSalt`:
- It writes the salt **before** the owner call.
- It tightens an existing book to 0600 and writes a 0600 temp file, then renames it over the book.
- It takes a `.lock` file (`takeLock` / `placeLock` through a hard link). A lock older than 15 s is reclaimed by an atomic rename-aside (`reclaimStale`).
- It re-checks the lock token before the rename (`refreshLock`), follows symlinks, refuses a dangling one, and gitignores the temp name.

**Tests.** `scripts/owner/near/test/supplier.test.ts`:
- "concurrent owner scripts saving salts lose no entry"
- "a lock left by a crashed script is recovered once it is stale"
- "a fresh lock is never moved, even when its PID is dead"
- "a holder whose lock was reclaimed writes nothing"
- "concurrent scripts that all find the same stale lock lose no entry"
- "an existing world-readable salt book is never appended to in place"
- "a salt book that lands in the repo is gitignored wherever it lands"
- "… saves the salt before the owner call and keeps it when the call fails"

**What is left.** The accepted gap is in §5.

### 4.10 Scam check: fail-closed, and where it is not
**Threat.** A prompt-injected or scam invoice gets paid.

**Enforced by.**
- **Pre-sign check:** `scamcheck/src/check.ts` `checkScam` / `checkAndHold`, called from `agent/mcp/src/buyer.ts` `Buyer.guard` before any signature.
- **Deterministic rules run first:** urgency wording, unknown payee, a changed payTo or IBAN versus history, an amount spike over 5× the median, and malformed or future `last_seen`.
- **The model is asked only after those pass,** with the invoice marked as untrusted data.
- **Fails closed:**
  - an HTTP error, an empty or non-JSON answer, a result other than `ok` or `suspicious`, or a thrown error each give `suspicious`;
  - a timeout gives `timeout`;
  - everything that is not `ok` or `skipped` is written to the held queue and nothing is signed.
- **Owner approval of a held item needs a passkey assertion:** `agent/mcp/src/runtime.ts` `verifyOwnerDecision`.

**Tests.**
- `scamcheck/src/check.test.ts`: "API error returns suspicious not timeout", "timeout with injectable fetch", "deterministic: …", "suspicious verdict writes held item to disk", "last_seen …".
- `agent/mcp/test/buyer.test.ts`: "suspicious x402 request is held without signing or retrying payment", "held SEPA never signs or calls M1…", "real SC1 timeout holds before any signature, and without a key explicitly skips", "owner rejection of a held payment never signs; tampered approval fails closed", "owner proof verification failure prevents a forged file approval from signing".

**Not covered.**
- **Fails open without an API key:** with no `NEAR_AI_API_KEY`, `checkScam` returns `skipped` before even the deterministic rules run, and `Buyer.guard` lets the payment proceed. The test above asserts this behaviour.
- **Advisory only:** the check runs in the agent's own process, so a compromised agent skips it by calling the contract directly. Only the contract checks (§4.1–4.6) bind such an agent.
- **No attestation:** the model's verdict is not attested (`signature_verified: false`).

### 4.11 Relayer trust
**Threat.** A malicious or compromised relayer redirects funds, alters owner calls, or blocks a revoke.

**Enforced by.**
- **The contract limits what the relayer can request:**
  - The relayer may call only `sweep`, and only when it is the predecessor named by `set_relayer`.
  - `shapes::sweep::build_sweep` takes `from` and the destination (`sweep_config.safe_address`) from the stored agent record, never from the caller. The EURe fallback caps gas at `MAX_SWEEP_GAS_LIMIT` and the fee at `MAX_SWEEP_FEE_PER_GAS`.
  - Only one sweep per (agent, token) may be pending.
  - `set_relayer` cannot name the contract itself.
- **Owner calls the relayer submits** are WebAuthn assertions bound to the contract, network, method, borsh args, nonce and expiry (`contract/src/owner.rs` `verify_assertion`). The relayer can't alter one, and any account can submit one.
- **The relayer checks before it sends:**
  - `relayer/src/sweep.ts` recomputes the digest from the stored payload and recovers the signature to the agent EOA, then sends exactly what was signed.
  - `relayer/src/owner-call.ts` verifies the assertion against the owner key and journals each call, so it is not resent.

**Tests.**
- `contract/tests/c2_owner.rs`: `set_relayer_by_non_owner_is_rejected`, `set_relayer_rejects_this_contract_and_none_removes_it`, `sweep_rejects_third_account`, `agent_sweep_wrong_agent_rejected`, `valid_assertion_is_accepted_from_any_submitter_and_consumes_the_nonce`, `assertion_for_different_args_is_rejected`.
- `contract/src/shapes/sweep.rs`: `usdc_sweep_to_is_safe_address`, `eure_sweep_calldata_to_is_safe_address`, `sweep_from_is_stored_evm_address`, `eure_sweep_rejects_max_fee_over_cap`, `eure_sweep_rejects_high_gas_limit`.
- `contract/tests/integration/tests/t2_adversarial.rs`: `sweep_callers`, `second_pending_sweep_for_the_same_agent_and_token_is_rejected`, `sweep_by_a_disallowed_caller_uses_the_documented_code`.
- `relayer/test/sweep.test.ts`: "USDC sweep: a tampered or foreign reservation is refused before any send", "EURe fallback: gas above the caps, a tampered tx, or a stuck fee funds nothing".
- `relayer/test/owner-call.test.ts`: "a tampered call is refused before anything is sent", "a call signed by another key, stale, expired, or for a wallet owner is refused".

**What is left.**
- **Delay and censorship:** the relayer can refuse to submit. The owner then submits the same call from any account (`pnpm owner:revoke` in `scripts/owner/near`).
- **Griefing:**
  - A relayer can request sweeps the caller sizes; one too high just fails on chain.
  - A sweep just before an x402 payment makes that payment fail.
  - Each sweep costs the contract an MPC fee. The one-pending-per-token rule limits simultaneous sweeps, not their total: the slot frees after each callback and relayer sweeps don't count toward `MAX_AGENT_REQUESTS`, so a hostile relayer can keep spending fees until the owner rotates it.
  - It can't redirect funds.
- **A relayer key compromise** risks only the relayer's own ETH, which the EURe fallback spends on gas.

### 4.12 Owner passkey and contract keys
**Enforced by.**
- **Owner authorization:** `contract/src/owner.rs` `assert_owner` / `verify_assertion` checks the type, the exact challenge (domain, contract, network, method, args, nonce, expiry), the origin, the rpIdHash and user presence. It also checks that the nonce is above the stored one by at most 1000, that the TTL is at most 600 s, and the P-256 signature.
- **Wallet mode:** the owner must be the predecessor and attach exactly 1 yoctoNEAR.
- **No full-access key on the contract:** the deploy script deletes every full-access key on the contract account and checks that none remain (`scripts/owner/near/src/cli/deploy.ts`).

**Tests.**
- `contract/tests/c2_owner.rs`: `replayed_assertion_is_rejected`, `expired_assertion_is_rejected`, `assertion_with_too_long_ttl_is_rejected`, `wrong_rp_id_hash_is_rejected`, `assertion_for_a_different_method_is_rejected`, `assertion_without_user_presence_is_rejected`, `wrong_type_origin_or_key_is_rejected`, `challenge_must_be_strict_unpadded_base64url`, `agent_key_calling_owner_methods_is_rejected`.
- `contract/tests/sec1_hardening.rs`: `wallet_owner_call_without_a_deposit_is_rejected`, `deposit_does_not_help_another_account`.

**What is left.**
- **No recovery:** losing the passkey freezes every mandate. Funds stay in the Safe, and the float can still be swept by the relayer.
- **A stolen passkey is a full compromise:** the holder can set mandates, add payees and change IBANs. The cooling-off still delays a new IBAN.
- **The deploy check is not under test;** it is a script step.

## 5. Residual risks

| # | Risk | Severity | Why it is accepted, or what would fix it |
|---|---|---|---|
| R1 | **Signatures issued before revoke stay valid until they expire,** including an MPC callback recorded as `revoked` after the revoke (§4.2). | Medium | Bounded by `max_validity_secs` ≤ 300 s, the per-payment cap and the budget. Stated in the README wording from PLAN. |
| R2 | **A compromised agent spends the whole budget** on listed payees each period (§4.1). | Medium | This is the mandate's design bound. The owner sizes the caps. |
| R3 | **The shape-3 transaction arguments carry the IBAN and salt in plaintext** (§4.7). | Medium (privacy) | PRIV1 covers contract state only. PRIV2 is the path that keeps the IBAN off chain. |
| R4 | **The scam check fails open without a NEAR AI API key,** and a compromised agent can bypass it (§4.10). | Medium | It is advisory by design; the contract is the enforcement. Fix: make `skipped` hold, or require the key in production config. |
| R5 | **PRIV2 trusts OutLayer's TEE and the owner-checked `worker_pk`.** The contract cannot check what the worker's digest hashes, and signs it with the agent EOA's key, so the worker key can get any digest signed for that EOA, not only a SEPA order (§4.8). | Medium (needs the worker key); high impact | Not bounded by the SEPA amount, cap, budget or invoice checks: it is bounded by trust in the worker key and its TEE attestation, and by the EOA's float (`float_cap`). Fix (future work): a separate MPC path/EOA holding only EURe for PRIV2, or the contract rebuilds the EIP-191 digest from order fields the worker returns. |
| R6 | **PRIV2 digests may be guessable.** The EIP-191 digest of `Send EUR {amount} to {IBAN} at {time}` is on chain (`signature_requested`, `Reservation.digest`), and so are the amount and time. For a known bank code an IBAN has little entropy, so it may be brute-forced against the digest. | Low–Medium (privacy) | This is analysis; it is not tested or measured. A fix needs the rail's message format to carry a secret, which Monerium's fixed order text does not allow. |
| R7 | **Monerium's duplicate refusal is confirmed only for an exact replay,** in the sandbox. Whoever holds the M1 credentials can submit any public signed order within its validity (§4.4). | Low | M1 claims each `request_id` once, and validity is short. |
| R8 | **Invoice ids are agent-declared:** other spellings bypass exactly-once (§4.6). | Low | Bounded by the supplier cap and the budget. |
| R9 | **The same IBAN under two suppliers** gets two invoice-id namespaces and two caps. D3 still stops the same agent re-signing the same (iban, amount, timestamp). | Low | Only the owner can list a supplier (passkey and cooling-off), so this is an owner configuration error, not an agent attack. |
| R10 | **Salt-lock refresh-to-rename gap.** In `recordSalt`, the last `refreshLock` and the `renameSync` are not atomic. A holder that stalls for more than 15 s between them can lose its lock to a reclaiming script and still rename its file over the book, dropping the other script's line. `reclaimStale` also documents a microsecond link-back race. | Low | It needs a stall of more than 15 s mid-save plus a concurrent owner script. A lost salt fails safe: payouts to that supplier are refused (`ERR_IBAN_NOT_ALLOWED`) until the owner re-commits the IBAN, which then waits out the cooling-off. Nothing is misdirected. |
| R11 | **`float_cap` is enforced only by the owner's top-up script,** not on chain (§4.1). | Low | Only the owner can top up, and the script re-checks the balance after the passkey tap. |
| R12 | **No owner recovery,** and a stolen passkey is a full compromise (§4.12). | High impact, accepted | There is no upgrade key by design (PLAN). Funds stay in the Safe. |
| R13 | **A listed x402 seller may not deliver** (§4.3). | Low | Bounded by the per-payment cap. |
