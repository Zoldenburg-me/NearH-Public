# PRIV2-S: OutLayer TEE spike

**Verdict: GO for PRIV2, with conditions.** A contract can pin the worker code and check every result on-chain. The check is **not** a proof OutLayer hands to the callback: OutLayer's callback carries only the guest's stdout. The check is an ed25519 signature from an OutLayer **signing key** that OutLayer derives from `(wasm sha256, calling contract)`. The contract pins that public key once and verifies each result with `env::ed25519_verify`. The conditions are in "What this does not prove" below.

Network: NEAR testnet only. All accounts are throwaways created for this spike from the faucet. The "secret" is a fake IBAN map (`ZZ00FAKE…` values, not valid IBANs).

## Accounts and builds

| What | Value |
|---|---|
| Owner (secret owner, signer) | `nearh-cc2-ol-1794222360.testnet` |
| Caller v1 (no result check) | `caller.nearh-cc2-ol-1794222360.testnet` |
| Caller v2 (on-chain signature check) | `caller2.nearh-cc2-ol-1794222360.testnet` (`caller/`, wasm sha256 `502ebb10…082f`) |
| Worker v1 (`worker/`) | sha256 `9e4ac160790d564d54711f34c9828fdff66dffd600db63905061fea3619e8f6f` |
| Worker v2, signed (`worker-signed/`) | sha256 `c33c5a59a8710fccaf35b3e0edd7308b4df8db60ef919a12bd13091594d45e28` |
| OutLayer | `outlayer.testnet` (operator `worker.outlayer.testnet`), source read at out-layer/outlayer@`3079d756` |

Caller v1 was deployed from an earlier revision of `caller/src/lib.rs` that had no nonce or signature check. The committed file is v2.

## Steps and tx hashes

| # | Step | Tx | Result |
|---|---|---|---|
| 0 | Create owner / caller accounts | `7qwmh3Mv6pRkpKSx7J5UQS7XgNUpHNZQ6671BxSxFepr`, `9oP28beUZa9B1QiSVQeAgNfceKjpGAPwCcGaPFFfRsfG` | |
| 1 | Upload worker v1 to FastFS | `4m4nUmEQ5KGRgC4u3FDPoCyPLTWM9keaTTW4wnKnXEhQ` | |
| 2 | `store_secrets`: fake IBAN map + salt, bound to worker v1's hash | `8WKSoS9eazqjGb7sxE8QAmK6q7n1FkizadjsS6W22q76` | Tx args hold only `encrypted_secrets_base64` (ECIES to the keystore key). Plaintext is not in them (checked) |
| 3 | Deploy caller v1 | `BaQq2wXymCR37ZW2TxTf8etB8m1rvK3z5hQpEpnERc3D` | |
| 4 | `lookup` with access `whitelist:caller` | `Af366tqejpuT6HzGKoQTwwXM3fXRSUHC2748wrJdRYMf` | Callback arrived (15 blocks) with `null`: **access denied**. A whitelist names the *signer*, not the calling contract |
| 5 | `update_access` → `whitelist:owner AND from:caller` (`--via`) | `4GHic14xWdH8Pnd3QpPrN2LtqcJkiUqStAG2Q2PZJw1a` | |
| 6 | **Step 1+2 proof:** `lookup(payee-1)` → request 14619 | `7C7hDey4q8pJsrnbShAmbLUZyE8ZX2PHDVDxAphSR1jz` | Callback got `{"found":true,"country":"ZZ","commitment":"6e2c35…b6e7","secrets_loaded":true}`. The commitment equals `sha256(salt‖iban)`, recomputed locally, so the worker read the secret. The IBAN is in no arg, log or result |
| 7 | Worker resolve for 14619 | `8KUSMq5pCMHMdkwhjM32k4UyHTiLvwtfaXKM793R4UTQ` | Signed by `worker.outlayer.testnet` with an `ml-dsa-65` function-call key (TEE-registered) |
| 8 | Bypass: owner calls `outlayer.testnet.request_execution` directly with the same `secrets_ref` | `9itQBcvapVeYr7G3yLcJV9MfBteDkgxY8yZjuuWRPFDE` | **Denied**: "signer …, called from … Access denied" |
| 9 | `lookup(payee-2)`, `lookup(payee-9)` (v1) | `DWsi3ZgPaLsNkEJaf3fuMaDb7GX4v8AZhf7AxyxWwABY`, `CZszoRfG2edhkh7aLRFa7yn9zFKzT6tu3YVjie6z5Mmp` | found / `found:false` |
| 10 | Upload worker v2 (signed) | `FjgeXuWot6cJUu2x8fZ1CwGanYhT52a93HAPm1KGahnz` | |
| 11 | `store_secrets` for v2's hash, `whitelist:owner AND from:caller2` | `2rYexWA7VU4ck18z1MvAoKGSbujcf9KR2suBxJM1Jbaz` | Ciphertext only (checked) |
| 12 | Create + deploy caller v2 | `4PNv3e5YZ78hpeNJ4BgDdtpFkcZB9EdUKCTbNVYZYgCE`, `BvQniRPydHRbwzBfqgg7DaYdhuCaM1fbhRESsLq1sR1D` | |
| 13 | **Bootstrap:** `lookup(payee-1)`, no key pinned → request 14662 | `6bT4jFq1mTJu1ffnDVG6DSjgHXcRJpsMvLhPTwjkPcGZ` | Output carries `pk 62312c69…8b26` and `sig`. Attestation checked off-chain (below) |
| 14 | Negative test: pin a wrong key, then `lookup(payee-1)` | `8ubJHEzsgUCjuKyCiFuLw83uqstNDTbNGCqCb7ma51hW`, `D7nkKpDTpRMgSkc19r7wB2h9fFagwYWjzDojMrkbfGrj` | Contract logs `verified: REJECTED: bad signature` |
| 15 | Pin the real key | `CX5zC18bwkjW4X8GEY4g5JgDD8TeDiEdBaZpbkpeQuHS` | |
| 16 | **Step 3 proof:** `lookup(payee-2)`, `lookup(payee-9)` | `9PhUNg5tUTMjG83Fi5SBoVJb1QQNi6LwFWqMzCpWw9ue`, `F8kh8xjMHe11gfjs9iwzfRHAD3G8zxEnPtotTkH3tMd2` | `verified: ok` on-chain for a found payee and for a not-found one |

The logs for these runs are in `runs/`: tx id, contract logs, OutLayer events, and the balance before and after. They contain no key material.

## 3. What the callback gives the contract, and what can be checked on-chain

From `contract/src/execution.rs` (`on_execution_response`) and the observed receipts:

- **The calling contract receives only the promise result**: the guest's stdout as JSON (with `response_format: Json`), or `null` on failure. It carries **no** wasm hash, no attestation, no worker signature. The worker's `ExecutionResponse` (`success, output, error, resources_used, compilation_note, refund_usd`) stops at `outlayer.testnet`.
- **Code pin: yes, on-chain.** The caller chooses `source: WasmUrl { url, hash }` itself and stores the hash. `outlayer.testnet` forwards the hash to the worker, which refuses bytes that don't match. The attestation's `executed_wasm_sha256` equals the pin. The secret is bound to the same hash (`accessor: WasmHash`), so no other build can read it.
- **Result authenticity from OutLayer itself: not checkable on-chain.** It rests on `outlayer.testnet` accepting `resolve_execution` only from its operator `worker.outlayer.testnet`. The callback cannot tell which of the operator account's keys signed a resolve. The resolves for our requests were signed by `ml-dsa-65` TEE keys (step 7), but nothing on-chain forces that.
- **Per-execution attestation: off-chain only.** `GET https://testnet-api.outlayer.ai/attestations/by-request/{id}` returns a TDX quote whose REPORTDATA is `sha256(task_type, task_id, build_target, wasm_hash, input_hash, output_hash, block_height, caller, secrets_ref, timestamp, attached_usd)`. `verify_attestation.py` recomputes it for requests 14619 and 14662: it matches, `input_hash` matches what the contract sent, `output_hash` matches the recorded worker stdout (`runs/output-req*.json`), and `executed_wasm_sha256` equals the pin. The quote's five measurements return `true` from `worker.outlayer.testnet.is_measurements_approved`. OutLayer's docs say checking the quote on-chain on every call is too gas-expensive. The register contract does it (dcap-qvl) only once, when a worker key is registered.
- **What makes it checkable on-chain: OutLayer signing keys.** A `wasm32-wasip2` worker that declares `signing_keys: [{path, type: ed25519, bind: "wasm", caller: "predecessor"}]` in its embedded `outlayer.manifest` can call `signing_keys::sign`. The keystore derives the key from the wasm sha256 and the calling contract, inside the TEE. The module never sees the private key. Our worker signs `nearh-priv2s:v1|{nonce}|{payee}|{found}|{country}|{commitment}`, with a nonce of `{contract}:{id}` chosen by the contract. `caller2.on_result` rebuilds the message from the returned fields and checks the nonce, the payee and `ed25519_verify` against the pinned key (steps 14–16, plus unit tests for tampering, replay, wrong payee, wrong key and a missing signature). A resolve not produced by the pinned worker fails this check unless that party also controls the keystore. A different build derives a different key and fails it too.
- **Bootstrap.** The owner learns the key from a first run and pins it (`set_worker_pk`, owner-only). That one run is checked off-chain: `verify_attestation.py` hashes the worker stdout byte for byte and refuses to print a key to pin unless it equals the attestation's `output_hash`; the quote binds that hash, the pinned wasm hash and this caller. For request 14662 the recorded output (`runs/output-req14662.json`) matches; a copy with a substituted `pk` (`runs/output-req14662-forged.json`) is refused.

## 4. Latency and cost per call (7 lookups)

| | Value |
|---|---|
| Request → callback | 10–16 blocks; 9.7–14.3 s wall clock, from `send` until the CLI returned the final result |
| Worker execution | 204 ms, 92k instructions (WASM cached) |
| OutLayer compute charge | 0.0010204 NEAR (base fee 0.001 + usage). We attached 0.1 NEAR; the rest was refunded to the signer (`payer_account_id`) in the same flow |
| Gas burnt (whole receipt tree) | 12.1–12.7 Tgas ≈ 0.0011–0.00116 NEAR. The on-chain check adds ~0.5 Tgas to `on_result` (1.64 → 2.13 Tgas) |
| Net balance change per call | 0.00212–0.00223 NEAR |
| One-off | `store_secrets` ≈ 0.0004 NEAR fee plus refundable storage; FastFS upload ≈ 0.0007 NEAR |

A failed run (access denied) still costs the 0.001 NEAR base fee.

## What this does not prove (conditions on the GO)

1. **Trust moves to the OutLayer keystore, not to zero.** The signature shows the key derived for `(this wasm, this caller)` signed the result. That holds only if the keystore (a TEE plus its master/CKD derivation) releases that key to no one else. We did not check the keystore's own attestation.
2. **We did not verify the Intel signature chain of the quotes** (that needs dcap-qvl and Intel collateral from `/public/collateral`). We checked the REPORTDATA binding and the on-chain measurement approval only.
3. **Access conditions are enforced off-chain** by the keystore, from on-chain state. The bypass call was refused (step 8), but that refusal is OutLayer's.
4. **Availability is OutLayer's.** If no worker resolves, the yield times out and the callback gets `null`. PRIV2 must treat `null` or `REJECTED` as "no payout".
5. **Builds are not reproducible here.** The worker was built locally with `cargo build`. For PRIV2, use OutLayer's pinned Docker build so others can recompute the hash.
6. **Key rotation:** a new worker build means a new key and a new bootstrap. Use `bind: "project"` to keep the key across versions, which shifts trust to the project's owner.
7. Not measured: cold-start compile time (all runs hit the WASM cache after the first), behaviour under load, the large-output (>1 KB) 2-call path.

## Reproduce

Tools: `near` CLI (near-cli-rs 0.30), `cargo-near`, `jq`, Rust with target `wasm32-wasip2`, and OutLayer CLI 0.2.2 built from out-layer/outlayer-cli (`cargo install --path .`). Log in with `OUTLAYER_HOME` set to a private directory. The throwaway account's key stays in `~/.near-credentials` (legacy keychain), never in this repo. Use a fresh faucet testnet account as `OWNER`.

```bash
cd spikes/outlayer
OWNER=<your-throwaway>.testnet; CALLER=caller2.$OWNER; echo "$OWNER" > /tmp/ol-acct

# 1. Build and upload the signed worker; its sha256 is the pin.
(cd worker-signed && cargo test && cargo build --target wasm32-wasip2 --release)   # uses vendor/outlayer-sdk
WASM=worker-signed/target/wasm32-wasip2/release/ol-iban-worker-signed.wasm
WASM_HASH=$(shasum -a 256 "$WASM" | cut -d' ' -f1)
outlayer upload "$WASM"   # FastFS URL below is where step 10 landed
WASM_URL=https://test.fastfs.io/$OWNER/outlayer.testnet/$WASM_HASH.wasm

# 2. Create the caller account, then store a FAKE secret profile bound to this
#    hash, readable only when OWNER signs and CALLER calls. The OutLayer CLI takes
#    the profile as an argument, so it must hold fake values only (never a real IBAN).
near account create-account fund-myself "$CALLER" '3 NEAR' autogenerate-new-keypair \
  save-to-legacy-keychain sign-as "$OWNER" network-config testnet sign-with-legacy-keychain send
SALT=$(openssl rand -hex 16)
PROFILE=$(jq -cn --arg salt "$SALT" \
  '{IBAN_MAP: ({"payee-1": "ZZ00FAKE0000000001", "payee-2": "ZZ00FAKE0000000002"} | tojson), IBAN_SALT: $salt}')
outlayer secrets set "$PROFILE" --wasm-hash "$WASM_HASH" --profile priv2s \
  --access "whitelist:$OWNER" --via "$CALLER"

# 3. Build and deploy the caller with its five init fields.
(cd caller && cargo test && cargo near build non-reproducible-wasm)
INIT=$(jq -cn --arg url "$WASM_URL" --arg hash "$WASM_HASH" --arg owner "$OWNER" \
  '{outlayer: "outlayer.testnet", wasm_url: $url, wasm_hash: $hash, secrets_owner: $owner, secrets_profile: "priv2s"}')
near contract deploy "$CALLER" use-file caller/target/near/ol_caller.wasm \
  with-init-call new json-args "$INIT" prepaid-gas '30 Tgas' attached-deposit '0 NEAR' \
  network-config testnet sign-with-legacy-keychain send

# 4. Bootstrap run (no key pinned yet). Save the worker stdout from the
#    on_result log, fetch the attestation (request id is in the
#    execution_requested event), and pin the key only if the verifier prints it.
./run.sh payee-1 runs/bootstrap.log caller2
python3 -I -c 'import re,sys; sys.stdout.write(re.search(r"no pinned key\): (\{.*\})", open(sys.argv[1]).read()).group(1))' \
  runs/bootstrap.log > runs/bootstrap-output.json
curl -s https://testnet-api.outlayer.ai/attestations/by-request/<request_id> > runs/bootstrap-attestation.json
python3 -I verify_attestation.py runs/bootstrap-attestation.json \
  "$(jq -cn --arg n "$CALLER:0" '{payee: "payee-1", nonce: $n}')" runs/bootstrap-output.json
#   -> exits 1 and prints no key unless sha256(output) == output_hash (and the other checks pass)
PK=<the hex after "pin:">
near contract call-function as-transaction "$CALLER" set_worker_pk json-args "$(jq -cn --arg pk "$PK" '{pk_hex: $pk}')" \
  prepaid-gas '30 Tgas' attached-deposit '0 NEAR' sign-as "$OWNER" network-config testnet sign-with-legacy-keychain send

# 5. Checked lookups: the caller logs `verified: ok`.
./run.sh payee-2 runs/x.log caller2
```

Offline tests: `python3 -I -m unittest discover -s spikes/outlayer -p 'test_*.py'` (verifier against the recorded runs, including a substituted bootstrap output that must not be pinned) and `cargo test` in `worker-signed/` and `caller/`.

The worker now exits with an error and signs nothing when `IBAN_SALT` or `IBAN_MAP` is missing, empty or malformed (review fix after the runs above). That changes its sha256 from the `c33c5a59…` build used in steps 10–16, so a rerun gets a new hash, a new derived key and needs a new bootstrap.

`vendor/outlayer-sdk` is a copy of `sdk/outlayer` from out-layer/outlayer@3079d756 (MIT/Apache-2.0). The `signing-keys` feature is not in the crates.io release (0.2.1).
