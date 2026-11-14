import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { assertNoIban, cargoNearProblem, CARGO_NEAR_INSTALL, CARGO_NEAR_VERSION, eventLines, localTranscript, maskIban, preflightProblems, reasonCode, requestIds, supplierIdProblem, type Preflight } from "../src/inv104.ts";

const refused = `EVENT_JSON:${JSON.stringify({
  standard: "zold-mandate",
  version: "1.0.0",
  event: "payout_refused",
  data: { key: { agent: "agent-1", caller: { kind: "agent" }, request_id: "inv-104-b" }, supplier: "acme", invoice_id: "INV-104", reason: "ERR_DUPLICATE_INVOICE" },
})}`;

test("eventLines prints each event with its reason code and skips other logs", () => {
  const lines = eventLines(["plain log", refused, "EVENT_JSON:{not json"]);
  assert.equal(lines.length, 1);
  assert.match(lines[0], /^ {2}event payout_refused +reason=ERR_DUPLICATE_INVOICE +data=\{/);
  const approved = eventLines([`EVENT_JSON:{"event":"payout_approved","data":{"invoice_id":"INV-104"}}`]);
  assert.match(approved[0], /reason=- /);
});

test("reasonCode takes the ERR_ code out of a contract failure", () => {
  assert.equal(reasonCode('{"ActionError":{"kind":{"FunctionCallError":{"ExecutionError":"Smart contract panicked: ERR_BANK_CHANGE_COOLING_OFF: acme"}}}}'), "ERR_BANK_CHANGE_COOLING_OFF");
  assert.equal(reasonCode("Exceeded the prepaid gas"), undefined);
});

test("IBANs are only ever printed masked", () => {
  assert.equal(maskIban("XX00FIXTURE0003000"), "****3000");
  assert.throws(() => assertNoIban("paid XX00FIXTURE0003000"), /unmasked IBAN/);
  assert.doesNotThrow(() => assertNoIban("paid ****3000, tx 4HuN3Nxxr99Hff9V1XspoQEfp7nYjktzZgdAHbP8RARD"));
});

test("localTranscript keeps only the DEMO lines, without the prefix", () => {
  assert.deepEqual(localTranscript("   Compiling x\nDEMO [1] step\nDEMO\nrunning 1 test\nDEMO   outcome: OK\n"), ["[1] step", "", "  outcome: OK"]);
});

const ready: Preflight = {
  contractId: "nearh-ap1.testnet",
  ownerMode: "passkey",
  network: "testnet",
  hasCoolingOff: true,
  ownerKeyPath: "/k/nearh-ap1.testnet/owner-p256.json",
  ownerKeyFound: true,
  ownerKeyMatches: true,
  submitter: "nearh-ap1-sub.testnet",
  submitterKeyFound: true,
  nearCliFound: true,
  agent: "agent-1",
  agentKeySource: "file",
  agentKeyPath: "/k/nearh-ap1.testnet/agents/agent-1.json",
  agentOfKey: "agent-1",
  sepaMaxEure: 50n * 10n ** 18n,
  sepaMinEure: 10n ** 18n,
  sepaBudgetLeftEure: 500n * 10n ** 18n,
  supplier: "acme-1762646400",
  supplierExists: false,
  supplierInvoicePaid: false,
  ibanA: "XX00FIXTURE0003000",
  ibanB: "XX00FIXTURE0005555",
};

test("preflight passes when everything is in place", () => {
  assert.deepEqual(preflightProblems(ready), []);
});

test("preflight stops at the owner passkey and the agent key with what to do", () => {
  const p = preflightProblems({ ...ready, ownerKeyFound: false, agentKeySource: undefined, agentOfKey: undefined });
  assert.equal(p.length, 2);
  assert.match(p[0], /^1\. OWNER PASSKEY NEEDED: no owner key at \/k\/nearh-ap1\.testnet\/owner-p256\.json/);
  assert.match(p[1], /^2\. AGENT KEY NEEDED: set AGENT_NEAR_PRIVATE_KEY in demo\/\.env \(never on the command line\)/);
  assert.match(preflightProblems({ ...ready, ownerKeyMatches: false })[0], /not nearh-ap1\.testnet's owner/);
  assert.match(preflightProblems({ ...ready, agentOfKey: null })[0], /is not on nearh-ap1\.testnet\. OWNER: `pnpm add-agent agent-1`/);
});

test("preflight with nothing set lists every missing piece, never a deploy by itself", () => {
  const p = preflightProblems({ agent: "agent-1" });
  assert.match(p[0], /^1\. Set CONTRACT_ID .* this script never deploys/);
  assert.ok(p.some((l) => /SUBMITTER_ACCOUNT_ID/.test(l)));
  assert.ok(p.some((l) => /AGENT KEY NEEDED/.test(l)));
  assert.ok(p.some((l) => /AP1_IBAN_A/.test(l)) && p.some((l) => /AP1_IBAN_B/.test(l)));
});

test("preflight refuses a pre-AP1 contract, a small mandate, and equal or malformed IBANs", () => {
  assert.match(preflightProblems({ ...ready, hasCoolingOff: false })[0], /predates AP1/);
  assert.match(preflightProblems({ ...ready, sepaMaxEure: 10n ** 18n })[0], /below EUR 42\.50/);
  assert.match(preflightProblems({ ...ready, sepaMaxEure: null })[0], /has no mandate/);
  assert.match(preflightProblems({ ...ready, ibanB: ready.ibanA })[0], /must differ/);
  assert.match(preflightProblems({ ...ready, ibanA: "xx00 fixture" })[0], /AP1_IBAN_A/);
});

test("preflight refuses a mandate whose SEPA minimum or remaining budget does not fit INV-104", () => {
  const p = preflightProblems({ ...ready, sepaMinEure: 50n * 10n ** 18n });
  assert.equal(p.length, 1);
  assert.match(p[0], /SEPA minimum above EUR 42\.50/);
  assert.match(preflightProblems({ ...ready, sepaBudgetLeftEure: 30n * 10n ** 18n })[0], /less than EUR 42\.50 of SEPA budget left/);
  assert.deepEqual(preflightProblems({ ...ready, sepaMinEure: 4250n * 10n ** 16n, sepaBudgetLeftEure: 4250n * 10n ** 16n }), []);
});

test("preflight refuses an AP1_SUPPLIER that is already registered or already paid INV-104", () => {
  assert.match(preflightProblems({ ...ready, supplierExists: true })[0], /already registered for agent-1.*Unset AP1_SUPPLIER/);
  assert.match(preflightProblems({ ...ready, supplierInvoicePaid: true })[0], /INV-104 is already paid for supplier/);
});

test("preflight refuses a supplier id whose request ids would pass 64 chars", () => {
  const max = 64 - "-inv-104-a".length;
  assert.equal(supplierIdProblem("a".repeat(max)), undefined);
  assert.ok(Object.values(requestIds("a".repeat(max))).every((id) => id.length <= 64));
  assert.match(supplierIdProblem("a".repeat(max + 1))!, /too long: request id "a+-inv-10\d-[ab]" exceeds 64 chars\. Use at most 54 chars/);
  assert.match(preflightProblems({ ...ready, supplier: "a".repeat(max + 1) })[0], /too long/);
  assert.match(supplierIdProblem("acme gmbh")!, /not a supplier id/);
  assert.match(supplierIdProblem("")!, /not a supplier id/);
  assert.match(supplierIdProblem("link-acme")!, /reserves that prefix/);
  assert.equal(supplierIdProblem("acme-link-1"), undefined);
});

test("the committed sandbox evidence is labelled, shows both refusals and holds no IBAN", () => {
  const text = readFileSync(new URL("../evidence/ap1-inv104-local-sandbox.txt", import.meta.url), "utf8");
  assert.match(text.split("\n")[0], /LOCAL SANDBOX RUN, NOT TESTNET/);
  assert.match(text, /\[5\][^\n]*\n(?:[^\n]*\n)*?\s+event payout_refused\s+reason=ERR_BANK_CHANGE_COOLING_OFF/);
  assert.match(text, /\[6\][^\n]*\n(?:[^\n]*\n)*?\s+event payout_refused\s+reason=ERR_DUPLICATE_INVOICE/);
  assert.match(text, /outcome: REFUSED ERR_BANK_CHANGE_COOLING_OFF/);
  assert.match(text, /outcome: REFUSED ERR_DUPLICATE_INVOICE/);
  assertNoIban(text);
});

test("cargoNearProblem names the pinned install command only when cargo-near is missing", () => {
  const fix = `cargo-near not found: ${CARGO_NEAR_INSTALL}`;
  assert.match(fix, new RegExp(`cargo-near-v${CARGO_NEAR_VERSION}/cargo-near-installer\\.sh \\| sh.*cargo install --locked cargo-near@${CARGO_NEAR_VERSION}`));
  assert.equal(cargoNearProblem({ stderr: "error: no such command: `near`\n" }), fix);
  assert.match(cargoNearProblem({ error: new Error("spawn cargo ENOENT") }) ?? "", /^cargo not found/);
  assert.equal(cargoNearProblem({ stderr: "" }), undefined);
});

test("CARGO_NEAR_VERSION matches the version CI pins", () => {
  const ci = readFileSync(new URL("../../.github/workflows/ci.yml", import.meta.url), "utf8");
  assert.equal(/CARGO_NEAR_VERSION: (\S+)/.exec(ci)?.[1], CARGO_NEAR_VERSION);
});
