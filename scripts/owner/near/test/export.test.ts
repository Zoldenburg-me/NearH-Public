// Accountant export (AP2): payout decisions from contract events, IBAN last 4 via the salt book,
// never a full IBAN, and cells a spreadsheet cannot run as formulas.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import {
  assertNoIban,
  buildRows,
  cell,
  euros,
  ibanIndex,
  parseEvents,
  parseSaltBook,
  receiptsFromTxStatus,
  toCsv,
  type RecordedReceipt,
  type Recording,
} from "../src/export.ts";
import { ibanCommitment } from "../src/supplier.ts";

const IBAN = "DE89370400440532013000";
const OTHER = "GB33BUKB20201555555555";
const S1 = `0x${"11".repeat(32)}`;
const S2 = `0x${"22".repeat(32)}`;
const C1 = ibanCommitment(IBAN, S1);
const C2 = ibanCommitment(OTHER, S2);
const T0 = 1_794_218_400; // 2026-11-09 10:00:00 UTC
const LAST4 = ibanIndex([
  { iban: IBAN, salt: S1, commitment: C1 },
  { iban: OTHER, salt: S2, commitment: C2 },
]).last4;

const ev = (event: string, data: unknown) => `EVENT_JSON:${JSON.stringify({ standard: "zold-mandate", version: "1.0.0", event, data })}`;
const key = (request_id: string, agent = "agent-1") => ({ agent, caller: { kind: "agent" }, request_id });
let n = 0;
const receipt = (dt: number, logs: string[], failure?: string): RecordedReceipt => ({
  tx_hash: `tx-${++n}`,
  receipt_id: `r-${n}`,
  block_height: 1_000 + dt,
  block_timestamp_ns: `${BigInt(T0 + dt) * 1_000_000_000n}`,
  status: failure ? "failure" : "success",
  failure: failure ?? null,
  logs,
});
const rec = (...receipts: RecordedReceipt[]): Recording => ({ source: "fixture", contract: "c.testnet", receipts });
const added = (dt: number, commitment = C1, effective = T0 + dt + 60, agent = "agent-1") =>
  receipt(dt, [
    ev("payee_added", { agent, payee: { rail: "sepa", supplier: "acme", name: "Acme GmbH", iban_commitment: commitment, cap: "1" } }),
    ev("supplier_iban_pending", { agent, supplier: "acme", iban_commitment: commitment, effective_at: effective }),
  ]);
const approved = (dt: number, id: string, amount: string, failure?: string, agent = "agent-1") =>
  receipt(dt, [ev("payout_approved", { key: key(id, agent), supplier: "acme", invoice_id: id.toUpperCase(), amount, invoice_amount: amount })], failure);
const refused = (dt: number, id: string, reason: string) =>
  receipt(dt, [ev("payout_refused", { key: key(id), supplier: "acme", invoice_id: id.toUpperCase(), reason })], `${reason}: x`);
const pending = (dt: number, commitment: string, effective: number) =>
  receipt(dt, [ev("supplier_iban_pending", { agent: "agent-1", supplier: "acme", iban_commitment: commitment, effective_at: effective })]);

test("the INV-104 story: the paid IBAN follows the cooling-off, refusals carry their reason code", () => {
  const rows = buildRows(
    rec(
      added(0),
      approved(61, "inv-104", "42.5"),
      pending(70, C2, T0 + 130),
      refused(75, "inv-105", "ERR_BANK_CHANGE_COOLING_OFF"),
      refused(76, "inv-104", "ERR_DUPLICATE_INVOICE"),
      approved(80, "inv-106", "1"),
      approved(140, "inv-107", "10"),
      refused(141, "inv-108", "ERR_IBAN_NOT_ALLOWED"),
    ),
    LAST4,
  );
  assert.deepEqual(
    rows.map((r) => [r.time, r.ibanLast4, r.invoiceId, r.amount, r.decision, r.reasonCode]),
    [
      ["10:01:01", "****3000", "INV-104", "42,50", "approved", ""],
      ["10:01:15", "****5555", "INV-105", "", "refused", "ERR_BANK_CHANGE_COOLING_OFF"], // the IBAN still cooling off
      ["10:01:16", "****3000", "INV-104", "", "refused", "ERR_DUPLICATE_INVOICE"], // passed the IBAN check: the payable one
      ["10:01:20", "****3000", "INV-106", "1,00", "approved", ""], // old IBAN pays during the window
      ["10:02:20", "****5555", "INV-107", "10,00", "approved", ""], // new IBAN after it
      ["10:02:21", "", "INV-108", "", "refused", "ERR_IBAN_NOT_ALLOWED"], // the IBAN opened no listed commitment
    ],
  );
  assert.equal(rows[0].date, "09.11.2026");
  assert.equal(rows[0].supplier, "Acme GmbH");
  assert.equal(rows[0].payoutId, "inv-104");
  assert.equal(rows[0].txHash, "tx-2");
  assert.ok(rows.every((r) => r.currency === "EUR" && r.rail === "SEPA"));
});

test("a payout_approved in a failed receipt is a refusal with the panic's code", () => {
  const [row] = buildRows(rec(added(0), approved(61, "inv-1", "5", '{"ActionError":{"kind":{"FunctionCallError":{"ExecutionError":"Smart contract panicked: ERR_OVER_BUDGET: sepa"}}}}')), LAST4);
  assert.equal(row.decision, "refused");
  assert.equal(row.reasonCode, "ERR_OVER_BUDGET");
  assert.equal(row.amount, "");
  const [unknown] = buildRows(rec(added(0), approved(61, "inv-1", "5", "out of gas")), LAST4);
  assert.equal(unknown.reasonCode, "RECEIPT_FAILED");
});

test("a failed receipt changes no supplier state", () => {
  // A failed change_supplier_iban would have logged nothing, but even if it had, it must not count.
  const failedChange = receipt(70, [ev("supplier_iban_pending", { agent: "agent-1", supplier: "acme", iban_commitment: C2, effective_at: T0 + 71 })], "ERR_X");
  const rows = buildRows(rec(added(0), failedChange, approved(100, "inv-1", "1")), LAST4);
  assert.equal(rows[0].ibanLast4, "****3000");
});

test("a cancelled change keeps the payable IBAN; a revoke clears the agent's suppliers", () => {
  const cancel = receipt(75, [ev("supplier_iban_cancelled", { agent: "agent-1", supplier: "acme", iban_commitment: C2 })]);
  let rows = buildRows(rec(added(0), pending(70, C2, T0 + 130), cancel, approved(200, "inv-1", "1")), LAST4);
  assert.equal(rows[0].ibanLast4, "****3000");

  const revoke = receipt(80, [ev("agent_revoked", { agent: "agent-1", by: "owner" })]);
  rows = buildRows(rec(added(0), revoke, refused(90, "inv-2", "ERR_OVER_SUPPLIER_CAP")), LAST4);
  assert.equal(rows[0].ibanLast4, ""); // no supplier left to look up
  assert.equal(rows[0].supplier, "acme"); // falls back to the id
});

test("suppliers are per agent", () => {
  const rows = buildRows(rec(added(0, C1), added(1, C2, T0 + 60, "agent-2"), approved(100, "a", "1"), approved(101, "b", "1", undefined, "agent-2")), LAST4);
  assert.deepEqual(rows.map((r) => r.ibanLast4), ["****3000", "****5555"]);
});

test("receipts are replayed in block order whatever the recording order", () => {
  const rows = buildRows(rec(approved(61, "inv-1", "1"), added(0)), LAST4);
  assert.equal(rows[0].ibanLast4, "****3000");
});

test("same-block receipts replay in execution order, not recording order", () => {
  // Owner adds Acme, then the agent pays it, both in block 1061; recorded as `pay-tx add-tx`.
  const add = { ...added(61, C1, T0), index_in_block: 0 };
  const pay = { ...approved(61, "inv-1", "1"), index_in_block: 1 };
  const [row] = buildRows(rec(pay, add), LAST4);
  assert.equal(row.supplier, "Acme GmbH");
  assert.equal(row.ibanLast4, "****3000");

  // A same-block IBAN change executed before the payout counts for it; one after does not.
  const change = (i: number) => ({ ...pending(100, C2, T0 + 100), index_in_block: i });
  const payAt = (i: number) => ({ ...approved(100, "inv-2", "1"), index_in_block: i });
  assert.equal(buildRows(rec(added(0, C1, T0), payAt(1), change(0)), LAST4)[0].ibanLast4, "****5555");
  assert.equal(buildRows(rec(added(0, C1, T0), change(1), payAt(0)), LAST4)[0].ibanLast4, "****3000");
});

test("same-block receipts with equal index_in_block are refused, naming the block and txs", () => {
  const add = { ...added(61, C1, T0), index_in_block: 0 };
  const pay = { ...approved(61, "inv-1", "1"), index_in_block: 0 };
  assert.throws(
    () => buildRows(rec(pay, add), LAST4),
    (e: Error) => /share index_in_block 0 in block 1061/.test(e.message) && e.message.includes(add.tx_hash) && e.message.includes(pay.tx_hash),
  );
  // Same tx, two receipts, one index: still ambiguous.
  assert.throws(() => buildRows(rec({ ...pay, tx_hash: add.tx_hash }, add), LAST4), /share index_in_block/);
});

test("same-block receipts of different txs without index_in_block are refused, one tx keeps its order", () => {
  assert.throws(() => buildRows(rec(approved(61, "inv-1", "1"), added(61, C1, T0)), LAST4), /index_in_block/);
  const add = added(61, C1, T0);
  const pay = { ...approved(61, "inv-1", "1"), tx_hash: add.tx_hash };
  assert.equal(buildRows(rec(add, pay), LAST4)[0].ibanLast4, "****3000");
  const { block_height, ...noHeight } = add;
  assert.throws(() => buildRows(rec(noHeight as RecordedReceipt, pay), LAST4), /block_height/);
});

test("salt book lines that do not reproduce their commitment are never used", () => {
  const book = parseSaltBook(
    [
      JSON.stringify({ iban: IBAN, salt: S1, commitment: C1 }),
      JSON.stringify({ iban: OTHER, salt: S1, commitment: C2 }), // wrong salt
      JSON.stringify({ iban: "not an iban", salt: S1, commitment: C1 }),
      "",
    ].join("\n"),
  );
  const { last4, mismatched } = ibanIndex(book);
  assert.equal(mismatched, 2);
  assert.deepEqual([...last4.entries()], [[C1, "****3000"]]);
});

test("events: other standards and plain logs are skipped, an unknown version throws", () => {
  assert.deepEqual(parseEvents(["hello", `EVENT_JSON:${JSON.stringify({ standard: "nep141", version: "1.0.0", event: "ft_transfer", data: [] })}`]), []);
  assert.throws(() => parseEvents([`EVENT_JSON:${JSON.stringify({ standard: "zold-mandate", version: "2.0.0", event: "x", data: {} })}`]));
});

test("amounts get a decimal comma and two decimals, exactly", () => {
  assert.equal(euros("42.5"), "42,50");
  assert.equal(euros("1"), "1,00");
  assert.equal(euros("0.005"), "0,005");
  assert.equal(euros("12345678901234567890.12"), "12345678901234567890,12");
  assert.throws(() => euros("1e3"));
});

test("cells: formulas are neutralised, separators and quotes escaped", () => {
  assert.equal(cell("=HYPERLINK(1)"), "'=HYPERLINK(1)");
  assert.equal(cell("-INV-1"), "'-INV-1"); // supplier and invoice ids may start with '-'
  assert.equal(cell("+1"), "'+1");
  assert.equal(cell("@x"), "'@x");
  assert.equal(cell('a;b"c'), '"a;b""c"');
  assert.equal(cell("a\nb"), '"a\nb"');
  assert.equal(cell("Acme GmbH"), "Acme GmbH");
});

test("the CSV has a BOM, a header, CRLF lines and no full IBAN", () => {
  const rows = buildRows(rec(added(0), approved(61, "inv-104", "42.5")), LAST4);
  const csv = toCsv(rows, ["FIXTURE DATA"]);
  assert.ok(csv.startsWith("﻿# FIXTURE DATA\r\nDate;Time (UTC);Supplier;IBAN (last 4);Invoice;Amount;Currency;Rail;NEAR tx;Payout id;Decision;Reason code\r\n"));
  assert.ok(csv.includes("09.11.2026;10:01:01;Acme GmbH;****3000;INV-104;42,50;EUR;SEPA;tx-"));
  assert.ok(!csv.includes(IBAN) && !csv.includes(OTHER));
  assertNoIban(csv);
  assert.throws(() => assertNoIban(`x;${IBAN};y`));
});

test("receiptsFromTxStatus keeps the contract's receipts with status, failure, block height and time", () => {
  const result = {
    transaction: { hash: "TX1" },
    receipts_outcome: [
      { id: "R1", block_hash: "B1", outcome: { executor_id: "c.testnet", logs: ["a"], status: { SuccessReceiptId: "R2" } } },
      { id: "R2", block_hash: "B2", outcome: { executor_id: "c.testnet", logs: ["b"], status: { Failure: { ActionError: { kind: "x" } } } } },
      { id: "R3", block_hash: "B2", outcome: { executor_id: "v1.signer-prod.testnet", logs: ["c"], status: { SuccessValue: "" } } },
    ],
  };
  const out = receiptsFromTxStatus(
    result,
    "c.testnet",
    new Map([
      ["B1", { height: 10, timestamp_ns: "1" }],
      ["B2", { height: 11, timestamp_ns: "2" }],
    ]),
  );
  assert.deepEqual(out, [
    { tx_hash: "TX1", receipt_id: "R1", block_height: 10, block_timestamp_ns: "1", status: "success", failure: null, logs: ["a"] },
    { tx_hash: "TX1", receipt_id: "R2", block_height: 11, block_timestamp_ns: "2", status: "failure", failure: '{"ActionError":{"kind":"x"}}', logs: ["b"] },
  ]);
  assert.throws(() => receiptsFromTxStatus(result, "c.testnet", new Map()));
});

test("the committed fixture CSV is what export-csv builds from the committed fixture", () => {
  const evidence = join(dirname(fileURLToPath(import.meta.url)), "../../../../demo/evidence");
  const dir = mkdtempSync(join(tmpdir(), "export-"));
  try {
    const out = join(dir, "out.csv");
    const r = spawnSync(
      process.execPath,
      ["src/cli/export-csv.ts", join(evidence, "ap2-fixture-recording.json"), "--salts", join(evidence, "ap2-fixture-salt-book.jsonl"), "--out", out],
      { cwd: join(dirname(fileURLToPath(import.meta.url)), ".."), encoding: "utf8" },
    );
    assert.equal(r.status, 0, r.stderr);
    const csv = readFileSync(out, "utf8");
    assert.equal(csv, readFileSync(join(evidence, "ap2-fixture-export.csv"), "utf8"));
    assert.ok(csv.includes("FIXTURE DATA"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("export-csv refuses to write a CSV with a full IBAN, e.g. one typed into a supplier name", () => {
  const dir = mkdtempSync(join(tmpdir(), "export-"));
  try {
    const leaky = added(0);
    leaky.logs[0] = leaky.logs[0].replace("Acme GmbH", `Acme ${IBAN}`);
    const input = join(dir, "rec.json");
    writeFileSync(input, JSON.stringify(rec(leaky, approved(61, "inv-1", "1"))));
    const out = join(dir, "out.csv");
    const r = spawnSync(process.execPath, ["src/cli/export-csv.ts", input, "--salts", join(dir, "none.jsonl"), "--out", out], {
      cwd: join(dirname(fileURLToPath(import.meta.url)), ".."),
      encoding: "utf8",
    });
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /full IBAN/);
    assert.ok(!existsSync(out));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
