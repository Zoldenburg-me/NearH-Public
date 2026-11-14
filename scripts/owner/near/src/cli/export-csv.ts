// pnpm export-csv <recording.json> [--salts <salt book>] [--out <file.csv>]: the payout decisions
// in a receipt recording (pnpm record-receipts, or a fixture) as an accountant CSV. IBAN last 4
// comes from the owner's salt book (default ~/.config/nearh/supplier-salts.jsonl); without it
// that column stays empty. The CSV never holds a full IBAN.
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { assertNoIban, buildRows, ibanIndex, parseSaltBook, toCsv, type Recording } from "../export.ts";
import { saltsFile } from "../supplier.ts";

const args = process.argv.slice(2);
const opt = (name: string) => {
  const i = args.indexOf(name);
  if (i < 0) return undefined;
  const v = args[i + 1];
  if (!v) throw new Error(`${name} needs a value`);
  args.splice(i, 2);
  return v;
};
const out = opt("--out");
const salts = opt("--salts") ?? saltsFile();
const [input] = args;
if (!input || args.length !== 1) throw new Error("usage: export-csv <recording.json> [--salts <salt book>] [--out <file.csv>]");

const rec = JSON.parse(readFileSync(input, "utf8")) as Recording;
if (rec.source !== "fixture" && rec.source !== "testnet") throw new Error(`recording source must be fixture or testnet, got ${rec.source}`);
let last4 = new Map<string, string>();
if (existsSync(salts)) {
  const idx = ibanIndex(parseSaltBook(readFileSync(salts, "utf8")));
  last4 = idx.last4;
  if (idx.mismatched) console.error(`warning: ${idx.mismatched} salt book line(s) do not reproduce their commitment; ignored`);
} else {
  console.error(`warning: no salt book at ${salts}; the IBAN (last 4) column stays empty`);
}
const rows = buildRows(rec, last4);
const preamble = [
  rec.source === "fixture"
    ? "FIXTURE DATA: recorded example events, not a NEAR testnet run"
    : "Source: NEAR testnet receipts",
  `Contract: ${rec.contract}`,
  "Decision is the mandate contract's. An approved payout passed the contract's checks and went to the MPC for signing. It does not prove the bank transfer settled",
];
// Supplier names are free text; a NEAR tx hash (base58) can look IBAN-shaped by chance, so it is not checked.
assertNoIban(toCsv(rows.map((r) => ({ ...r, txHash: "" })), preamble));
const csv = toCsv(rows, preamble);
if (out) {
  writeFileSync(out, csv);
  console.error(`wrote ${rows.length} row(s) to ${out}`);
} else {
  process.stdout.write(csv);
}
