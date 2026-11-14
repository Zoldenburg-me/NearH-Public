// Accountant export (AP2): the contract's SEPA payout decisions as a semicolon CSV that opens
// in a German Excel without import settings. Input is a recording of the contract's receipts
// (status and logs, docs/interfaces.md §5); the owner's salt book maps the IBAN commitment that
// was paid to its last four digits. A full IBAN is never written.

import { ibanCommitment } from "./supplier.ts";

/** One receipt on the contract: its logs, and whether it succeeded (a failed one changes nothing). */
export type RecordedReceipt = {
  tx_hash: string;
  receipt_id: string;
  /** Height of the block that executed the receipt. Receipts replay in (height, index_in_block) order. */
  block_height: number;
  /**
   * Execution position within the block, when known (e.g. from an indexer). Two receipts of
   * different txs in one block without it are ambiguous and the export refuses them; receipts of
   * one tx keep their recorded order (`receipts_outcome` is causal).
   */
  index_in_block?: number;
  /** Block timestamp in nanoseconds, as a decimal string (NEAR's `header.timestamp`). */
  block_timestamp_ns: string;
  status: "success" | "failure";
  /** The panic message of a failed receipt, e.g. `ERR_OVER_BUDGET: ...`. */
  failure?: string | null;
  logs: string[];
};

export type Recording = {
  /** `fixture` for recorded example data, `testnet` for receipts read from NEAR testnet. */
  source: "fixture" | "testnet";
  note?: string;
  contract: string;
  receipts: RecordedReceipt[];
};

export type SaltEntry = { agent?: string; supplier?: string; iban: string; salt: string; commitment: string };

export type Row = {
  date: string;
  time: string;
  supplier: string;
  ibanLast4: string;
  invoiceId: string;
  amount: string;
  currency: string;
  rail: string;
  txHash: string;
  payoutId: string;
  decision: "approved" | "refused";
  reasonCode: string;
};

export const HEADER = [
  "Date",
  "Time (UTC)",
  "Supplier",
  "IBAN (last 4)",
  "Invoice",
  "Amount",
  "Currency",
  "Rail",
  "NEAR tx",
  "Payout id",
  "Decision",
  "Reason code",
];

type Event = { event: string; data: any };

/** The contract's NEP-297 events in `logs`; other log lines are skipped. */
export function parseEvents(logs: string[]): Event[] {
  const out: Event[] = [];
  for (const line of logs) {
    if (!line.startsWith("EVENT_JSON:")) continue;
    const log = JSON.parse(line.slice("EVENT_JSON:".length));
    if (log.standard !== "zold-mandate") continue;
    if (log.version !== "1.0.0") throw new Error(`unsupported zold-mandate event version ${log.version}`);
    out.push({ event: log.event, data: log.data });
  }
  return out;
}

/**
 * commitment -> `****1234`, from salt book lines whose IBAN and salt reproduce the commitment.
 * Lines that do not are returned in `mismatched` and never used.
 */
export function ibanIndex(entries: SaltEntry[]): { last4: Map<string, string>; mismatched: number } {
  const last4 = new Map<string, string>();
  let mismatched = 0;
  for (const e of entries) {
    let ok = false;
    try {
      ok = ibanCommitment(e.iban, e.salt) === e.commitment?.toLowerCase();
    } catch {}
    if (ok) last4.set(e.commitment.toLowerCase(), `****${e.iban.slice(-4)}`);
    else mismatched++;
  }
  return { last4, mismatched };
}

/** Parses a salt book (JSON lines, as `recordSalt` writes). */
export function parseSaltBook(text: string): SaltEntry[] {
  return text
    .split("\n")
    .filter((l) => l.trim())
    .map((l) => JSON.parse(l));
}

// Refusals `build_payout` returns after the request's IBAN opened the payable commitment
// (contract/src/shapes/payout.rs), plus the two invoice/payout dedupes that follow it.
const AFTER_IBAN_CHECK = new Set([
  "ERR_INVALID_AMOUNT",
  "ERR_INVALID_INVOICE",
  "ERR_BELOW_MINIMUM",
  "ERR_OVER_PER_PAYMENT_CAP",
  "ERR_OVER_SUPPLIER_CAP",
  "ERR_OVER_INVOICE_AMOUNT",
  "ERR_INVALID_MANDATE",
  "ERR_TIMESTAMP_STALE",
  "ERR_TIMESTAMP_FUTURE",
  "ERR_DUPLICATE_INVOICE",
  "ERR_DUPLICATE_PAYOUT",
]);

type Supplier = { name: string; current?: string; pending?: { commitment: string; effectiveAt: number } };

/** `Supplier::settled`: a pending commitment becomes payable at `effective_at`. */
function settle(s: Supplier, now: number): Supplier {
  if (s.pending && now >= s.pending.effectiveAt) {
    s.current = s.pending.commitment;
    s.pending = undefined;
  }
  return s;
}

/**
 * Chain execution order: block height, then `index_in_block`. Block timestamps cannot order
 * receipts in one block, and the recording's order is the order txs were listed in, so two
 * receipts of different txs in one block need `index_in_block` or the export refuses them rather
 * than attribute a payout to the wrong supplier state. Two receipts with the same `index_in_block`
 * are refused too. (`sort` is stable: one tx keeps its order.)
 */
function executionOrder(a: RecordedReceipt, b: RecordedReceipt): number {
  for (const r of [a, b]) if (!Number.isSafeInteger(r.block_height)) throw new Error(`receipt ${r.receipt_id} has no block_height`);
  if (a.block_height !== b.block_height) return a.block_height - b.block_height;
  if (a.index_in_block !== undefined && b.index_in_block !== undefined) {
    if (a.index_in_block !== b.index_in_block) return a.index_in_block - b.index_in_block;
    if (a.receipt_id === b.receipt_id) return 0;
    throw new Error(
      `receipts ${a.receipt_id} (tx ${a.tx_hash}) and ${b.receipt_id} (tx ${b.tx_hash}) share index_in_block ${a.index_in_block} in block ${a.block_height}; their execution order is unknown`,
    );
  }
  if (a.tx_hash === b.tx_hash) return 0;
  throw new Error(
    `receipts ${a.receipt_id} and ${b.receipt_id} (different txs) executed in block ${a.block_height}; set index_in_block on both to give their execution order`,
  );
}

/**
 * Replays the receipts in execution order and returns one row per payout decision. Supplier state
 * comes from successful receipts only. A `payout_approved` in a failed receipt (a check after
 * it, such as the budget, panicked) is a refusal with the panic's code.
 */
export function buildRows(rec: Recording, last4: Map<string, string>): Row[] {
  const suppliers = new Map<string, Supplier>();
  const sk = (agent: string, supplier: string) => `${agent}\u0000${supplier}`;
  const receipts = [...rec.receipts].sort(executionOrder);
  const rows: Row[] = [];
  for (const r of receipts) {
    const ns = BigInt(r.block_timestamp_ns);
    const now = Number(ns / 1_000_000_000n);
    const at = new Date(Number(ns / 1_000_000n));
    const ok = r.status === "success";
    const lookup = (agent: string, supplier: string) => {
      const s = suppliers.get(sk(agent, supplier));
      return s && settle(s, now);
    };
    const row = (agent: string, supplier: string, invoiceId: string, payoutId: string, commitment: string | undefined) => ({
      date: `${pad(at.getUTCDate())}.${pad(at.getUTCMonth() + 1)}.${at.getUTCFullYear()}`,
      time: `${pad(at.getUTCHours())}:${pad(at.getUTCMinutes())}:${pad(at.getUTCSeconds())}`,
      supplier: lookup(agent, supplier)?.name ?? supplier,
      ibanLast4: (commitment && last4.get(commitment.toLowerCase())) ?? "",
      invoiceId,
      currency: "EUR",
      rail: "SEPA",
      txHash: r.tx_hash,
      payoutId,
    });
    for (const { event, data } of parseEvents(r.logs)) {
      if (event === "payout_refused") {
        const s = lookup(data.key.agent, data.supplier);
        const commitment =
          data.reason === "ERR_BANK_CHANGE_COOLING_OFF"
            ? s?.pending?.commitment
            : AFTER_IBAN_CHECK.has(data.reason)
              ? s?.current
              : undefined; // the IBAN did not open a listed commitment, or was never checked
        rows.push({
          ...row(data.key.agent, data.supplier, data.invoice_id, data.key.request_id, commitment),
          amount: "",
          decision: "refused",
          reasonCode: data.reason,
        });
        continue;
      }
      if (event === "payout_approved") {
        const commitment = lookup(data.key.agent, data.supplier)?.current;
        const base = row(data.key.agent, data.supplier, data.invoice_id, data.key.request_id, commitment);
        rows.push(
          ok
            ? { ...base, amount: euros(data.amount), decision: "approved", reasonCode: "" }
            : { ...base, amount: "", decision: "refused", reasonCode: /\bERR_[A-Z0-9_]+/.exec(r.failure ?? "")?.[0] ?? "RECEIPT_FAILED" },
        );
        continue;
      }
      if (!ok) continue; // a failed receipt's other logs record no state change
      if (event === "payee_added" && data.payee.rail === "sepa") {
        suppliers.set(sk(data.agent, data.payee.supplier), { name: data.payee.name });
      } else if (event === "payee_removed" && data.payee.rail === "sepa") {
        suppliers.delete(sk(data.agent, data.payee.supplier));
      } else if (event === "supplier_iban_pending") {
        const s = lookup(data.agent, data.supplier);
        if (s) s.pending = { commitment: data.iban_commitment, effectiveAt: data.effective_at };
      } else if (event === "supplier_iban_cancelled") {
        const s = lookup(data.agent, data.supplier);
        if (s) s.pending = undefined;
      } else if (event === "agent_revoked") {
        for (const k of [...suppliers.keys()]) if (k.startsWith(`${data.agent}\u0000`)) suppliers.delete(k);
      }
    }
  }
  return rows;
}

const pad = (n: number) => String(n).padStart(2, "0");

/** A canonical euro amount (`42.5`) with a decimal comma and at least two decimals (`42,50`). */
export function euros(amount: string): string {
  const m = /^([0-9]+)(?:\.([0-9]+))?$/.exec(amount);
  if (!m) throw new Error(`not a canonical euro amount: ${amount}`);
  return `${m[1]},${(m[2] ?? "").padEnd(2, "0")}`;
}

/**
 * One CSV cell: a leading `= + - @`, tab or CR is prefixed with `'` so a spreadsheet shows it as
 * text instead of running it as a formula, then quoted if it holds `;`, `"` or a line break.
 */
export function cell(v: string): string {
  const s = /^[=+\-@\t\r]/.test(v) ? `'${v}` : v;
  return /[;"\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

/** The CSV: UTF-8 BOM (so Excel reads it as UTF-8), `;` separators, CRLF line ends. */
export function toCsv(rows: Row[], preamble: string[] = []): string {
  const lines = [
    ...preamble.map((p) => cell(`# ${p}`)),
    HEADER.map(cell).join(";"),
    ...rows.map((r) =>
      [r.date, r.time, r.supplier, r.ibanLast4, r.invoiceId, r.amount, r.currency, r.rail, r.txHash, r.payoutId, r.decision, r.reasonCode]
        .map(cell)
        .join(";"),
    ),
  ];
  return `﻿${lines.join("\r\n")}\r\n`;
}

/** No IBAN-shaped string (2 letters, 2 digits, 11+ alphanumerics) anywhere in `text`. */
export function assertNoIban(text: string): void {
  if (/[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}/.test(text)) throw new Error("export would contain a full IBAN; refusing to write it");
}

export type BlockInfo = { height: number; timestamp_ns: string };

/**
 * The contract's receipts in an `EXPERIMENTAL_tx_status` result, with each receipt's block
 * height and timestamp from `blocks` (block hash -> header). Receipts on other accounts are dropped.
 */
export function receiptsFromTxStatus(result: any, contract: string, blocks: Map<string, BlockInfo>): RecordedReceipt[] {
  const txHash: string = result.transaction.hash;
  return (result.receipts_outcome as any[])
    .filter((o) => o.outcome.executor_id === contract)
    .map((o) => {
      const block = blocks.get(o.block_hash);
      if (!block) throw new Error(`no header for block ${o.block_hash}`);
      const failure = o.outcome.status?.Failure;
      return {
        tx_hash: txHash,
        receipt_id: o.id,
        block_height: block.height,
        block_timestamp_ns: block.timestamp_ns,
        status: failure ? "failure" : "success",
        failure: failure ? JSON.stringify(failure) : null,
        logs: o.outcome.logs,
      };
    });
}
