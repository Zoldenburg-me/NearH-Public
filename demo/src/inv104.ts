// Pure helpers of the AP1 INV-104 demo (ap1-inv104.ts): event lines, reason codes, IBAN masking,
// the local transcript, and the testnet preflight's instructions. No I/O here, so tests cover them.

import { eurToBaseUnits } from "@nearh/owner-near/src/supplier.ts";

/** Payout amounts and ids of the story. */
export const STORY = {
  coolingOffSecs: 60,
  supplierName: "Acme GmbH",
  capEur: "50",
  inv104: { id: "INV-104", amount: "42.50" },
  inv105: { id: "INV-105", amount: "10" },
} as const;

/** Request ids the testnet run derives from the supplier id, one per payout step. */
export const requestIds = (supplier: string) => ({ inv104a: `${supplier}-inv-104-a`, inv105b: `${supplier}-inv-105-b`, inv104b: `${supplier}-inv-104-b` });

/** The contract's id rule for agents, suppliers and request ids: 1-64 chars of `[A-Za-z0-9._:-]`. */
const isId = (s: string) => /^[A-Za-z0-9._:-]{1,64}$/.test(s);

/** Seconds of the IBAN B cooling-off that must still be left when its payout is sent. */
export const COOLING_OFF_MARGIN_SECS = 20;

/** Why `supplier` (AP1_SUPPLIER) cannot be used, or undefined: it and every request id derived from it must pass the contract's id rule. */
export function supplierIdProblem(supplier: string): string | undefined {
  if (!isId(supplier)) return `AP1_SUPPLIER="${supplier}" is not a supplier id (1-64 chars of [A-Za-z0-9._:-]).`;
  const longest = Object.values(requestIds(supplier)).reduce((a, b) => (b.length > a.length ? b : a));
  if (supplier.startsWith("link-")) return `AP1_SUPPLIER="${supplier}" starts with "link-": the contract reserves that prefix for link_agent request ids, so the first payout would fail. Pick another id.`;
  if (!isId(longest)) return `AP1_SUPPLIER is too long: request id "${longest}" exceeds 64 chars. Use at most ${64 - (longest.length - supplier.length)} chars, or unset it for a fresh acme-<unix time>.`;
}

const IBAN = /^[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}$/;

export const isIban = (s: string | undefined): s is string => !!s && IBAN.test(s);

/** `****1234`: the only form of an IBAN the demo prints. */
export const maskIban = (iban: string) => `****${iban.slice(-4)}`;

/** The `ERR_*` code in a contract failure (`"{CODE}: {detail}"`, docs/interfaces.md §7), else undefined. */
export function reasonCode(failure: string): string | undefined {
  return /\b(ERR_[A-Z0-9_]+)/.exec(failure)?.[1];
}

/** One line per `EVENT_JSON` log, as the sandbox transcript prints them (demo_inv104.rs). */
export function eventLines(logs: string[]): string[] {
  const out: string[] = [];
  for (const log of logs) {
    if (!log.startsWith("EVENT_JSON:")) continue;
    let e: any;
    try {
      e = JSON.parse(log.slice("EVENT_JSON:".length));
    } catch {
      continue;
    }
    const reason = typeof e?.data?.reason === "string" ? e.data.reason : "-";
    out.push(`  event ${String(e?.event ?? "?").padEnd(24)} reason=${reason.padEnd(28)} data=${JSON.stringify(e?.data ?? null)}`);
  }
  return out;
}

/** The `DEMO ` lines of the sandbox test's output, without the prefix. */
export function localTranscript(cargoOutput: string): string[] {
  return cargoOutput
    .split("\n")
    .filter((l) => l === "DEMO" || l.startsWith("DEMO "))
    .map((l) => l.slice(5));
}

/** The cargo-near CI pins (CARGO_NEAR_VERSION in .github/workflows/ci.yml); the sandbox build needs it. */
export const CARGO_NEAR_VERSION = "0.22.0";

/** How to install that cargo-near: the prebuilt release binary first, the source build as fallback. */
export const CARGO_NEAR_INSTALL =
  `install the prebuilt binary with curl --proto '=https' --tlsv1.2 -LsSf https://github.com/near/cargo-near/releases/download/cargo-near-v${CARGO_NEAR_VERSION}/cargo-near-installer.sh | sh` +
  ` (or build from source, several minutes: cargo install --locked cargo-near@${CARGO_NEAR_VERSION})`;

/** Why `cargo near --help` shows cargo or cargo-near is missing, from its spawnSync result; `undefined` if it is there. */
export function cargoNearProblem(r: { error?: Error; stderr?: string | null }): string | undefined {
  if (r.error) return `cargo not found (${r.error.message}): install rustup, see README Quick start`;
  if (/no such (sub)?command/i.test(r.stderr ?? "")) return `cargo-near not found: ${CARGO_NEAR_INSTALL}`;
}

/** Throws if `text` holds an IBAN-shaped string that is not masked (evidence must not leak one). */
export function assertNoIban(text: string): void {
  const m = /\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\b/.exec(text);
  if (m) throw new Error(`refusing to write an unmasked IBAN-shaped string (${maskIban(m[0])})`);
}

/** What the read-only testnet preflight found; `undefined` where it could not look. */
export type Preflight = {
  contractId?: string;
  contractError?: string;
  ownerMode?: string;
  network?: string;
  hasCoolingOff?: boolean;
  ownerKeyPath?: string;
  ownerKeyFound?: boolean;
  ownerKeyMatches?: boolean;
  submitter?: string;
  submitterKeyFound?: boolean;
  nearCliFound?: boolean;
  agent: string;
  agentKeySource?: "env" | "file";
  agentKeyPath?: string;
  agentOfKey?: string | null;
  sepaMaxEure?: bigint | null;
  sepaMinEure?: bigint;
  /** SEPA budget minus what is reserved in the current window. */
  sepaBudgetLeftEure?: bigint;
  supplier?: string;
  /** Whether `get_suppliers` already lists the supplier for this agent. */
  supplierExists?: boolean;
  /** Whether `is_invoice_paid(supplier, INV-104)`. */
  supplierInvoicePaid?: boolean;
  ibanA?: string;
  ibanB?: string;
};

/**
 * Numbered instructions for everything the testnet run still needs; empty when it can run.
 * Owner-only steps (the passkey, the agent key) say so: the script never creates keys or deploys.
 */
export function preflightProblems(p: Preflight): string[] {
  const out: string[] = [];
  const contractOk = !!p.contractId && !p.contractError;
  if (!p.contractId) {
    out.push("Set CONTRACT_ID (or MANDATE_CONTRACT_ID in the root .env) to a mandate contract on testnet, deployed from current main. OWNER: `pnpm keygen` and `pnpm deploy-contract` in scripts/owner/near (see its README); this script never deploys.");
  } else if (p.contractError) {
    out.push(`Cannot read get_config on ${p.contractId}: ${p.contractError}. Deploy the current contract there first (OWNER: scripts/owner/near \`pnpm deploy-contract\`).`);
  } else {
    if (p.ownerMode !== "passkey") out.push(`The contract's owner is in ${p.ownerMode} mode; the demo signs owner calls for a passkey owner only.`);
    if (p.network !== "testnet") out.push(`The contract's network is ${p.network}; testnet only.`);
    if (!p.hasCoolingOff) out.push("get_config has no bank_change_cooling_off_secs: the contract predates AP1. OWNER: deploy a fresh contract from current main (the state layout changed).");
    if (!p.ownerKeyFound) {
      out.push(`OWNER PASSKEY NEEDED: no owner key at ${p.ownerKeyPath}. Owner calls (cooling-off, add supplier, bank change) are signed with the owner key that \`pnpm keygen\` made before deploy; run the demo on the machine that holds it, or set OWNER_KEY_DIR to its folder.`);
    } else if (!p.ownerKeyMatches) {
      out.push(`OWNER PASSKEY NEEDED: the key at ${p.ownerKeyPath} is not ${p.contractId}'s owner. Point OWNER_KEY_DIR at the owner key used at deploy.`);
    }
  }
  if (!p.submitter) out.push("Set SUBMITTER_ACCOUNT_ID to a .testnet account with a key in ~/.near-credentials (it pays gas for owner calls; any account works, the passkey assertion is what counts).");
  else if (!p.submitterKeyFound) out.push(`No key for ${p.submitter} in ~/.near-credentials/testnet/. Create it with the faucet (scripts/owner/near README, Setup).`);
  if (!p.nearCliFound) out.push("Install near-cli-rs (`near` on PATH); owner calls go through it.");
  if (!p.agentKeySource) {
    const file = p.agentKeyPath ?? `$OWNER_KEY_DIR/<contract>/agents/${p.agent}.json`;
    out.push(`AGENT KEY NEEDED: set AGENT_NEAR_PRIVATE_KEY in demo/.env (never on the command line), or keep the key \`pnpm add-agent ${p.agent}\` generated at ${file}.`);
  } else if (p.agentOfKey === null) {
    out.push(`AGENT KEY NEEDED: the agent key (${p.agentKeySource === "env" ? "AGENT_NEAR_PRIVATE_KEY" : p.agentKeyPath}) is not on ${p.contractId}. OWNER: \`pnpm add-agent ${p.agent}\`.`);
  } else if (p.agentOfKey !== undefined && p.agentOfKey !== p.agent) {
    out.push(`The agent key belongs to "${p.agentOfKey}", not AGENT_ID="${p.agent}". Set AGENT_ID=${p.agentOfKey}.`);
  }
  if (contractOk && p.agentOfKey === p.agent) {
    const need = BigInt(eurToBaseUnits(STORY.inv104.amount));
    if (p.sepaMaxEure === null) out.push(`${p.agent} has no mandate. OWNER: \`pnpm set-mandate ${p.agent} examples/mandate.json\`.`);
    else if (p.sepaMaxEure !== undefined && p.sepaMaxEure < need) out.push(`${p.agent}'s mandate caps a SEPA payout below EUR ${STORY.inv104.amount}. OWNER: set a mandate like examples/mandate.json.`);
    if (p.sepaMaxEure !== null && p.sepaMinEure !== undefined && p.sepaMinEure > need) out.push(`${p.agent}'s mandate sets a SEPA minimum above EUR ${STORY.inv104.amount}. OWNER: set a mandate like examples/mandate.json.`);
    if (p.sepaMaxEure !== null && p.sepaBudgetLeftEure !== undefined && p.sepaBudgetLeftEure < need) out.push(`${p.agent} has less than EUR ${STORY.inv104.amount} of SEPA budget left in this window. OWNER: raise the budget (\`pnpm set-mandate\`) or wait for the next window.`);
  }
  if (p.supplier !== undefined) {
    const idProblem = supplierIdProblem(p.supplier);
    if (idProblem) out.push(idProblem);
    else if (p.supplierExists) out.push(`Supplier "${p.supplier}" is already registered for ${p.agent}; the run registers a fresh one. Unset AP1_SUPPLIER (a fresh acme-<unix time> is used) or pick a new id.`);
    else if (p.supplierInvoicePaid) out.push(`${STORY.inv104.id} is already paid for supplier "${p.supplier}". Unset AP1_SUPPLIER or pick a new id.`);
  }
  if (!isIban(p.ibanA)) out.push("Set AP1_IBAN_A (or MONERIUM_PAYEE_IBAN) to the supplier's first IBAN: a Monerium sandbox or fixture IBAN, uppercase, no spaces. Never a real one.");
  if (!isIban(p.ibanB)) out.push("Set AP1_IBAN_B to the supplier's \"new bank\" IBAN: sandbox or fixture only, uppercase, no spaces.");
  if (isIban(p.ibanA) && p.ibanA === p.ibanB) out.push("AP1_IBAN_A and AP1_IBAN_B must differ.");
  return out.map((s, i) => `${i + 1}. ${s}`);
}
