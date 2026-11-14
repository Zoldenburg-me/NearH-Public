// pnpm demo:inv104 [--local | --testnet [--check]] [--write]
//
// The AP1 INV-104 story: register supplier at IBAN A -> pay INV-104 -> "we changed banks", the
// owner moves the supplier to IBAN B (passkey) -> a payout to B is held during the 60 s
// cooling-off (ERR_BANK_CHANGE_COOLING_OFF) -> INV-104 again is refused (ERR_DUPLICATE_INVOICE).
// Every contract event of every step is printed with its reason code.
//
// --local (default): runs it in the near-workspaces sandbox (contract/tests/integration,
//   test demo_inv104) with the harness's software P-256 owner key and mock MPC. Not testnet.
// --testnet: runs it on NEAR testnet against an already deployed contract, signing owner calls
//   with the owner key in OWNER_KEY_DIR and payouts with the agent key. It first checks, read-only,
//   that everything is in place and otherwise stops with the steps the owner must take.
//   --check stops after that preflight. It never deploys, creates keys or prints a secret.
// --write: also saves the transcript under demo/evidence/.
//
// Env (testnet): CONTRACT_ID or MANDATE_CONTRACT_ID, SUBMITTER_ACCOUNT_ID, OWNER_KEY_DIR, NEAR_RPC,
// AGENT_ID (default agent-1), AGENT_NEAR_PRIVATE_KEY (optional, else the add-agent key file),
// AP1_IBAN_A (or MONERIUM_PAYEE_IBAN), AP1_IBAN_B, AP1_SUPPLIER (default acme-<unix time>).
import { spawn, spawnSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { bytesToHex } from "@noble/hashes/utils.js";
import { callAndWait, failureMessage, httpRpc, parseNearKey, view as agentView, type NearKey } from "@nearh/agent-signer";
import { base58Encode } from "@nearh/owner-near/src/base58.ts";
import { changeSupplierIbanArgs, coolingOffArgs, payeeArgs, type Payee } from "@nearh/owner-near/src/borsh.ts";
import { agentKeyPath, loadOwnerKey, ownerKeyPath } from "@nearh/owner-near/src/keys.ts";
import { assertAgentId, config, view, waitFor, type Config } from "@nearh/owner-near/src/near.ts";
import { getConfig, ownerCall } from "@nearh/owner-near/src/owner.ts";
import { eurToBaseUnits, ibanCommitment, newSalt, recordSalt, saltsFile } from "@nearh/owner-near/src/supplier.ts";
import { assertNoIban, cargoNearProblem, COOLING_OFF_MARGIN_SECS, eventLines, localTranscript, maskIban, preflightProblems, reasonCode, requestIds, STORY, supplierIdProblem, type Preflight } from "./src/inv104.ts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const args = new Set(process.argv.slice(2));
const mode = args.has("--testnet") ? "testnet" : "local";
const lines: string[] = [];
const say = (l = "") => {
  lines.push(l);
  console.log(l);
};

function gitHead(): string {
  const r = spawnSync("git", ["describe", "--always", "--dirty"], { cwd: ROOT, encoding: "utf8" });
  return r.status === 0 ? r.stdout.trim() : "unknown";
}

function writeEvidence(file: string, header: string[]): void {
  const text = [...header, "", ...lines, ""].join("\n");
  assertNoIban(text);
  const path = join(ROOT, "demo", "evidence", file);
  writeFileSync(path, text);
  console.log(`\nwrote ${path}`);
}

// ---------- local sandbox ----------

async function runLocal(): Promise<void> {
  // compile_project builds the wasm with `cargo near build`; without it cargo fails deep in the build.
  const missing = cargoNearProblem(spawnSync("cargo", ["near", "--help"], { cwd: ROOT, encoding: "utf8" }));
  if (missing) {
    console.error(missing);
    process.exit(1);
  }
  const cargoArgs = ["test", "--manifest-path", join(ROOT, "contract/tests/integration/Cargo.toml"), "--test", "demo_inv104", "--", "--nocapture"];
  console.error(`running: cargo ${cargoArgs.join(" ")}`);
  console.error("building contracts (first run can take 10+ min); cargo progress follows on stderr…");
  const child = spawn("cargo", cargoArgs, { cwd: ROOT, stdio: ["ignore", "pipe", "pipe"] });
  // stdout carries the DEMO transcript and is only parsed at the end; cargo's progress goes to
  // stderr and is relayed live. compile_project builds the wasm silently, so while nothing arrives
  // a heartbeat line says the run is still alive.
  const started = Date.now();
  let lastOutput = started;
  const heartbeat = setInterval(() => {
    if (Date.now() - lastOutput < 30_000) return;
    console.error(`  …still building/running (${Math.round((Date.now() - started) / 60_000)} min elapsed)`);
    lastOutput = Date.now();
  }, 5_000);
  let out = "";
  child.stdout.on("data", (d) => (out += d));
  child.stderr.on("data", (d) => {
    lastOutput = Date.now();
    process.stderr.write(d);
  });
  const code: number = await new Promise((r) => child.on("close", (c) => r(c ?? 1)));
  clearInterval(heartbeat);
  if (code !== 0) {
    process.stderr.write(out.slice(-4000));
    throw new Error(`sandbox demo failed (cargo exit ${code}); on an Intel Mac set NEAR_SANDBOX_BIN_PATH (contract/tests/integration/src/lib.rs)`);
  }
  for (const l of localTranscript(out)) say(l);
  if (args.has("--write")) {
    writeEvidence("ap1-inv104-local-sandbox.txt", [
      "# AP1 INV-104 demo: LOCAL SANDBOX RUN, NOT TESTNET",
      "# near-workspaces sandbox, the harness's software P-256 key as the owner passkey, mock MPC signer,",
      "# fixture IBANs (last 4 only). No NEAR testnet, no Monerium, no funds.",
      `# \`pnpm demo:inv104 --local --write\` at commit ${gitHead()}, ${new Date().toISOString()}`,
    ]);
  }
}

// ---------- testnet ----------

type Ctx = { cfg: Config; agent: string; key: NearKey; submitter: string; supplier: string; ibanA: string; ibanB: string };

function agentKeyString(cfg: Config | undefined, agent: string): { key?: string; source?: "env" | "file"; path?: string } {
  if (process.env.AGENT_NEAR_PRIVATE_KEY) return { key: process.env.AGENT_NEAR_PRIVATE_KEY, source: "env" };
  if (!cfg) return {};
  const path = agentKeyPath(cfg, agent);
  if (!existsSync(path)) return { path };
  return { key: JSON.parse(readFileSync(path, "utf8")).private_key, source: "file", path };
}

/** Read-only checks; returns the problems and, when there are none, what the run needs. */
async function preflight(): Promise<{ problems: string[]; ctx?: Ctx }> {
  if (!process.env.CONTRACT_ID && process.env.MANDATE_CONTRACT_ID) process.env.CONTRACT_ID = process.env.MANDATE_CONTRACT_ID;
  const agent = assertAgentId(process.env.AGENT_ID || "agent-1");
  const supplier = process.env.AP1_SUPPLIER || `acme-${Math.floor(Date.now() / 1000)}`;
  const p: Preflight = {
    agent,
    supplier,
    ibanA: process.env.AP1_IBAN_A || process.env.MONERIUM_PAYEE_IBAN || undefined,
    ibanB: process.env.AP1_IBAN_B || undefined,
    submitter: process.env.SUBMITTER_ACCOUNT_ID || undefined,
    nearCliFound: spawnSync("near", ["--version"], { stdio: "ignore" }).status === 0,
  };
  if (p.submitter) p.submitterKeyFound = existsSync(join(homedir(), ".near-credentials", "testnet", `${p.submitter}.json`));
  let cfg: Config | undefined;
  if (process.env.CONTRACT_ID) {
    cfg = config(); // throws on a non-testnet account or RPC
    p.contractId = cfg.contractId;
    p.ownerKeyPath = ownerKeyPath(cfg);
    p.agentKeyPath = agentKeyPath(cfg, agent);
    try {
      const c: any = await getConfig(cfg);
      p.ownerMode = c.owner?.mode;
      p.network = c.network;
      p.hasCoolingOff = typeof c.bank_change_cooling_off_secs === "number";
      p.ownerKeyFound = existsSync(p.ownerKeyPath);
      if (p.ownerKeyFound && c.owner?.mode === "passkey") {
        p.ownerKeyMatches = Buffer.from(c.owner.public_key, "base64").toString("hex") === bytesToHex(loadOwnerKey(cfg).publicKey);
      }
    } catch (e) {
      p.contractError = (e as Error).message;
    }
  }
  const ak = agentKeyString(cfg, agent);
  p.agentKeySource = ak.source;
  if (ak.path) p.agentKeyPath = ak.path;
  let key: NearKey | undefined;
  if (cfg && ak.key && !p.contractError) {
    key = parseNearKey(cfg.contractId, ak.key);
    const pk = `ed25519:${base58Encode(key.publicKey)}`;
    p.agentOfKey = (await view<string | null>(cfg, cfg.contractId, "agent_of_key", { public_key: pk })) ?? null;
    if (p.agentOfKey === agent) {
      const m = await view<any>(cfg, cfg.contractId, "get_mandate", { agent });
      p.sepaMaxEure = m ? BigInt(m.sepa.amount_range.max) : null;
      if (m) {
        p.sepaMinEure = BigInt(m.sepa.amount_range.min);
        const b = await view<any>(cfg, cfg.contractId, "get_budget", { agent, rail: "sepa" });
        if (b) p.sepaBudgetLeftEure = BigInt(b.budget) - BigInt(b.reserved);
      }
    }
    if (!supplierIdProblem(supplier)) {
      p.supplierExists = (await view<any[]>(cfg, cfg.contractId, "get_suppliers", { agent })).some((x) => x.supplier === supplier);
      p.supplierInvoicePaid = await view<boolean>(cfg, cfg.contractId, "is_invoice_paid", { supplier, invoice_id: STORY.inv104.id });
    }
  }
  const problems = preflightProblems(p);
  if (problems.length || !cfg || !key) return { problems };
  return { problems, ctx: { cfg, agent, key, submitter: p.submitter!, supplier, ibanA: p.ibanA!, ibanB: p.ibanB! } };
}

/** The `EVENT_JSON` logs of a tx's receipts on the contract, failed receipts included. */
async function txLogs(cfg: Config, hash: string, sender: string): Promise<string[]> {
  const near = httpRpc(cfg.rpc);
  for (let i = 0; i < 10; i++) {
    try {
      const r = await near("EXPERIMENTAL_tx_status", { tx_hash: hash, sender_account_id: sender, wait_until: "FINAL" });
      return (r.receipts_outcome as any[]).filter((o) => o.outcome.executor_id === cfg.contractId).flatMap((o) => o.outcome.logs);
    } catch {
      await new Promise((r) => setTimeout(r, 3000));
    }
  }
  return [`(logs of ${hash} not readable yet; use \`pnpm record-receipts ${sender} ${hash}\`)`];
}

const txs: { sender: string; hash: string }[] = [];

async function owner(ctx: Ctx, method: string, json: Record<string, unknown>, borsh: Uint8Array): Promise<void> {
  const { txHash, nonce } = await ownerCall(ctx.cfg, method, json, borsh);
  await waitFor("owner_nonce consumed", async () => ((await getConfig(ctx.cfg)).owner_nonce >= nonce ? true : undefined));
  if (!txHash) throw new Error(`${method}: no tx hash printed; check the near-cli output above`);
  txs.push({ sender: ctx.submitter, hash: txHash });
  say(`  tx ${txHash}`);
  for (const l of eventLines(await txLogs(ctx.cfg, txHash, ctx.submitter))) say(l);
  say("  outcome: OK");
}

/** A payout request with the agent key; `expect` is "OK" or the reason code it must be refused with. */
async function payout(ctx: Ctx, requestId: string, iban: string, salt: string, inv: { id: string; amount: string }, expect: string): Promise<void> {
  const shape = { type: "payout", supplier: ctx.supplier, iban, salt, amount: inv.amount, invoice_id: inv.id, invoice_amount: inv.amount, timestamp: Math.floor(Date.now() / 1000) };
  const r = await callAndWait(httpRpc(ctx.cfg.rpc), ctx.key, ctx.cfg.contractId, "request_signature", { request_id: requestId, shape }, { gas: 300_000_000_000_000n, deadlineMs: Date.now() + 180_000 });
  txs.push({ sender: ctx.cfg.contractId, hash: r.hash });
  say(`  tx ${r.hash}`);
  for (const l of eventLines(await txLogs(ctx.cfg, r.hash, ctx.cfg.contractId))) say(l);
  let outcome: string;
  if (r.failure !== undefined) outcome = `REFUSED ${reasonCode(failureMessage(r.failure)) ?? failureMessage(r.failure)}`;
  else {
    const res = JSON.parse(Buffer.from(r.successValue ?? "", "base64").toString() || "null");
    outcome = res?.status === "signed" ? "OK" : `NOT SIGNED (${res?.status})`;
    say(`  reservation: ${res?.status}`);
  }
  say(`  outcome: ${outcome}`);
  const want = expect === "OK" ? "OK" : `REFUSED ${expect}`;
  if (outcome !== want) throw new Error(`expected ${want}, got ${outcome}`);
}

function step(n: number, title: string): void {
  say();
  say(`[${n}] ${title}`);
}

async function runTestnet(): Promise<void> {
  const { problems, ctx } = await preflight();
  if (!ctx) {
    console.log("Testnet preflight (read-only, nothing sent). Before the INV-104 run can start:\n");
    for (const p of problems) console.log(p);
    console.log("\nThen run `pnpm demo:inv104 --testnet` again. Runbook: demo/evidence/README.md.");
    process.exitCode = 2;
    return;
  }
  console.log(`Testnet preflight passed: contract ${ctx.cfg.contractId}, agent ${ctx.agent}, supplier ${ctx.supplier}.`);
  if (args.has("--check")) return;

  const { cfg, agent, supplier } = ctx;
  say("AP1 INV-104 demo: NEAR TESTNET RUN");
  say(`contract ${cfg.contractId} | agent ${agent} | supplier ${supplier} | submitter ${ctx.submitter}`);
  say(`IBAN A ${maskIban(ctx.ibanA)} | IBAN B ${maskIban(ctx.ibanB)} (last 4 only)`);

  step(1, `Owner sets the demo bank-change cooling-off to ${STORY.coolingOffSecs} s (passkey)`);
  if ((await getConfig(cfg)).bank_change_cooling_off_secs === STORY.coolingOffSecs) say(`  already ${STORY.coolingOffSecs} s; no tx`);
  else await owner(ctx, "set_bank_change_cooling_off", { secs: STORY.coolingOffSecs }, coolingOffArgs(STORY.coolingOffSecs));

  step(2, `Owner registers supplier ${supplier} (${STORY.supplierName}, cap ${STORY.capEur} EUR) at IBAN A ${maskIban(ctx.ibanA)} (passkey)`);
  const saltA = newSalt();
  const payee: Payee = { rail: "sepa", supplier, name: STORY.supplierName, iban_commitment: ibanCommitment(ctx.ibanA, saltA), cap: eurToBaseUnits(STORY.capEur) };
  recordSalt(saltsFile(), { agent, supplier, iban: ctx.ibanA, salt: saltA, commitment: payee.iban_commitment });
  await owner(ctx, "add_payee", { agent, payee }, payeeArgs(agent, payee));
  console.log(`  waiting out the first IBAN's ${STORY.coolingOffSecs} s cooling-off...`);
  await waitFor("IBAN A payable", async () => {
    const s = (await view<any[]>(cfg, cfg.contractId, "get_suppliers", { agent })).find((x) => x.supplier === supplier);
    return s?.iban_commitment === payee.iban_commitment ? true : undefined;
  }, 60);
  say(`  IBAN A payable after the cooling-off`);

  step(3, `Agent pays ${STORY.inv104.id}, EUR ${STORY.inv104.amount}, to IBAN A`);
  const ids = requestIds(supplier);
  await payout(ctx, ids.inv104a, ctx.ibanA, saltA, STORY.inv104, "OK");

  step(4, `"We changed banks" email: owner moves ${supplier} to IBAN B ${maskIban(ctx.ibanB)} (passkey)`);
  const saltB = newSalt();
  const commitmentB = ibanCommitment(ctx.ibanB, saltB);
  recordSalt(saltsFile(), { agent, supplier, iban: ctx.ibanB, salt: saltB, commitment: commitmentB });
  await owner(ctx, "change_supplier_iban", { agent, supplier, iban_commitment: commitmentB }, changeSupplierIbanArgs(agent, supplier, commitmentB));
  const s = (await view<any[]>(cfg, cfg.contractId, "get_suppliers", { agent })).find((x) => x.supplier === supplier);
  say(`  get_suppliers: ${JSON.stringify(s)}`);

  step(5, `Agent pays ${STORY.inv105.id}, EUR ${STORY.inv105.amount}, to IBAN B during the cooling-off`);
  // Reading step 4's logs can take up to ~30 s on a slow RPC. Send the IBAN B payout only while at
  // least COOLING_OFF_MARGIN_SECS of its cooling-off are left, else stop instead of a misleading OK.
  const left = Number(s?.pending?.effective_at ?? 0) - Math.floor(Date.now() / 1000);
  if (left < COOLING_OFF_MARGIN_SECS) throw new Error(`only ${left} s of IBAN B's cooling-off left (need ${COOLING_OFF_MARGIN_SECS} s margin); testnet RPC too slow, run again`);
  say(`  ${left} s of the cooling-off left`);
  await payout(ctx, ids.inv105b, ctx.ibanB, saltB, STORY.inv105, "ERR_BANK_CHANGE_COOLING_OFF");

  step(6, `Agent pays ${STORY.inv104.id} again, EUR ${STORY.inv104.amount}, to IBAN A`);
  await payout(ctx, ids.inv104b, ctx.ibanA, saltA, STORY.inv104, "ERR_DUPLICATE_INVOICE");
  say(`  is_invoice_paid(${supplier}, ${STORY.inv104.id}) = ${await agentView(httpRpc(cfg.rpc), cfg.contractId, "is_invoice_paid", { supplier, invoice_id: STORY.inv104.id })}`);

  say();
  say(`Result: ${STORY.inv104.id} paid once; the new IBAN held during the cooling-off (ERR_BANK_CHANGE_COOLING_OFF); ${STORY.inv104.id} again refused (ERR_DUPLICATE_INVOICE).`);
  say(`Receipts for the AP2 CSV: pnpm record-receipts (in scripts/owner/near) per sender: ${txs.map((t) => `${t.sender} ${t.hash}`).join(", ")}`);
  if (args.has("--write")) {
    writeEvidence("ap1-inv104-testnet.txt", [
      "# AP1 INV-104 demo: NEAR TESTNET RUN",
      `# \`pnpm demo:inv104 --testnet --write\` at commit ${gitHead()}, ${new Date().toISOString()}. Payouts were signed, not sent to Monerium.`,
    ]);
  }
}

await (mode === "testnet" ? runTestnet() : runLocal());
