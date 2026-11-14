// pnpm add-payee <agent> x402 <0x address>
//          | <agent> sepa <supplier> <name> <IBAN> <cap EUR> [salt]: allowlists a payee and checks
// it. A supplier's IBAN goes on chain only as a salted commitment; the salt (fresh unless given) is
// saved to the owner's 0600 salt book before the call and printed once the call is sent, for the
// agent's and M1's supplier book. The first IBAN cools off before it is payable.
import { isDeepStrictEqual } from "node:util";
import { payeeArgs, type Payee } from "../borsh.ts";
import { assertAgentId, config, view, waitFor } from "../near.ts";
import { getConfig, ownerCall } from "../owner.ts";
import { eurToBaseUnits, ibanCommitment, newSalt, recordSalt, saltsFile } from "../supplier.ts";

const USAGE = "usage: add-payee <agent> x402 <0x address> | <agent> sepa <supplier> <name> <IBAN> <cap EUR> [salt]";
const cfg = config();
const [agent, rail, ...rest] = process.argv.slice(2);
if (!agent || (rail !== "x402" && rail !== "sepa")) throw new Error(USAGE);
assertAgentId(agent);

let payee: Payee;
let salt: string | undefined;
let iban = "";
if (rail === "x402") {
  if (!rest[0]) throw new Error(USAGE);
  payee = { rail, pay_to: rest[0] };
} else {
  const [supplier, name, ibanArg, capEur, given] = rest;
  if (!supplier || !name || !ibanArg || !capEur) throw new Error(USAGE);
  iban = ibanArg;
  salt = given ?? newSalt();
  payee = { rail, supplier, name, iban_commitment: ibanCommitment(iban, salt), cap: eurToBaseUnits(capEur) };
}
if (payee.rail === "sepa") {
  const file = recordSalt(saltsFile(), { agent, supplier: payee.supplier, iban, salt: salt!, commitment: payee.iban_commitment });
  console.log(`salt saved to ${file} (mode 0600) before the call`);
}
const { nonce } = await ownerCall(cfg, "add_payee", { agent, payee }, payeeArgs(agent, payee));
if (payee.rail === "sepa") console.log(`salt of ${payee.supplier} (give it with the IBAN to the agent and M1, keep it off chain): ${salt}`);
await waitFor("owner_nonce consumed", async () => ((await getConfig(cfg)).owner_nonce >= nonce ? true : undefined));
if (payee.rail === "x402") {
  const want = { rail, pay_to: payee.pay_to.toLowerCase() };
  const payees = await view<Payee[]>(cfg, cfg.contractId, "get_payees", { agent });
  if (!payees.some((p) => isDeepStrictEqual(p, want))) {
    throw new Error(`get_payees does not list ${JSON.stringify(want)}: ${JSON.stringify(payees)}`);
  }
  console.log(`PASS: payees of ${agent} = ${JSON.stringify(payees)}`);
} else {
  const suppliers = await view<any[]>(cfg, cfg.contractId, "get_suppliers", { agent });
  const s = suppliers.find((x) => x.supplier === payee.supplier);
  const latest = s?.pending?.iban_commitment ?? s?.iban_commitment;
  if (latest !== payee.iban_commitment) throw new Error(`get_suppliers does not show ${payee.supplier} at the new commitment`);
  console.log(`PASS: supplier ${payee.supplier} of ${agent}, commitment ${payee.iban_commitment}, payable from ${s.pending?.effective_at ?? "now"}`);
}
