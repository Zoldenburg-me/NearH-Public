// pnpm change-supplier-iban <agent> <supplier> <IBAN> [salt] | <agent> <supplier> --cancel:
// records new bank details for a supplier (payable only after the cooling-off), or withdraws a
// pending change. Saves the new salt to the owner's 0600 salt book before the call and prints it once
// the call is sent; checks get_suppliers.
import { cancelSupplierIbanChangeArgs, changeSupplierIbanArgs } from "../borsh.ts";
import { assertAgentId, config, view, waitFor } from "../near.ts";
import { getConfig, ownerCall } from "../owner.ts";
import { ibanCommitment, newSalt, recordSalt, saltsFile } from "../supplier.ts";

const cfg = config();
const [agent, supplier, iban, given] = process.argv.slice(2);
if (!agent || !supplier || !iban) throw new Error("usage: change-supplier-iban <agent> <supplier> <IBAN> [salt] | <agent> <supplier> --cancel");
assertAgentId(agent);
const cancel = iban === "--cancel";
const salt = cancel ? undefined : given ?? newSalt();
const commitment = salt ? ibanCommitment(iban, salt) : undefined;
if (salt) console.log(`salt saved to ${recordSalt(saltsFile(), { agent, supplier, iban, salt, commitment: commitment! })} (mode 0600) before the call`);
const { nonce } = cancel
  ? await ownerCall(cfg, "cancel_supplier_iban_change", { agent, supplier }, cancelSupplierIbanChangeArgs(agent, supplier))
  : await ownerCall(cfg, "change_supplier_iban", { agent, supplier, iban_commitment: commitment }, changeSupplierIbanArgs(agent, supplier, commitment!));
if (salt) console.log(`salt of ${supplier} (give it with the IBAN to the agent and M1, keep it off chain): ${salt}`);
await waitFor("owner_nonce consumed", async () => ((await getConfig(cfg)).owner_nonce >= nonce ? true : undefined));
const s = (await view<any[]>(cfg, cfg.contractId, "get_suppliers", { agent })).find((x) => x.supplier === supplier);
if (cancel) {
  if (!s || s.pending) throw new Error(`${supplier} still has a pending change: ${JSON.stringify(s)}`);
  console.log(`PASS: pending bank change of ${supplier} cancelled`);
} else {
  if (s?.pending?.iban_commitment !== commitment) throw new Error(`get_suppliers does not show the pending change: ${JSON.stringify(s)}`);
  console.log(`PASS: ${supplier} new commitment ${commitment} payable from ${s.pending.effective_at}`);
}
