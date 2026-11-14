// pnpm set-cooling-off <secs>: the cooling-off of new supplier IBANs (60..2592000, default
// 86400 on deploy; the demo uses 60). Checks get_config.
import { coolingOffArgs } from "../borsh.ts";
import { config, waitFor } from "../near.ts";
import { getConfig, ownerCall } from "../owner.ts";

const cfg = config();
const secs = Number(process.argv[2]);
if (!Number.isInteger(secs)) throw new Error("usage: set-cooling-off <secs>");
const { nonce } = await ownerCall(cfg, "set_bank_change_cooling_off", { secs }, coolingOffArgs(secs));
const c = await waitFor("get_config shows the cooling-off", async () => {
  const c = await getConfig(cfg);
  return c.owner_nonce >= nonce ? c : undefined;
});
if ((c as any).bank_change_cooling_off_secs !== secs) throw new Error(`cooling-off is ${(c as any).bank_change_cooling_off_secs}, expected ${secs}`);
console.log(`PASS: bank_change_cooling_off_secs = ${secs}`);
