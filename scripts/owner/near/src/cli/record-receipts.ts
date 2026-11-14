// pnpm record-receipts <sender.testnet> <tx hash>... > recording.json: reads each tx's receipts on
// CONTRACT_ID from NEAR testnet (EXPERIMENTAL_tx_status, then each receipt's block height and
// timestamp) and prints a recording for pnpm export-csv. Read-only; sends nothing. RPC gives no
// execution order between txs in one block: export-csv refuses such receipts until index_in_block
// is set on them by hand (e.g. from an explorer).
import { assertTestnet, assertTestnetRpc, env } from "../near.ts";
import { receiptsFromTxStatus, type BlockInfo, type RecordedReceipt, type Recording } from "../export.ts";

const rpcUrl = env("NEAR_RPC", "https://archival-rpc.testnet.near.org");
assertTestnetRpc(rpcUrl);
const contract = assertTestnet("CONTRACT_ID", env("CONTRACT_ID"));
const [sender, ...txs] = process.argv.slice(2);
if (!sender || txs.length === 0) throw new Error("usage: record-receipts <sender.testnet> <tx hash>...");
assertTestnet("sender", sender);

async function call(method: string, params: unknown): Promise<any> {
  const res = await fetch(rpcUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const body = (await res.json()) as any;
  if (body.error) throw new Error(`rpc ${method}: ${JSON.stringify(body.error)}`);
  return body.result;
}

const receipts: RecordedReceipt[] = [];
const blocks = new Map<string, BlockInfo>();
for (const tx of txs) {
  const result = await call("EXPERIMENTAL_tx_status", { tx_hash: tx, sender_account_id: sender, wait_until: "FINAL" });
  for (const o of result.receipts_outcome) {
    if (o.outcome.executor_id !== contract || blocks.has(o.block_hash)) continue;
    const block = await call("block", { block_id: o.block_hash });
    blocks.set(o.block_hash, { height: block.header.height, timestamp_ns: String(block.header.timestamp_nanosec ?? block.header.timestamp) });
  }
  receipts.push(...receiptsFromTxStatus(result, contract, blocks));
}
const rec: Recording = { source: "testnet", contract, receipts };
process.stdout.write(`${JSON.stringify(rec, null, 2)}\n`);
