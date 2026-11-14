import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createPublicClient, erc20Abi, getAddress, http } from 'viem';
import { baseSepolia } from 'viem/chains';
import { NearX402Signer, httpRpc, parseNearKey, REQUEST_GAS, DEFAULT_TIMEOUT_MS } from '@nearh/agent-signer';
import { assertTestnet, assertTestnetRpc, callAndWait, failureMessage, view } from '@nearh/agent-signer';
import { Buyer, type HeldDecision } from './buyer.ts';
import { verifyHeldDecision } from '@nearh/dashboard/decisions';
import { verifyX402Settlement } from './settlement.ts';
import { ReceiptStore } from './store.ts';

const pkgDir = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const envValue = (env: NodeJS.ProcessEnv, name: string, fallback?: string): string => {
  const value = env[name] || fallback;
  if (!value) throw new Error(`Set ${name}`);
  return value;
};

/** An authenticated local rail endpoint, fixed by the operator rather than tool arguments. */
export function m1Endpoint(raw: string): string {
  const url = new URL(raw);
  if (url.protocol !== 'http:' || !['127.0.0.1', '[::1]'].includes(url.hostname) || url.username || url.password || url.search || url.hash || url.pathname !== '/payouts') {
    throw new Error('M1_URL must be http://127.0.0.1:<port>/payouts (or [::1])');
  }
  return url.href;
}

export async function createBuyerFromEnv(env: NodeJS.ProcessEnv = process.env): Promise<Buyer> {
  const rpcUrl = envValue(env, 'NEAR_RPC', 'https://rpc.testnet.near.org');
  assertTestnetRpc(rpcUrl);
  const contractId = assertTestnet('MANDATE_CONTRACT_ID', envValue(env, 'MANDATE_CONTRACT_ID'));
  const near = httpRpc(rpcUrl);
  const key = parseNearKey(contractId, envValue(env, 'AGENT_NEAR_PRIVATE_KEY'));
  const connectedSigner = await NearX402Signer.connect({ near, key, contractId, expectedAddress: env.AGENT_EVM_ADDRESS || undefined });
  const signer = limitX402Signer(connectedSigner, env.MCP_X402_MAX_UNITS);
  let payoutClient: ReturnType<typeof m1Client> | undefined;
  const sepaClient = () => {
    if (!payoutClient) {
      const endpoint = m1Endpoint(envValue(env, 'M1_URL', 'http://127.0.0.1:8787/payouts'));
      const token = envValue(env, 'M1_AGENT_TOKEN');
      if (!/^[A-Za-z0-9._~+\/=-]{32,256}$/.test(token)) throw new Error('M1_AGENT_TOKEN must be a 32-256 character per-agent service token');
      payoutClient = m1Client(endpoint, token);
    }
    return payoutClient;
  };
  const query = (method: string, args: object) => view<unknown>(near, contractId, method, args);
  const store = new ReceiptStore(resolve(pkgDir, env.MCP_RECEIPT_DIR || '.receipts', contractId, signer.agent));
  const baseClient = async () => {
    const evm = createPublicClient({ chain: baseSepolia, transport: http(envValue(env, 'BASE_SEPOLIA_RPC', 'https://sepolia.base.org'), { timeout: 15_000, retryCount: 0 }) });
    if (await evm.getChainId() !== baseSepolia.id) throw new Error('Base RPC must be on Base Sepolia');
    return evm;
  };
  return new Buyer({
    signer,
    get allowedOrigins() {
      return envValue(env, 'MCP_SELLER_ORIGINS').split(',').map(origin => new URL(origin.trim()).origin);
    },
    secrets: [env.M1_AGENT_TOKEN ?? '', env.AGENT_NEAR_PRIVATE_KEY ?? '', env.NEAR_AI_API_KEY ?? ''],
    store,
    view: query,
    call: async (method, args) => {
      const outcome = await callAndWait(near, key, contractId, method, args, { gas: REQUEST_GAS, deadlineMs: Date.now() + DEFAULT_TIMEOUT_MS });
      if (outcome.failure !== undefined) throw new Error(`${method}: ${failureMessage(outcome.failure)} (tx ${outcome.hash})`);
      if (outcome.successValue === undefined) throw new Error(`${method}: no final result (tx ${outcome.hash})`);
      return { hash: outcome.hash, value: JSON.parse(Buffer.from(outcome.successValue, 'base64').toString()) as unknown };
    },
    balance: async rail => {
      // Payment dependencies must never block NEAR-only revoke or receipt access.
      if (rail === 'sepa') sepaClient();
      const evm = await baseClient();
      const record = await query('get_agent', { agent: signer.agent }) as { sweep_config: { usdc_address: string; eure_address: string } } | null;
      if (!record) throw new Error('Agent record not found');
      const tokenAddress = rail === 'x402' ? record.sweep_config.usdc_address : record.sweep_config.eure_address;
      return evm.readContract({ address: getAddress(tokenAddress), abi: erc20Abi, functionName: 'balanceOf', args: [signer.address] });
    },
    submit: input => sepaClient()(input),
    notifyOwner: message => { process.stderr.write(`${message}\n`); },
    verifyDecision: item => verifyOwnerDecision(query, contractId, store, item),
    verifySettlement: async (receipt, hash) => {
      const evm = await baseClient();
      const record = await query('get_agent', { agent: signer.agent }) as { sweep_config: { usdc_address: string } } | null;
      if (!record) return false;
      return verifyX402Settlement(evm, receipt, hash, signer.address, record.sweep_config.usdc_address);
    },
  });
}

/** Calls the configured service once; a timeout never triggers another POST. */
export function m1Client(endpoint: string, token: string, fetcher: typeof fetch = fetch) {
  const url = m1Endpoint(endpoint);
  return async (input: import('./buyer.ts').PayoutInput): Promise<Record<string, unknown>> => {
    const response = await fetcher(url, {
      method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
      body: JSON.stringify(input), signal: AbortSignal.timeout(45_000), redirect: 'error',
    });
    if (!response.ok) throw new Error(`M1 returned HTTP ${response.status}; inspect its private order log before retrying`);
    const result: unknown = await response.json();
    if (!result || typeof result !== 'object' || Array.isArray(result)) throw new Error('Invalid M1 response');
    return result as Record<string, unknown>;
  };
}

/** Recheck the passkey proof stored by the dashboard; a writable queue is not approval authority. */
export async function verifyOwnerDecision(query: (method: string, args: object) => Promise<unknown>, contractId: string, store: ReceiptStore, item: HeldDecision): Promise<void> {
  if (item.status !== 'approved' && item.status !== 'rejected') throw new Error('Invalid owner decision');
  if (!item.assertion || !Number.isSafeInteger(item.decided_nonce) || item.decided_nonce !== item.assertion.owner_nonce) throw new Error('Missing or inconsistent owner assertion/nonce');
  const timestamp = Date.parse(item.decided_at ?? '');
  if (!Number.isFinite(timestamp) || timestamp > Date.now() + 60_000) throw new Error('Invalid decision timestamp');
  const minNonce = store.all().reduce((max, receipt) => Math.max(max, receipt.decision_nonce ?? 0), 0);
  const config = await query('get_config', {});
  await verifyHeldDecision({ config, contractId, id: item.id, status: item.status, assertion: item.assertion, minNonce, nowSecs: Math.floor(Date.now() / 1000) });
}

/** Enforce the operator's amount ceiling on the freshly fetched offer before NEAR signing. */
export function limitX402Signer(signer: NearX402Signer, limit: string | undefined): NearX402Signer {
  if (limit === undefined) return signer;
  if (!/^[1-9][0-9]{0,38}$/.test(limit)) throw new Error('MCP_X402_MAX_UNITS must be positive base units');
  const maximum = BigInt(limit);
  return new Proxy(signer, { get(target, property, receiver) {
    if (property !== 'signX402') return Reflect.get(target, property, receiver);
    return async (shape: import('@nearh/agent-signer').X402Shape, id?: string) => {
      if (!/^[0-9]+$/.test(shape.amount) || BigInt(shape.amount) > maximum) throw new Error('ERR_LOCAL_AMOUNT_LIMIT: payment exceeds operator ceiling');
      return target.signX402(shape, id);
    };
  } });
}
