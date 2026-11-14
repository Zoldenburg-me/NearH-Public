import { parseNearKey, view, type Rpc } from '@nearh/agent-signer';
import { base58Encode } from '@nearh/owner-near/src/base58.ts';
import { ibanCommitment, eurToBaseUnits } from '@nearh/owner-near/src/supplier.ts';
import { m1Endpoint } from '@nearh/agent-mcp/src/runtime.ts';

export type Check = { name: string; status: 'pass' | 'fail' | 'skipped'; detail: string };
export type Ports = { near: Rpc; base: Rpc; fetch: typeof fetch };
type RecordValue = Record<string, unknown>;
const record = (value: unknown): RecordValue => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Expected object');
  return value as RecordValue;
};
const address = (value: unknown): string => {
  if (typeof value !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(value) || /^0x0{40}$/.test(value)) throw new Error('Invalid address');
  return value.toLowerCase();
};
const units = (value: unknown): bigint => {
  if (typeof value !== 'string' || !/^[0-9]{1,39}$/.test(value)) throw new Error('Invalid units');
  return BigInt(value);
};
const required = (env: NodeJS.ProcessEnv, name: string): string => {
  const value = env[name];
  if (!value) throw new Error(`Set ${name}`);
  return value;
};
export function endpoint(value: string, loopbackOnly = false): string {
  const url = new URL(value);
  const loopback = ['127.0.0.1', '[::1]', 'localhost'].includes(url.hostname);
  if (url.username || url.password || url.hash || url.search || (loopbackOnly && !loopback) ||
      (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback))) throw new Error('Unsafe endpoint');
  return url.href;
}

/** Only read methods can leave this transport, even if a caller accidentally requests a write. */
export function readRpc(url: string, chain: 'near' | 'base', fetcher: typeof fetch = fetch): Rpc {
  const safeUrl = endpoint(url);
  return async (method, params) => {
    const allowed = chain === 'near' ? ['status', 'query', 'tx', 'block'] : ['eth_chainId', 'eth_call', 'eth_getCode'];
    if (!allowed.includes(method)) throw new Error('Preflight refuses a write RPC');
    if (chain === 'near' && method === 'query') {
      const query = record(params);
      if (!['call_function', 'view_access_key'].includes(String(query.request_type))) throw new Error('Unsupported query');
    }
    const response = await fetcher(safeUrl, {
      method: 'POST', redirect: 'error', signal: AbortSignal.timeout(15_000),
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
    });
    if (!response.ok) throw new Error('RPC HTTP failure');
    const body = record(await response.json());
    if (body.error || !('result' in body)) throw new Error('RPC failure');
    return body.result;
  };
}

/** Collect independent prerequisites without reflecting remote errors or private configuration. */
export async function preflight(env: NodeJS.ProcessEnv, ports: Ports, options: { ownerTopup?: boolean } = {}): Promise<Check[]> {
  const checks: Check[] = [];
  async function check(name: string, detail: string, action: () => Promise<void> | void): Promise<void> {
    try {
      await action();
      checks.push({ name, status: 'pass', detail: 'Verified read-only' });
    } catch {
      checks.push({ name, status: 'fail', detail });
    }
  }
  let contract = '';
  let agent = '';
  let identityValid = false;
  await check('identity configuration', 'Set MANDATE_CONTRACT_ID (.testnet) and AGENT_ID; resolve any conflicting CONTRACT_ID.', () => {
    contract = required(env, 'MANDATE_CONTRACT_ID');
    agent = required(env, 'AGENT_ID');
    if (!/^[a-z0-9._-]+\.testnet$/.test(contract) || !/^[A-Za-z0-9._:-]{1,64}$/.test(agent) ||
      (env.CONTRACT_ID && env.CONTRACT_ID !== contract)) throw new Error('Identity mismatch');
    identityValid = true;
  });
  await check('NEAR network', 'NEAR_RPC must report testnet.', async () => {
    if (record(await ports.near('status', [])).chain_id !== 'testnet') throw new Error('Wrong network');
  });
  await check('Base network', 'BASE_SEPOLIA_RPC must report chain 84532.', async () => {
    if (await ports.base('eth_chainId', []) !== '0x14a34') throw new Error('Wrong network');
  });
  const query = (method: string, args: object = {}) => {
    if (!identityValid) throw new Error('Configure identity before contract queries');
    return view<unknown>(ports.near, contract, method, args);
  };
  let configuration: RecordValue = {};
  await check('contract interfaces', 'Use a testnet contract with supplier cooling-off interfaces and a passkey owner.', async () => {
    configuration = record(await query('get_config'));
    if (configuration.network !== 'testnet' || !Number.isSafeInteger(configuration.bank_change_cooling_off_secs) ||
        record(configuration.owner).mode !== 'passkey') throw new Error('Incompatible deployment');
  });
  let agentRecord: RecordValue = {};
  let sweep: RecordValue = {};
  await check('agent and Safe', 'Match AGENT_EVM_ADDRESS and SAFE_ADDRESS to the active agent sweep configuration on Base Sepolia.', async () => {
    agentRecord = record(await query('get_agent', { agent }));
    sweep = record(agentRecord.sweep_config);
    if (agentRecord.revoked !== false || sweep.chain_id !== 84532 ||
        address(agentRecord.evm_address) !== address(env.AGENT_EVM_ADDRESS) ||
        address(sweep.safe_address) !== address(env.SAFE_ADDRESS)) throw new Error('Agent mismatch');
    const code = await ports.base('eth_getCode', [address(sweep.safe_address), 'latest']);
    if (typeof code !== 'string' || !/^0x[0-9a-fA-F]+$/.test(code) || code === '0x0') throw new Error('Safe not deployed');
  });
  await check('agent access key', 'Supply the registered agent function-call key with request_signature permission and nonzero allowance.', async () => {
    const key = parseNearKey(contract, required(env, 'AGENT_NEAR_PRIVATE_KEY'));
    const publicKey = `ed25519:${base58Encode(key.publicKey)}`;
    if (await query('agent_of_key', { public_key: publicKey }) !== agent) throw new Error('Wrong key');
    const access = record(await ports.near('query', {
      request_type: 'view_access_key', account_id: contract, public_key: publicKey, finality: 'final',
    }));
    const permission = record(record(access.permission).FunctionCall);
    if (permission.receiver_id !== contract || !Array.isArray(permission.method_names) ||
        !permission.method_names.includes('request_signature') ||
        (permission.allowance !== null && units(permission.allowance) === 0n)) throw new Error('Unusable key');
  });
  let mandate: RecordValue = {};
  await check('mandate', 'Configure a mandate with matching chain, tokens and a usable validity window.', async () => {
    mandate = record(await query('get_mandate', { agent }));
    if (mandate.chain_id !== 84532 || address(mandate.usdc_address) !== address(sweep.usdc_address) ||
        address(mandate.eure_address) !== address(sweep.eure_address) ||
        typeof mandate.max_validity_secs !== 'number' || mandate.max_validity_secs < 45) throw new Error('Wrong mandate');
  });
  let payees: RecordValue[] = [];
  await check('payee interfaces', 'The deployed get_payees and get_suppliers views must be available.', async () => {
    const values = await query('get_payees', { agent });
    if (!Array.isArray(values) || !Array.isArray(await query('get_suppliers', { agent }))) throw new Error('Missing interfaces');
    payees = values.map(record);
  });
  let x402Amount = 0n;
  await check('seller requirements', 'Set E1_SELLER_URL to an allowed SE1 resource returning exact Base Sepolia USDC requirements within E1_X402_MAX_UNITS.', async () => {
    const url = endpoint(required(env, 'E1_SELLER_URL'));
    const origins = required(env, 'MCP_SELLER_ORIGINS').split(',').map(value => new URL(value.trim()).origin);
    if (!origins.includes(new URL(url).origin)) throw new Error('Origin not allowed');
    const response = await ports.fetch(url, { redirect: 'error', signal: AbortSignal.timeout(15_000) });
    if (response.status !== 402) throw new Error('Expected payment required');
    const header = response.headers.get('payment-required');
    if (!header || header.length > 32_000) throw new Error('Missing requirements');
    const body = record(JSON.parse(Buffer.from(header, 'base64').toString()));
    if (body.x402Version !== 2 || !Array.isArray(body.accepts)) throw new Error('Wrong protocol');
    const offer = body.accepts.map(record).find(item => item.scheme === 'exact' && item.network === 'eip155:84532');
    if (!offer || address(offer.asset) !== address(mandate.usdc_address) ||
        !payees.some(item => item.rail === 'x402' && address(item.pay_to) === address(offer.payTo))) throw new Error('Unapproved offer');
    const extra = record(offer.extra);
    if ((extra.assetTransferMethod ?? 'eip3009') !== 'eip3009' || extra.name !== 'USDC' || extra.version !== '2') throw new Error('Unsupported payment domain');
    x402Amount = units(offer.amount);
    if (x402Amount === 0n || x402Amount > units(required(env, 'E1_X402_MAX_UNITS')) ||
        typeof offer.maxTimeoutSeconds !== 'number' || offer.maxTimeoutSeconds < 45) throw new Error('Offer limits');
  });
  let sepaAmount = 0n;
  await check('supplier and invoice', 'Set E1_SUPPLIER, E1_IBAN, E1_IBAN_SALT, E1_SEPA_AMOUNT and a fresh E1_INVOICE_ID; supplier commitment must be payable after cooling-off.', async () => {
    const supplier = required(env, 'E1_SUPPLIER');
    const invoice = required(env, 'E1_INVOICE_ID');
    if (![supplier, invoice].every(value => /^[A-Za-z0-9._:-]{1,64}$/.test(value))) throw new Error('Invalid identifier');
    const amount = required(env, 'E1_SEPA_AMOUNT');
    if (!/^[0-9]+(\.[0-9]{1,2})?$/.test(amount)) throw new Error('Invalid cents');
    sepaAmount = BigInt(eurToBaseUnits(amount));
    const commitment = ibanCommitment(required(env, 'E1_IBAN'), required(env, 'E1_IBAN_SALT'));
    const entry = payees.find(item => item.rail === 'sepa' && item.supplier === supplier && item.iban_commitment === commitment);
    if (!entry || units(entry.cap) < sepaAmount || await query('is_invoice_paid', { supplier, invoice_id: invoice }) !== false) throw new Error('Supplier unavailable');
  });
  for (const [rail, token, amount] of [['x402', 'usdc', x402Amount], ['sepa', 'eure', sepaAmount]] as const) {
    await check(`${rail} budget and float`, options.ownerTopup ? `Set E1_TOPUP_${token.toUpperCase()}_UNITS within the Safe balance and float cap, sufficient for the ${rail} purchase.` : `Provide sufficient ${token.toUpperCase()} float and ${rail} mandate cap/budget for the configured purchase.`, async () => {
      if (amount === 0n) throw new Error('Amount not verified');
      const range = record(record(mandate[rail]).amount_range);
      const budget = record(await query('get_budget', { agent, rail }));
      if (amount < units(range.min) || amount > units(range.max) || amount > units(budget.budget) - units(budget.reserved)) throw new Error('Budget insufficient');
      const balance = async (holder: unknown): Promise<bigint> => {
        const result: unknown = await ports.base('eth_call', [{ to: address(sweep[`${token}_address`]),
          data: `0x70a08231${address(holder).slice(2).padStart(64, '0')}` }, 'latest']);
        if (typeof result !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(result)) throw new Error('Invalid balance');
        return BigInt(result);
      };
      const current = await balance(agentRecord.evm_address);
      if (options.ownerTopup) {
        const topup = units(required(env, `E1_TOPUP_${token.toUpperCase()}_UNITS`));
        if (topup === 0n || await balance(sweep.safe_address) < topup || current + topup < amount ||
          current + topup > units(record(mandate.float_cap)[token])) throw new Error('Top-up cannot fund the demo within the float cap');
      } else if (current < amount) throw new Error('Float insufficient');
    });
  }
  await check('dashboard reachable', 'Set E1_DASHBOARD_URL to the running owner dashboard.', async () => {
    const response = await ports.fetch(endpoint(required(env, 'E1_DASHBOARD_URL'), true), { redirect: 'error', signal: AbortSignal.timeout(15_000) });
    if (!response.ok) throw new Error('Dashboard unavailable');
  });
  await check('M1 reachable', 'Set M1_URL to the loopback M1 /payouts endpoint; GET must return its documented 404 response.', async () => {
    const url = m1Endpoint(required(env, 'M1_URL'));
    const response = await ports.fetch(url, { method: 'GET', redirect: 'error', signal: AbortSignal.timeout(15_000) });
    if (response.status !== 404 || record(await response.json()).error !== 'POST /payouts only') throw new Error('M1 unavailable');
  });
  await check('M1 token format', 'Supply M1_AGENT_TOKEN; Monerium credentials belong only in the M1 process.', () => {
    if (!/^[A-Za-z0-9._~+\/=-]{32,256}$/.test(required(env, 'M1_AGENT_TOKEN'))) throw new Error('Invalid token');
  });
  await check('M1 runtime authentication', 'Run the updated M1 service with a matching per-agent token, contract, EVM address and sandbox network binding.', async () => {
    const url = new URL(m1Endpoint(required(env, 'M1_URL')));
    url.pathname = `/health/${agent}`;
    const response = await ports.fetch(url, { method: 'GET', redirect: 'error', signal: AbortSignal.timeout(15_000),
      headers: { authorization: `Bearer ${required(env, 'M1_AGENT_TOKEN')}` } });
    if (!response.ok) throw new Error('M1 authentication unavailable');
    const health = record(await response.json());
    if (health.contract_id !== contract || health.agent !== agent || health.network !== 'testnet' ||
        health.chain_id !== 84532 || health.monerium !== 'sandbox' ||
        address(health.evm_address) !== address(env.AGENT_EVM_ADDRESS)) throw new Error('M1 binding mismatch');
  });
  checks.push({ name: 'scam check', status: env.NEAR_AI_API_KEY ? 'pass' : 'skipped', detail: env.NEAR_AI_API_KEY ? 'Key configured; inference and held behavior are not yet verified.' : 'NEAR_AI_API_KEY absent: AI demonstration skipped; contract rejection remains required.' });
  return checks;
}

export function report(checks: Check[]): string {
  return JSON.stringify({ mode: 'read-only preflight', payment_submissions: 0,
    ready: checks.every(check => check.status !== 'fail'), checks }, null, 2);
}
