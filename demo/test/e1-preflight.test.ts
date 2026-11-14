import test from 'node:test';
import assert from 'node:assert/strict';
import { endpoint, preflight, readRpc, report, type Ports } from '../src/e1-preflight.ts';

const neverFetch: typeof fetch = async () => { throw new Error('secret upstream diagnostic'); };

test('missing configuration lists independent failures without leaking upstream diagnostics', async () => {
  const ports: Ports = { near: async () => { throw new Error('private-key-content'); },
    base: async () => { throw new Error('private-service-token'); }, fetch: neverFetch };
  const checks = await preflight({}, ports);
  for (const name of ['identity configuration', 'agent access key', 'mandate', 'supplier and invoice', 'seller requirements', 'M1 token format']) {
    assert.equal(checks.find(check => check.name === name)?.status, 'fail', name);
  }
  assert.equal(checks.find(check => check.name === 'scam check')?.status, 'skipped');
  const output = report(checks);
  assert.equal(JSON.parse(output).ready, false);
  assert.equal(JSON.parse(output).payment_submissions, 0);
  assert.doesNotMatch(output, /private-key-content|private-service-token|secret upstream diagnostic/);
});

test('read transport refuses submission before making a network request', async () => {
  let calls = 0;
  const fetcher: typeof fetch = async () => { calls++; return Response.json({ result: null }); };
  for (const [chain, method] of [['near', 'broadcast_tx_commit'], ['near', 'send_tx'], ['base', 'eth_sendRawTransaction']] as const) {
    await assert.rejects(readRpc('https://example.org', chain, fetcher)(method, {}), /refuses a write/);
  }
  await assert.rejects(readRpc('https://example.org', 'near', fetcher)('query', { request_type: 'unexpected' }), /Unsupported query/);
  assert.equal(calls, 0);
});

test('read transport bounds network requests and refuses RPC errors', async () => {
  const fetcher: typeof fetch = async (url, options) => {
    assert.equal(url, 'https://example.org/');
    assert.equal(options?.redirect, 'error');
    assert.ok(options?.signal);
    assert.equal(JSON.parse(String(options?.body)).method, 'eth_chainId');
    return Response.json({ error: { message: 'credential in upstream error' } });
  };
  await assert.rejects(readRpc('https://example.org', 'base', fetcher)('eth_chainId', []), /^Error: RPC failure$/);
});

test('endpoints refuse credential forwarding, redirects configured as URLs and public HTTP', () => {
  for (const value of ['https://user:password@example.org', 'http://example.org', 'https://example.org?key=private', 'file:///tmp/config']) {
    assert.throws(() => endpoint(value));
  }
  assert.throws(() => endpoint('https://example.org', true));
  assert.equal(endpoint('http://127.0.0.1:8787/payouts', true), 'http://127.0.0.1:8787/payouts');
});

test('M1 URL must use literal 127.0.0.1 or [::1], not localhost', async () => {
  const requests: string[] = [];
  const fetcher: typeof fetch = async (url, options) => {
    requests.push(String(url));
    if (String(url).includes('/health/')) return Response.json({ contract_id: 'demo.testnet', agent: 'agent-1', evm_address: `0x${'11'.repeat(20)}`, network: 'testnet', chain_id: 84532, monerium: 'sandbox' });
    return Response.json({ error: 'POST /payouts only' }, { status: 404 });
  };
  const checks = await preflight({ M1_URL: 'http://localhost:8787/payouts', M1_AGENT_TOKEN: 'a'.repeat(32) }, {
    near: async () => { throw new Error('offline'); }, base: async () => { throw new Error('offline'); }, fetch: fetcher,
  });
  assert.equal(checks.find(check => check.name === 'M1 reachable')?.status, 'fail');
  assert.equal(checks.find(check => check.name === 'M1 runtime authentication')?.status, 'fail');
  assert.deepEqual(requests, []);
});

test('M1 reachability is GET-only and cannot certify runtime authentication', async () => {
  const requests: string[] = [];
  const fetcher: typeof fetch = async (url, options) => {
    requests.push(String(url));
    assert.equal(options?.method, 'GET');
    if (String(url).includes('/health/')) assert.ok(options?.headers);
    else assert.equal(options?.headers, undefined);
    return Response.json({ error: 'POST /payouts only' }, { status: 404 });
  };
  const checks = await preflight({ M1_URL: 'http://127.0.0.1:8787/payouts', M1_AGENT_TOKEN: 'a'.repeat(32) }, {
    near: async () => { throw new Error('offline'); }, base: async () => { throw new Error('offline'); }, fetch: fetcher,
  });
  assert.deepEqual(requests, ['http://127.0.0.1:8787/payouts', 'http://127.0.0.1:8787/health/']);
  assert.equal(checks.find(check => check.name === 'M1 reachable')?.status, 'pass');
  assert.equal(checks.find(check => check.name === 'M1 token format')?.status, 'pass');
  assert.equal(checks.find(check => check.name === 'M1 runtime authentication')?.status, 'fail');
  assert.equal(JSON.parse(report(checks)).ready, false);
});

import { generateKeyPairSync } from 'node:crypto';
import { base58Encode } from '@nearh/owner-near/src/base58.ts';
import { ibanCommitment } from '@nearh/owner-near/src/supplier.ts';

function fixture(overrides: Record<string, unknown> = {}, extra: Record<string, unknown> = { name: 'USDC', version: '2' }) {
  const keys = generateKeyPairSync('ed25519');
  const jwk = keys.privateKey.export({ format: 'jwk' });
  assert.ok(jwk.d);
  assert.ok(jwk.x);
  const key = `ed25519:${base58Encode(Buffer.concat([Buffer.from(jwk.d, 'base64url'), Buffer.from(jwk.x, 'base64url')]))}`;
  const eoa = `0x${'11'.repeat(20)}`;
  const safe = `0x${'22'.repeat(20)}`;
  const usdc = `0x${'33'.repeat(20)}`;
  const eure = `0x${'44'.repeat(20)}`;
  const seller = `0x${'55'.repeat(20)}`;
  const iban = 'DE89370400440532013000';
  const salt = `0x${'66'.repeat(32)}`;
  const env = { MANDATE_CONTRACT_ID: 'demo.testnet', AGENT_ID: 'agent-1', AGENT_EVM_ADDRESS: eoa,
    SAFE_ADDRESS: safe, AGENT_NEAR_PRIVATE_KEY: key, E1_SELLER_URL: 'http://127.0.0.1:4021/weather',
    MCP_SELLER_ORIGINS: 'http://127.0.0.1:4021', E1_X402_MAX_UNITS: '10000', E1_SUPPLIER: 'supplier',
    E1_IBAN: iban, E1_IBAN_SALT: salt, E1_SEPA_AMOUNT: '0.01', E1_INVOICE_ID: 'fresh-invoice',
    E1_DASHBOARD_URL: 'http://127.0.0.1:3000', M1_URL: 'http://127.0.0.1:8787/payouts', M1_AGENT_TOKEN: 'b'.repeat(32) };
  const rail = { amount_range: { min: '1', max: '1000000000000000000' } };
  const views: Record<string, unknown> = {
    get_config: { network: 'testnet', owner: { mode: 'passkey' }, bank_change_cooling_off_secs: 60 },
    get_agent: { revoked: false, evm_address: eoa, sweep_config: { safe_address: safe, chain_id: 84532, usdc_address: usdc, eure_address: eure } },
    get_mandate: { chain_id: 84532, usdc_address: usdc, eure_address: eure, max_validity_secs: 240, x402: rail, sepa: rail },
    get_payees: [{ rail: 'x402', pay_to: seller }, { rail: 'sepa', supplier: 'supplier', iban_commitment: ibanCommitment(iban, salt), cap: '1000000000000000000' }],
    get_suppliers: [], agent_of_key: 'agent-1', is_invoice_paid: false,
    get_budget: { budget: '1000000000000000000', reserved: '0' }, ...overrides,
  };
  const ports: Ports = {
    near: async (method, raw) => {
      if (method === 'status') return { chain_id: 'testnet' };
      assert.equal(method, 'query');
      const params = raw as Record<string, string>;
      if (params.request_type === 'view_access_key') return { permission: { FunctionCall: { receiver_id: 'demo.testnet', method_names: ['request_signature'], allowance: '10000000000' } } };
      assert.ok(params.method_name in views);
      return { result: [...Buffer.from(JSON.stringify(views[params.method_name]))] };
    },
    base: async method => {
      if (method === 'eth_chainId') return '0x14a34';
      if (method === 'eth_getCode') return '0x1234';
      assert.equal(method, 'eth_call');
      return `0x${(10n ** 18n).toString(16).padStart(64, '0')}`;
    },
    fetch: async url => {
      if (String(url).includes('/health/')) return Response.json({ contract_id: 'demo.testnet', agent: 'agent-1', evm_address: eoa, network: 'testnet', chain_id: 84532, monerium: 'sandbox' });
      if (String(url).includes('/payouts')) return Response.json({ error: 'POST /payouts only' }, { status: 404 });
      if (String(url).includes('/weather')) return new Response(null, { status: 402, headers: { 'payment-required': Buffer.from(JSON.stringify({ x402Version: 2, accepts: [
        { scheme: 'exact', network: 'eip155:84532', asset: usdc, payTo: seller, amount: '10000', maxTimeoutSeconds: 240, extra },
      ] })).toString('base64') } });
      return new Response('dashboard');
    },
  };
  return { env, ports };
}

test('consistent deployment and authenticated service binding pass preflight', async () => {
  const { env, ports } = fixture();
  const checks = await preflight(env, ports);
  assert.deepEqual(checks.filter(check => check.status === 'fail').map(check => check.name), []);
  const output = report(checks);
  for (const secret of [env.AGENT_NEAR_PRIVATE_KEY, env.E1_IBAN, env.E1_IBAN_SALT, env.M1_AGENT_TOKEN]) assert.ok(!output.includes(secret));
});

test('cooling-off supplier and previously used invoice each stop the SEPA path', async () => {
  for (const overrides of [{ get_payees: [] }, { is_invoice_paid: true }]) {
    const { env, ports } = fixture(overrides);
    const checks = await preflight(env, ports);
    assert.equal(checks.find(check => check.name === 'supplier and invoice')?.status, 'fail');
  }
});

test('reserved budget is deducted and the wrong Safe is rejected', async () => {
  const { env, ports } = fixture({ get_budget: { budget: '10000', reserved: '1' } });
  const checks = await preflight({ ...env, SAFE_ADDRESS: `0x${'77'.repeat(20)}` }, ports);
  assert.equal(checks.find(check => check.name === 'agent and Safe')?.status, 'fail');
  assert.equal(checks.find(check => check.name === 'x402 budget and float')?.status, 'fail');
});


test('seller domains and transfer methods must match the reused signer', async () => {
  for (const extra of [{}, { name: 'USDC', version: '1' }, { name: 'Other', version: '2' },
    { name: 'USDC', version: '2', assetTransferMethod: 'permit2' }]) {
    const { env, ports } = fixture({}, extra);
    const checks = await preflight(env, ports);
    assert.equal(checks.find(check => check.name === 'seller requirements')?.status, 'fail');
  }
});

test('missing identity never issues contract queries', async () => {
  const calls: string[] = [];
  const checks = await preflight({}, { near: async method => { calls.push(method); return { chain_id: 'testnet' }; },
    base: async () => '0x14a34', fetch: neverFetch });
  assert.deepEqual(calls, ['status']);
  assert.equal(checks.find(check => check.name === 'identity configuration')?.status, 'fail');
});

test('full-run preflight permits empty float only when the Safe can fund it within the cap', async () => {
  const { env, ports } = fixture();
  const near = ports.near;
  ports.near = async (method, raw) => {
    const result = await near(method, raw);
    if (method === 'query' && (raw as { method_name?: string }).method_name === 'get_mandate') {
      const mandate = JSON.parse(Buffer.from(result.result).toString());
      return { result: [...Buffer.from(JSON.stringify({ ...mandate, float_cap: { usdc: '20000', eure: '20000000000000000' } }))] };
    }
    return result;
  };
  const base = ports.base;
  let safeFunded = true;
  ports.base = async (method, raw) => {
    if (method !== 'eth_call') return base(method, raw);
    const call = (raw as [{ data: string }])[0];
    const isSafe = call.data.endsWith(env.SAFE_ADDRESS.slice(2));
    return `0x${(isSafe && safeFunded ? 10n ** 18n : 0n).toString(16).padStart(64, '0')}`;
  };
  const configuration = { ...env, E1_TOPUP_USDC_UNITS: '10000', E1_TOPUP_EURE_UNITS: '10000000000000000' };
  const first = await preflight(configuration, ports, { ownerTopup: true });
  assert.equal(first.find(check => check.name === 'x402 budget and float')?.status, 'pass');
  assert.equal(first.find(check => check.name === 'sepa budget and float')?.status, 'pass');
  const notFunded = await preflight(configuration, ports);
  assert.equal(notFunded.find(check => check.name === 'x402 budget and float')?.status, 'fail');
  safeFunded = false;
  const broke = await preflight(configuration, ports, { ownerTopup: true });
  assert.equal(broke.find(check => check.name === 'x402 budget and float')?.status, 'fail');
  safeFunded = true;
  const overCap = await preflight({ ...configuration, E1_TOPUP_USDC_UNITS: '20001' }, ports, { ownerTopup: true });
  assert.equal(overCap.find(check => check.name === 'x402 budget and float')?.status, 'fail');
});
