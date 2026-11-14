import { strict as assert } from 'node:assert';
import { test, type TestContext } from 'node:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createBuyerFromEnv } from '../src/runtime.ts';
import { FakeNear, CONTRACT } from '../../signer/test/fake-near.ts';

async function runtime(t: TestContext, settings: NodeJS.ProcessEnv) {
  const near = new FakeNear();
  const dir = mkdtempSync(join(tmpdir(), 'nearh-a2-runtime-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  let baseCalls = 0;
  let revokes = 0;
  t.mock.method(globalThis, 'fetch', async (input: string | URL | Request, init?: RequestInit) => {
    const url = input instanceof Request ? input.url : String(input);
    if (url !== 'https://rpc.testnet.near.org') { baseCalls++; throw new Error('Base RPC unavailable'); }
    assert.ok(init?.body);
    const message = JSON.parse(String(init.body)) as { method: string; params: Record<string, unknown> };
    let result: unknown;
    if (message.method === 'send_tx') {
      const tx = Buffer.from(String(message.params.signed_tx_base64), 'base64');
      assert.equal(tx.includes(Buffer.from('revoke_self')), true);
      revokes++;
      result = { status: { SuccessValue: Buffer.from(JSON.stringify({ agent: 'agent-1', revoked: true, key_deleted: true })).toString('base64') } };
    } else if (message.method === 'query' && message.params.method_name === 'get_request') {
      result = { result: [...Buffer.from(JSON.stringify({ status: 'signed', rail: 'sepa' }))] };
    } else {
      result = await near.rpc(message.method, message.params);
    }
    return Response.json({ jsonrpc: '2.0', id: 1, result });
  });
  const buyer = await createBuyerFromEnv({ MANDATE_CONTRACT_ID: CONTRACT, AGENT_NEAR_PRIVATE_KEY: near.key.text, MCP_RECEIPT_DIR: dir, BASE_SEPOLIA_RPC: 'https://base.invalid', ...settings });
  assert.equal((await buyer.getReceipt('existing-payment')).status, 'signed');
  const result = await buyer.revoke();
  assert.equal(result.revoked, true);
  assert.equal(result.key_deleted, true);
  assert.equal(revokes, 1);
  assert.equal(baseCalls, 0);
}

for (const settings of [
  {},
  { MCP_SELLER_ORIGINS: 'malformed', M1_URL: 'https://remote.invalid/payouts', M1_AGENT_TOKEN: 'bad' },
  { MCP_SELLER_ORIGINS: 'https://seller.example', M1_AGENT_TOKEN: 'offline-agent-token-12345678901234567890' },
]) {
  test(`NEAR receipt and self-revoke work without payment dependencies (${JSON.stringify(Object.keys(settings))})`, t => runtime(t, settings));
}

test('payment-time ceiling refuses a seller price increase before requesting a signature', async () => {
  const { limitX402Signer } = await import('../src/runtime.ts');
  const { NearX402Signer } = await import('@nearh/agent-signer');
  const near = new FakeNear();
  const signer = await NearX402Signer.connect({ near: near.rpc, key: near.key.key, contractId: CONTRACT });
  let signatures = 0;
  const capped = limitX402Signer(new Proxy(signer, { get(target, property, receiver) {
    if (property === 'signX402') return async () => { signatures++; throw new Error('signing reached'); };
    return Reflect.get(target, property, receiver);
  } }), '10000');
  const shape = { resourceUrl: 'https://seller.example/weather', scheme: 'exact', network: 'eip155:84532',
    asset: '0x036cbd53842c5426634e7929541ec2318f3dcf7e', payTo: '0x1111111111111111111111111111111111111111', amount: '10001', maxTimeoutSeconds: 120 };
  await assert.rejects(capped.signX402(shape), /ERR_LOCAL_AMOUNT_LIMIT/);
  assert.equal(signatures, 0);
  await assert.rejects(capped.signX402({ ...shape, amount: '10000' }), /signing reached/);
  assert.equal(signatures, 1);
});
