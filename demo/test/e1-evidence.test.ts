import test from 'node:test';
import assert from 'node:assert/strict';
import { evidence, resourceDigest, assertSigned } from '../src/e1-evidence.ts';
import { agentEnvironment, demoAgentEnvironment } from '../src/e1-mcp.ts';
import { pendingDemo, pendingAtFailure } from '../src/e1-run.ts';

test('agent process receives only agent configuration, never owner or rail credentials', () => {
  assert.deepEqual(agentEnvironment({ AGENT_NEAR_PRIVATE_KEY: 'agent-key', OWNER_KEY_DIR: '/private/owner',
    MONERIUM_CLIENT_SECRET: 'rail-secret', RELAYER_EVM_PRIVATE_KEY: 'relayer-secret', M1_AGENT_TOKEN: 'agent-token',
    NODE_OPTIONS: '--import=untrusted.js' }), { AGENT_NEAR_PRIVATE_KEY: 'agent-key', M1_AGENT_TOKEN: 'agent-token' });
});

test('evidence projects references only and requires an actual delivered paid resource', () => {
  const entry = evidence('payment', 'submitted', { request_id: 'pay-example', detail: 'private IBAN and tokens',
    response: 'private resource', monerium_order_id: '32298aa0-cbd1-425d-9ba5-012295db6b80' });
  assert.equal('detail' in entry, false);
  assert.equal('response' in entry, false);
  assert.throws(() => evidence('payment', 'submitted', { tx_hash: 'secret' }));
  assert.throws(() => resourceDigest({ outcome: 'pending', response: 'body', resource_status: 200 }));
  assert.throws(() => resourceDigest({ outcome: 'paid', response: '', resource_status: 200 }));
  assert.throws(() => resourceDigest({ outcome: 'paid', response: 'body', resource_status: 503 }));
  assert.match(resourceDigest({ outcome: 'paid', response: 'body', resource_status: 200 }), /^[a-f0-9]{64}$/);
  assert.throws(() => assertSigned({ reservation: { key: { request_id: 'other' }, shape: 'x402', status: 'signed', signature: {} } }, 'wanted', 'x402'));
});

for (const state of ['pending', 'signed']) {
  test(`budget demonstration ${state === 'pending' ? 'accepts observed pending' : 'refuses a completed reservation'}`, async () => {
    const records: string[] = [];
    let sends = 0;
    const action = pendingDemo({
      query: async method => method === 'get_budget' ? { budget: '10', reserved: '0' } : { status: state },
      ownerTx: async (method, prompt) => { assert.equal(method, 'set_mandate'); assert.match(prompt, /10 base units/); },
      direct: async (id, shape, transport) => {
        sends++;
        assert.equal((shape as { amount: string }).amount, '10');
        assert.ok(transport);
        const send = await transport('send_tx', { wait_until: 'FINAL' });
        assert.equal(send, 'included');
        return id.startsWith('budget-') ? { hash: '1'.repeat(44), failure: 'ERR_OVER_BUDGET: rejected' } : { hash: '2'.repeat(44), successValue: '' };
      },
      near: async (method, raw) => {
        if (method === 'tx') return { receipts_outcome: [{ block_hash: 'block', outcome: { executor_id: 'demo.testnet', status: { Failure: 'ERR_OVER_BUDGET' } } }] };
        if (method === 'query') {
          assert.equal((raw as { block_id: string }).block_id, 'block');
          return { result: [...Buffer.from(JSON.stringify({ status: 'pending', key: { request_id: 'pending-fixture' } }))] };
        }
        assert.equal(method, 'send_tx');
        assert.equal((raw as { wait_until: string }).wait_until, 'INCLUDED');
        return 'included';
      },
      contract: 'demo.testnet', agent: 'agent-1', run: 'fixture', x402: { amount: '10' }, add: entry => { records.push(entry.step); },
    });
    if (state === 'pending') {
      await action;
      assert.equal(sends, 2);
      assert.ok(records.includes('budget-rejection'));
    } else {
      await assert.rejects(action, /before pending was observed/);
      assert.equal(sends, 1);
      assert.ok(!records.includes('budget-rejection'));
    }
  });
}


test('failed MCP payments preserve request IDs for each supported local error code', () => {
  for (const error_code of ['LOW_FLOAT', 'PAYMENT_ERROR', 'OWNER_APPROVAL_INVALID', 'ERR_LOCAL_AMOUNT_LIMIT', 'M1_ORDER_EXPIRED', 'MONERIUM_OUTCOME_UNKNOWN']) {
    const result = evidence('x402-request', 'failed', { request_id: 'pay-example', error_code, detail: 'private upstream message' });
    assert.equal(result.request_id, 'pay-example');
    assert.equal(result.error_code, error_code);
    assert.equal('detail' in result, false);
  }
  assert.throws(() => evidence('x402-request', 'failed', { error_code: 'unbounded private error' }));
});

test('pending proof uses the budget refusal execution block, never a stale final view', async () => {
  for (const status of ['pending', 'signed']) {
    const proven = await pendingAtFailure(async (method, raw) => {
      if (method === 'tx') {
        assert.equal((raw as { wait_until: string }).wait_until, 'FINAL');
        return { receipts_outcome: [{ block_hash: 'rejection-block', outcome: { executor_id: 'demo.testnet', status: { Failure: 'ERR_OVER_BUDGET' } } }] };
      }
      assert.equal(method, 'query');
      assert.equal((raw as { block_id: string }).block_id, 'rejection-block');
      assert.equal('finality' in (raw as object), false);
      return { result: [...Buffer.from(JSON.stringify({ status, key: { request_id: 'pending-test' } }))] };
    }, 'demo.testnet', 'agent-1', 'pending-test', 'hash');
    assert.equal(proven, status === 'pending');
  }
});


test('each demo child gets a fresh receipt namespace and an enforced ceiling', () => {
  const env = { MCP_RECEIPT_DIR: '/shared/approved-payments', MCP_X402_MAX_UNITS: '999999', E1_X402_MAX_UNITS: '10000' };
  const first = demoAgentEnvironment('/checkout', '11111111-1111-4111-8111-111111111111', env);
  const second = demoAgentEnvironment('/checkout', '22222222-2222-4222-8222-222222222222', env);
  assert.notEqual(first.MCP_RECEIPT_DIR, second.MCP_RECEIPT_DIR);
  assert.match(first.MCP_RECEIPT_DIR, /^\/checkout\/demo\/\.runs\/[^/]+\/receipts$/);
  assert.notEqual(first.MCP_RECEIPT_DIR, env.MCP_RECEIPT_DIR);
  assert.equal(first.MCP_X402_MAX_UNITS, '10000');
  assert.throws(() => demoAgentEnvironment('/checkout', '../shared', env));
});
