import { strict as assert } from 'node:assert';
import { test, type TestContext } from 'node:test';
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { AddressInfo } from 'node:net';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import type { Buyer } from '../src/buyer.ts';
import { createServer } from '../src/server.ts';
import { authorized, MAX_BODY_BYTES, readToken, serveHttp } from '../src/http.ts';

const TOKEN = 'a'.repeat(20) + 'b'.repeat(24);
const buyer = { redact: (text: string) => text } as unknown as Buyer;
const list = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} });
const accept = 'application/json, text/event-stream';

async function start(t: TestContext, use = buyer, timeoutMs?: number): Promise<string> {
  const http = await serveHttp(() => createServer(use), TOKEN, 0, undefined, timeoutMs);
  t.after(() => new Promise<void>(done => { http.closeAllConnections(); http.close(() => done()); }));
  return `http://127.0.0.1:${(http.address() as AddressInfo).port}`;
}

test('binds to loopback only', async t => {
  const base = await start(t);
  assert.match(base, /^http:\/\/127\.0\.0\.1:\d+$/);
});

test('missing, wrong or malformed bearer token gets 401 and no CORS headers', async t => {
  const base = await start(t);
  const cases: Record<string, string>[] = [
    {},
    { authorization: `Bearer ${TOKEN}x` },
    { authorization: `Bearer ${TOKEN.slice(0, -1)}` },
    { authorization: TOKEN },
    { authorization: `Basic ${TOKEN}` },
    { authorization: 'Bearer ' },
  ];
  for (const headers of cases) {
    const response = await fetch(`${base}/mcp`, { method: 'POST', headers: { 'content-type': 'application/json', accept, origin: 'https://evil.example', ...headers }, body: list });
    assert.equal(response.status, 401, JSON.stringify(Object.keys(headers)));
    assert.equal(response.headers.get('access-control-allow-origin'), null);
    assert.doesNotMatch(await response.text(), /pay_x402/);
  }
  for (const [method, path] of [['OPTIONS', '/mcp'], ['GET', '/mcp'], ['DELETE', '/mcp'], ['POST', '/other']]) {
    const response = await fetch(`${base}${path}`, { method, headers: { origin: 'https://evil.example' } });
    assert.equal(response.status, 401, `${method} ${path}`);
    assert.equal(response.headers.get('access-control-allow-origin'), null);
  }
});

test('tools/list works with the token over the SDK client', async t => {
  const base = await start(t);
  const client = new Client({ name: 'test', version: '1.0.0' });
  await client.connect(new StreamableHTTPClientTransport(new URL(`${base}/mcp`), { requestInit: { headers: { authorization: `Bearer ${TOKEN}` } } }));
  t.after(() => client.close());
  const { tools } = await client.listTools();
  assert.deepEqual(tools.map(tool => tool.name).sort(), ['get_receipt', 'pay_sepa', 'pay_x402', 'revoke']);
});

test('the SDK client without the token is refused', async t => {
  const base = await start(t);
  const client = new Client({ name: 'test', version: '1.0.0' });
  await assert.rejects(client.connect(new StreamableHTTPClientTransport(new URL(`${base}/mcp`))), /401|Unauthorized/);
});

test('with the token: oversized body 413, bad JSON 400, GET 405, other path 404', async t => {
  const base = await start(t);
  const headers = { authorization: `Bearer ${TOKEN}`, 'content-type': 'application/json', accept };
  assert.equal((await fetch(`${base}/mcp`, { method: 'POST', headers, body: 'x'.repeat(MAX_BODY_BYTES + 1) })).status, 413);
  assert.equal((await fetch(`${base}/mcp`, { method: 'POST', headers, body: '{' })).status, 400);
  assert.equal((await fetch(`${base}/mcp`, { method: 'GET', headers })).status, 405);
  assert.equal((await fetch(`${base}/other`, { method: 'POST', headers, body: list })).status, 404);
});

const payer = (delayMs: number) => ({
  redact: (text: string) => text,
  payX402: async () => { await new Promise(done => setTimeout(done, delayMs)); return { status: 'paid', request_id: 'pay-test' }; },
}) as unknown as Buyer;

test('a tool call slower than the request timeout still returns its request_id', async t => {
  const base = await start(t, payer(300), 50);
  const client = new Client({ name: 'test', version: '1.0.0' });
  await client.connect(new StreamableHTTPClientTransport(new URL(`${base}/mcp`), { requestInit: { headers: { authorization: `Bearer ${TOKEN}` } } }));
  t.after(() => client.close());
  const result = await client.callTool({ name: 'pay_x402', arguments: { url: 'https://seller.example/r', reason: 'test' } });
  assert.equal((result.structuredContent as { request_id: string }).request_id, 'pay-test');
});

test('a revoke slower than the request timeout still returns its tx_hash', async t => {
  const revoker = {
    redact: (text: string) => text,
    revoke: async () => { await new Promise(done => setTimeout(done, 300)); return { revoked: true, key_deleted: true, tx_hash: 'tx-test' }; },
  } as unknown as Buyer;
  const base = await start(t, revoker, 50);
  const client = new Client({ name: 'test', version: '1.0.0' });
  await client.connect(new StreamableHTTPClientTransport(new URL(`${base}/mcp`), { requestInit: { headers: { authorization: `Bearer ${TOKEN}` } } }));
  t.after(() => client.close());
  const result = await client.callTool({ name: 'revoke', arguments: {} });
  assert.equal((result.structuredContent as { tx_hash: string }).tx_hash, 'tx-test');
});

test('a stalled non-payment tool call ends its open stream with a JSON-RPC error', async t => {
  const stalled = { redact: (text: string) => text, getReceipt: () => new Promise(() => {}) } as unknown as Buyer;
  const base = await start(t, stalled, 50);
  const client = new Client({ name: 'test', version: '1.0.0' });
  await client.connect(new StreamableHTTPClientTransport(new URL(`${base}/mcp`), { requestInit: { headers: { authorization: `Bearer ${TOKEN}` } } }));
  t.after(() => client.close());
  await assert.rejects(client.callTool({ name: 'get_receipt', arguments: { request_id: 'pay-test' } }), /timed out/);
});

test('the largest valid pay_x402 call fits the body limit', async t => {
  const base = await start(t, payer(0));
  // \u0001 is JSON-escaped to 6 bytes, the worst case per character.
  const args = { url: `https://seller.example/${'p'.repeat(2000)}`, method: 'POST', body: '\u0001'.repeat(64_000), reason: '\u0001'.repeat(16_000) };
  const call = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'pay_x402', arguments: args } });
  assert.ok(Buffer.byteLength(call) > 480_000 && Buffer.byteLength(call) <= MAX_BODY_BYTES);
  const response = await fetch(`${base}/mcp`, { method: 'POST', headers: { authorization: `Bearer ${TOKEN}`, 'content-type': 'application/json', accept }, body: call });
  assert.equal(response.status, 200);
  assert.match(await response.text(), /pay-test/);
});

test('authorized is exact', () => {
  assert.equal(authorized(`Bearer ${TOKEN}`, TOKEN), true);
  assert.equal(authorized(undefined, TOKEN), false);
  assert.equal(authorized(`bearer ${TOKEN}`, TOKEN), false);
  assert.equal(authorized(`Bearer ${TOKEN} `, TOKEN), false);
});

test('token file must be private and long enough', t => {
  const dir = mkdtempSync(join(tmpdir(), 'nearh-http-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const file = join(dir, 'token');
  writeFileSync(file, `${TOKEN}\n`, { mode: 0o600 });
  assert.equal(readToken(file), TOKEN);
  chmodSync(file, 0o644);
  assert.throws(() => readToken(file), /mode 600/);
  writeFileSync(file, 'short', { mode: 0o600 });
  chmodSync(file, 0o600);
  assert.throws(() => readToken(file), /32-256/);
});
