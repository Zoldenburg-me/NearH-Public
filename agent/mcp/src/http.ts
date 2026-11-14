import { createHash, timingSafeEqual } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';
import { createServer as createHttpServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { x402Input } from './policy.ts';

/**
 * Fits the largest valid tool call, pay_x402 with a full body and reason: JSON may escape every
 * character as \uXXXX (6 bytes), plus 32 KiB for the url and the JSON-RPC envelope.
 */
export const MAX_BODY_BYTES = 6 * (x402Input.shape.body.unwrap().maxLength! + x402Input.shape.reason.maxLength!) + 32 * 1024;
export const REQUEST_TIMEOUT_MS = 150_000;
const HEADERS_TIMEOUT_MS = 10_000;
const BODY_TIMEOUT_MS = 30_000;
/** Tools that may submit a transaction: their stream stays open until the result. */
const TX_TOOLS = new Set<unknown>(['pay_x402', 'pay_sepa', 'revoke']);

/** Read the bearer token from a private file; refuses group/other-readable files and short tokens. */
export function readToken(path: string): string {
  const mode = statSync(path).mode;
  if (mode & 0o077) throw new Error(`${path} must be mode 600`);
  const token = readFileSync(path, 'utf8').trim();
  if (!/^[A-Za-z0-9._~+\/=-]{32,256}$/.test(token)) throw new Error(`${path} must hold a 32-256 character token`);
  return token;
}

const digest = (value: string) => createHash('sha256').update(value).digest();

/** Constant-time check of `Authorization: Bearer <token>`; hashing first hides the length. */
export function authorized(header: string | undefined, token: string): boolean {
  const presented = /^Bearer (\S+)$/.exec(header ?? '')?.[1] ?? '';
  return timingSafeEqual(digest(presented), digest(token)) && presented !== '';
}

function reply(res: ServerResponse, status: number, message: string, headers: Record<string, string> = {}): void {
  if (res.headersSent) { res.destroy(); return; }
  res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', ...headers });
  res.end(JSON.stringify({ jsonrpc: '2.0', error: { code: -32000, message }, id: null }));
}

async function readBody(req: IncomingMessage): Promise<Buffer> {
  const declared = Number(req.headers['content-length'] ?? 0);
  if (declared > MAX_BODY_BYTES) throw new RangeError('too large');
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > MAX_BODY_BYTES) throw new RangeError('too large');
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks);
}

/**
 * Stateless Streamable HTTP MCP endpoint at POST /mcp on loopback only. Every request must carry the
 * bearer token; anything else gets 401 before routing. No CORS headers are ever sent. Each request gets
 * a fresh MCP server around the same buyer, so payment state stays in this one process.
 */
export function serveHttp(newServer: () => McpServer, token: string, port: number, onError: (message: string) => void = () => {}, requestTimeoutMs = REQUEST_TIMEOUT_MS): Promise<Server> {
  const http = createHttpServer(async (req, res) => {
    if (!authorized(req.headers.authorization, token)) {
      req.resume();
      reply(res, 401, 'Unauthorized', { 'www-authenticate': 'Bearer' });
      return;
    }
    if (new URL(req.url ?? '/', 'http://127.0.0.1').pathname !== '/mcp') { req.resume(); reply(res, 404, 'Not found'); return; }
    if (req.method !== 'POST') { req.resume(); reply(res, 405, 'Method not allowed', { allow: 'POST' }); return; }
    // A payment's or revoke's stream stays open until its result (request_id or tx_hash): each step
    // (NEAR RPC included) has its own deadline. Any other open stream is ended with a JSON-RPC error.
    let body: unknown;
    const timer = setTimeout(() => {
      if (!res.headersSent) { reply(res, 504, 'Timed out'); return; }
      const messages = (Array.isArray(body) ? body : [body]) as { id?: unknown; method?: unknown; params?: { name?: unknown } }[];
      if (messages.some(m => m?.method === 'tools/call' && TX_TOOLS.has(m.params?.name))) return;
      for (const m of messages) {
        if (m?.id === undefined || typeof m.method !== 'string') continue;
        const error = { code: -32001, message: 'Request timed out; retry it' };
        res.write(`event: message\ndata: ${JSON.stringify({ jsonrpc: '2.0', id: m.id, error })}\n\n`);
      }
      res.end();
    }, requestTimeoutMs);
    res.on('close', () => clearTimeout(timer));
    try {
      body = JSON.parse((await readBody(req)).toString('utf8'));
    } catch (error) {
      if (error instanceof RangeError) { reply(res, 413, 'Request body too large', { connection: 'close' }); return; }
      reply(res, 400, 'Invalid JSON');
      return;
    }
    const server = newServer();
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    res.on('close', () => { void transport.close(); void server.close(); });
    try {
      await server.connect(transport);
      await transport.handleRequest(req, res, body);
    } catch (error) {
      onError(error instanceof Error ? error.message : 'request failed');
      reply(res, 500, 'Internal error');
    }
  });
  http.requestTimeout = BODY_TIMEOUT_MS;
  http.headersTimeout = HEADERS_TIMEOUT_MS;
  http.maxHeadersCount = 50;
  return new Promise((resolve, reject) => {
    http.once('error', reject);
    http.listen(port, '127.0.0.1', () => { http.off('error', reject); resolve(http); });
  });
}
