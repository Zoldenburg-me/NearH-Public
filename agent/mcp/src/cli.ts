import { homedir } from 'node:os';
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createBuyerFromEnv } from './runtime.ts';
import { createServer } from './server.ts';
import { safeDetail } from './buyer.ts';
import { readToken, serveHttp } from './http.ts';

try {
  const { values } = parseArgs({ options: { http: { type: 'string' } } });
  const port = values.http === undefined ? undefined : Number(values.http);
  if (port !== undefined && !(Number.isInteger(port) && port > 0 && port < 65536)) throw new Error('--http takes a port number');
  const token = port === undefined ? undefined : readToken(process.env.MCP_HTTP_TOKEN_FILE || join(homedir(), '.config/nearh/mcp-http.token'));
  const buyer = await createBuyerFromEnv();
  let checking = false;
  const timer = setInterval(() => {
    if (checking) return;
    checking = true;
    buyer.processDecisions().catch(error => {
      process.stderr.write(`Held decision processing failed: ${safeDetail(error)}\n`);
    }).finally(() => { checking = false; });
  }, 2000);
  if (port === undefined) {
    const server = createServer(buyer);
    await server.connect(new StdioServerTransport());
    server.server.onclose = () => { clearInterval(timer); };
  } else {
    await serveHttp(() => createServer(buyer), token!, port, message => process.stderr.write(`HTTP MCP request failed: ${buyer.redact(message)}\n`));
    process.stderr.write(`Buyer MCP listening on http://127.0.0.1:${port}/mcp (bearer token required)\n`);
  }
} catch (error) {
  process.stderr.write(`Buyer MCP startup failed: ${safeDetail(error)}\n`);
  process.exitCode = 1;
}
