import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createBuyerFromEnv } from '@nearh/agent-mcp/src/runtime.ts';
import { createServer } from '@nearh/agent-mcp/src/server.ts';

try {
  const buyer = await createBuyerFromEnv();
  const server = createServer(buyer);
  // Held requests remain visible to the dashboard; this demonstration never resumes them.
  await server.connect(new StdioServerTransport());
} catch {
  process.stderr.write('Demo buyer startup failed; no payment retried.\n');
  process.exitCode = 1;
}
