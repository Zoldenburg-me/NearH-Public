import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { resolve } from 'node:path';

const AGENT_ENV = ['PATH', 'HOME', 'TMPDIR', 'NEAR_RPC', 'MANDATE_CONTRACT_ID', 'AGENT_NEAR_PRIVATE_KEY',
  'AGENT_EVM_ADDRESS', 'BASE_SEPOLIA_RPC', 'M1_URL', 'M1_AGENT_TOKEN', 'MCP_SELLER_ORIGINS',
  'MCP_RECEIPT_DIR', 'MCP_X402_MAX_UNITS', 'NEAR_AI_API_KEY', 'SCAMCHECK_HELD_DIR', 'NEAR_AI_BASE_URL', 'NEAR_AI_MODEL'];
export function agentEnvironment(env: NodeJS.ProcessEnv): Record<string, string> {
  return Object.fromEntries(AGENT_ENV.flatMap(name => env[name] === undefined ? [] : [[name, env[name]!]]));
}
export function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid structured response');
  return value as Record<string, unknown>;
}
export function demoAgentEnvironment(root: string, run: string, env: NodeJS.ProcessEnv): Record<string, string> {
  if (!/^[1-9][0-9]{0,38}$/.test(env.E1_X402_MAX_UNITS ?? '')) throw new Error('Set a positive E1_X402_MAX_UNITS');
  if (!/^[0-9a-f-]{36}$/i.test(run)) throw new Error('Invalid demo run id');
  return agentEnvironment({ ...env, MCP_X402_MAX_UNITS: env.E1_X402_MAX_UNITS,
    MCP_RECEIPT_DIR: resolve(root, 'demo/.runs', run, 'receipts') });
}
export async function connectMcp(root: string, env: NodeJS.ProcessEnv, run: string) {
  const client = new Client({ name: 'nearh-e1', version: '1.0.0' });
  const transport = new StdioClientTransport({ command: process.execPath,
    args: [resolve(root, 'demo/src/e1-agent.ts')], cwd: resolve(root, 'agent/mcp'),
    env: demoAgentEnvironment(root, run, env), stderr: 'ignore' });
  // The child may include provider diagnostics; never copy them into public demo evidence.
  try {
    await client.connect(transport);
    const tools = await client.listTools();
    if (tools.tools.map(tool => tool.name).sort().join(',') !== 'get_receipt,pay_sepa,pay_x402,revoke') throw new Error('Unexpected agent tool surface');
  } catch {
    await transport.close();
    throw new Error('Buyer MCP startup failed; inspect private configuration');
  }
  return {
    async call(name: 'pay_x402' | 'pay_sepa' | 'get_receipt', args: Record<string, unknown>) {
      const result = await client.callTool({ name, arguments: args }, undefined, { timeout: 180_000 });
      if (result.isError) throw new Error(`MCP ${name} failed; inspect the existing receipt before another payment`);
      return object(result.structuredContent);
    },
    close: () => client.close(),
  };
}
