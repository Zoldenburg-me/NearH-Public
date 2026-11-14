import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { Buyer, safeDetail } from './buyer.ts';
import { x402Input, sepaInput, receiptInput, revokeInput } from './policy.ts';

const paymentOutput = z.object({
  status: z.enum(['paid', 'submitted', 'held', 'blocked', 'pending', 'failed']),
  request_id: z.string(),
}).passthrough();
const receiptOutput = z.object({
  request_id: z.string(), status: z.enum(['held', 'blocked', 'pending', 'signed', 'unknown', 'spent', 'released', 'revoked']),
}).passthrough();

export function createServer(buyer: Buyer): McpServer {
  const server = new McpServer({ name: 'nearh-buyer', version: '1.0.0' });
  const run = async (action: () => Promise<object>) => {
    try {
      const output = await action();
      const text = buyer.redact(JSON.stringify(output));
      return { content: [{ type: 'text' as const, text }], structuredContent: JSON.parse(text) as Record<string, unknown> };
    } catch (error) {
      return { isError: true, content: [{ type: 'text' as const, text: buyer.redact(safeDetail(error)) }] };
    }
  };
  server.registerTool('pay_x402', {
    description: 'Pay an allowed HTTP resource through the NEAR mandate. Scam checks may hold it for the owner. No automatic payment retries.',
    inputSchema: x402Input, outputSchema: paymentOutput,
  }, args => run(() => buyer.payX402(args)));
  server.registerTool('pay_sepa', {
    description: 'Request a contract-signed sandbox SEPA payout and hand it to M1 once. Monerium credentials stay in M1.',
    inputSchema: sepaInput, outputSchema: paymentOutput,
  }, args => run(() => buyer.paySepa(args)));
  server.registerTool('revoke', {
    description: "Revoke only this agent's own mandate and function-call key. Irreversible by the agent.",
    inputSchema: revokeInput, outputSchema: z.object({ revoked: z.boolean(), key_deleted: z.boolean().optional(), tx_hash: z.string().optional() }),
  }, () => run(() => buyer.revoke()));
  server.registerTool('get_receipt', {
    description: 'Read a payment receipt and current contract status. Never submits a payment or tops up.',
    inputSchema: receiptInput, outputSchema: receiptOutput,
    annotations: { readOnlyHint: true },
  }, args => run(() => buyer.getReceipt(args.request_id)));
  return server;
}
