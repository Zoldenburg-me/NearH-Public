import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { object } from './e1-mcp.ts';

export type Evidence = { step: string; result: string; request_id?: string; near_tx_hash?: string;
  tx_hash?: string; monerium_order_id?: string; error_code?: string; resource_sha256?: string };
const patterns: Record<string, RegExp> = {
  request_id: /^[A-Za-z0-9._:-]{1,64}$/, near_tx_hash: /^[1-9A-HJ-NP-Za-km-z]{32,64}$/,
  tx_hash: /^0x[0-9a-fA-F]{64}$/, monerium_order_id: /^[0-9a-f-]{36}$/i,
  error_code: /^(ERR_[A-Z0-9_]{1,60}|LOW_FLOAT|PAYMENT_ERROR|OWNER_APPROVAL_INVALID|M1_(ERROR|AGENT_REVOKED|BAD_SIGNATURE|DUPLICATE_REQUEST|IBAN_NOT_ALLOWED|INVALID_INPUT|NOT_A_PAYOUT|NOT_SIGNED|ORDER_EXPIRED|ORDER_MISMATCH|REQUEST_NOT_FOUND|UNKNOWN_AGENT)|MONERIUM_(OUTCOME_UNKNOWN|DUPLICATE_ORDER|REFUSED))$/,
};
export function evidence(step: string, result: string, value: Record<string, unknown> = {}): Evidence {
  const fields = Object.fromEntries(Object.entries(patterns).flatMap(([name, pattern]) => {
    const field = value[name];
    if (field === undefined) return [];
    if (typeof field !== 'string' || !pattern.test(field)) throw new Error(`Invalid ${name} evidence`);
    return [[name, field]];
  }));
  return { step, result, ...fields };
}
export function resourceDigest(receipt: Record<string, unknown>): string {
  if (receipt.outcome !== 'paid' || typeof receipt.response !== 'string' || !receipt.response ||
    typeof receipt.resource_status !== 'number' || receipt.resource_status < 200 || receipt.resource_status >= 300 || receipt.resource_error) {
    throw new Error('Paid resource was not delivered successfully');
  }
  return createHash('sha256').update(receipt.response).digest('hex');
}
export function assertSigned(receipt: Record<string, unknown>, requestId: unknown, shape: string): void {
  const reservation = object(receipt.reservation);
  const key = object(reservation.key);
  if (key.request_id !== requestId || reservation.shape !== shape || reservation.status !== 'signed' || !reservation.signature) {
    throw new Error('Missing matching signed reservation');
  }
}
export function saveEvidence(path: string, records: Evidence[], complete: boolean): void {
  writeFileSync(path, JSON.stringify({ network: 'NEAR testnet / Base Sepolia / Monerium sandbox', complete, records }, null, 2) + '\n', { mode: 0o600 });
}
