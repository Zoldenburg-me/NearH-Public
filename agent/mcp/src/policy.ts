import { createHash } from 'node:crypto';
import { z } from 'zod';

export const x402Input = z.object({
  url: z.string().url(), method: z.enum(['GET', 'POST']).default('GET'),
  body: z.string().max(64_000).optional(), reason: z.string().min(1).max(16_000),
}).strict();
const id = z.string().regex(/^[A-Za-z0-9._:-]{1,64}$/);
const euros = z.string().max(40).regex(/^[0-9]+(\.[0-9]{1,2})?$/);
export const sepaInput = z.object({
  supplier: id,
  iban: z.string().regex(/^[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}$/),
  /** The salt of the supplier's IBAN commitment, from the owner's supplier book. */
  salt: z.string().regex(/^0x[0-9a-fA-F]{64}$/),
  amount: euros,
  invoice_id: id,
  invoice_amount: euros,
  memo: z.string().max(140), invoice: z.string().max(16_000).optional(),
  reason: z.string().min(1).max(16_000),
}).strict();
export const receiptInput = z.object({ request_id: z.string().regex(/^[A-Za-z0-9._:-]{1,64}$/) }).strict();
export const revokeInput = z.object({}).strict();

export function canonicalAmount(amount: string): string {
  const [whole, fraction = ''] = amount.split('.');
  const integer = whole.replace(/^0+/, '') || '0';
  const decimal = fraction.replace(/0+$/, '');
  const result = decimal ? `${integer}.${decimal}` : integer;
  if (result === '0') throw new Error('Amount must be greater than zero');
  return result;
}
export function euroUnits(amount: string): bigint {
  const [whole, fraction = ''] = amount.split('.');
  return BigInt(whole) * 10n ** 18n + BigInt(fraction.padEnd(18, '0'));
}

/** Only operator-configured origins; redirects must not move a paid request elsewhere. */
export function sellerUrl(raw: string, origins: string[]): string {
  const url = new URL(raw);
  if (url.username || url.password || url.hash || !origins.includes(url.origin)) throw new Error('Seller origin is not allowed');
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && ['127.0.0.1', '[::1]', 'localhost'].includes(url.hostname))) {
    throw new Error('Seller requires HTTPS or loopback HTTP');
  }
  return url.href;
}

/** The supplier IBAN commitment the contract stores (PRIV1): sha256(domain || salt || iban). */
export function ibanCommitment(iban: string, salt: string): string {
  const hash = createHash('sha256');
  hash.update('nearh:iban-commitment:v1');
  hash.update(Buffer.from(salt.slice(2), 'hex'));
  hash.update(iban);
  return `0x${hash.digest('hex')}`;
}
