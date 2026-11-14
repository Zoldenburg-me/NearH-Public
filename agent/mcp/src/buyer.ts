import { randomUUID } from 'node:crypto';
import { nearX402Fetch, SettlementWindowError, type NearX402Signer, type X402Shape } from '@nearh/agent-signer';
import { decodePaymentResponseHeader } from '@x402/fetch';
import { readLimitedText } from '@x402/core/http';
import { checkAndHold, readHeldQueue, type CheckParams, type CheckResult, type HeldItem } from 'scamcheck';
import { canonicalAmount, euroUnits, ibanCommitment, sellerUrl, x402Input, sepaInput, receiptInput } from './policy.ts';
import { ReceiptStore, type PaymentResult, type Receipt } from './store.ts';

export type PayoutInput = { agent: string; request_id: string; iban: string; amount: string; memo: string };
export type HeldDecision = Omit<HeldItem, 'status' | 'decided_at'> & { status: 'held' | 'approved' | 'rejected'; decided_at: string | null; decided_nonce?: number; assertion?: { owner_nonce: number; expires_at: number; authenticator_data: string; client_data_json: string; signature: string } };
export type Dependencies = {
  signer: NearX402Signer;
  store: ReceiptStore;
  allowedOrigins: string[];
  view(method: string, args: object): Promise<unknown>;
  call(method: 'request_signature' | 'revoke_self', args: object): Promise<{ hash: string; value: unknown }>;
  submit(input: PayoutInput): Promise<Record<string, unknown>>;
  balance(rail: 'x402' | 'sepa'): Promise<bigint>;
  fetch?: typeof fetch;
  check?: (params: CheckParams) => Promise<CheckResult>;
  readHeld?: () => Promise<HeldDecision[]>;
  secrets?: string[];
  verifySettlement(receipt: Receipt, hash: string): Promise<boolean>;
  verifyDecision(item: HeldDecision): Promise<void>;
  notifyOwner?: (message: string) => void;
};
class HeldPayment extends Error {}
class LowFloat extends Error {}
const equalShape = (a: Record<string, unknown>, b: Record<string, unknown>) =>
  Object.keys(a).length === Object.keys(b).length && Object.entries(a).every(([key, value]) => b[key] === value);
const requestId = () => `pay-${randomUUID()}`;
const object = (value: unknown): Record<string, unknown> => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid service response');
  return value as Record<string, unknown>;
};

export function safeDetail(error: unknown, secrets: string[] = []): string {
  let text = error instanceof Error ? error.message : String(error);
  for (const secret of secrets) if (secret) text = text.split(secret).join('<REDACTED>');
  return text.replace(/[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}/g, iban => `IBAN …${iban.slice(-4)}`).slice(0, 1000);
}

export class Buyer {
  private readonly deps: Dependencies;
  private revoked = false;
  private readonly running = new Set<string>();
  constructor(deps: Dependencies) { this.deps = deps; }

  redact(text: string): string {
    let result = text;
    for (const secret of this.deps.secrets ?? []) if (secret) result = result.split(secret).join('<REDACTED>');
    return result.replace(/[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}/g, iban => `IBAN …${iban.slice(-4)}`);
  }

  private save(id: string, fields: Partial<Receipt>): Receipt {
    const previous = this.deps.store.get(id);
    if (!previous) throw new Error('Receipt not found');
    const receipt = { ...previous, ...fields };
    this.deps.store.put(receipt);
    return receipt;
  }
  private begin(rail: 'x402' | 'sepa', args: Record<string, unknown>): string {
    if (this.revoked) throw new Error('ERR_AGENT_REVOKED: this agent revoked itself');
    const id = requestId();
    this.deps.store.put({ request_id: id, agent: this.deps.signer.agent, rail, status: 'pending', created_at: new Date().toISOString(), signing_started: false, operation: { tool: rail === 'x402' ? 'pay_x402' : 'pay_sepa', args } });
    return id;
  }
  private fail(id: string, error: unknown): PaymentResult {
    const receipt = this.deps.store.get(id);
    const detail = safeDetail(error, this.deps.secrets);
    if (receipt?.outcome === 'paid') {
      const delivery = `Payment settled; resource delivery failed: ${detail}`;
      this.save(id, { detail: delivery });
      return { status: 'paid', request_id: id, amount: receipt.amount, pay_to: receipt.payee, tx_hash: receipt.tx_hash, scam_check: receipt.scam_check, detail: delivery };
    }
    const code = /\bERR_[A-Z0-9_]+\b/.exec(detail)?.[0];
    const held = error instanceof HeldPayment || receipt?.status === 'held';
    const lowFloat = error instanceof LowFloat || receipt?.error_code === 'LOW_FLOAT';
    const uncertain = !held && !code && !lowFloat && receipt?.signing_started === true;
    const status = held ? 'held' : code || lowFloat ? 'blocked' : uncertain ? 'pending' : 'failed';
    const error_code = held ? undefined : code ?? (lowFloat ? 'LOW_FLOAT' : 'PAYMENT_ERROR');
    this.save(id, { status: held ? 'held' : status === 'blocked' ? 'blocked' : receipt?.status === 'signed' ? 'signed' : uncertain ? 'unknown' : 'blocked', outcome: status, error_code, detail });
    return { status, request_id: id, tx_hash: receipt?.tx_hash, error_code, detail, scam_check: receipt?.scam_check };
  }

  private async guard(id: string, shape: Record<string, unknown>, invoice: string, source: string, approved = false, memo?: string): Promise<void> {
    const receipt = this.deps.store.get(id);
    if (!receipt) throw new Error('Receipt not found');
    const payee = String(shape.payTo ?? shape.iban);
    if (approved) {
      if (!receipt.shape || !equalShape(shape, receipt.shape)) throw new Error('Approved payment requirements changed; request a new payment');
    } else {
      this.save(id, { shape, payee, amount: String(shape.amount) });
      const payees = await this.deps.view('get_payees', { agent: this.deps.signer.agent });
      if (!Array.isArray(payees)) throw new Error('Invalid contract payee response');
      const known = payees.some(value => {
        const p = object(value);
        return receipt.rail === 'x402' ? p.rail === 'x402' && String(p.pay_to).toLowerCase() === payee.toLowerCase()
          : p.rail === 'sepa' && p.supplier === shape.supplier && p.iban_commitment === ibanCommitment(payee, String(shape.salt));
      });
      const history = this.deps.store.all().filter(r => r.agent === receipt.agent && r.rail === receipt.rail && r.payee && r.amount && ['paid', 'submitted'].includes(r.outcome ?? '') && (r.completed_at || r.created_at));
      const result = await (this.deps.check ?? checkAndHold)({
        agent: receipt.agent, request_id: id, rail: receipt.rail, shape, memo,
        invoice: { text: invoice, source }, payee_known: known,
        payee_history: history.map(r => ({ payee: r.payee!, amounts: [r.amount!], last_seen: (r.completed_at ?? r.created_at)! })),
      });
      this.save(id, { scam_check: result.verdict.result });
      if (result.status === 'held') {
        this.save(id, { status: 'held', held_id: result.item?.id });
        throw new HeldPayment(result.verdict.reason ?? 'Scam check timed out; held for owner');
      }
      if (result.status !== 'approved' && result.status !== 'skipped') throw new Error('Invalid scam check response');
    }
    const balance = await this.deps.balance(receipt.rail);
    const amount = receipt.rail === 'sepa' ? euroUnits(String(shape.amount)) : BigInt(String(shape.amount));
    if (balance < amount) {
      this.save(id, { status: 'blocked', error_code: 'LOW_FLOAT' });
      this.deps.notifyOwner?.(`Owner notice: LOW_FLOAT for agent ${receipt.agent} on ${receipt.rail}; owner Safe top-up required`);
      throw new LowFloat('Low float: owner must top up from the Safe; the agent cannot top up');
    }
    // Persist before signing: an interrupted call must never become an automatic retry.
    this.save(id, { status: 'pending' });
  }

  async payX402(input: unknown): Promise<PaymentResult> {
    const args = x402Input.parse(input);
    sellerUrl(args.url, this.deps.allowedOrigins);
    const id = this.begin('x402', args);
    return this.executeX402(id, args);
  }
  private async executeX402(id: string, args: ReturnType<typeof x402Input.parse>, approved = false): Promise<PaymentResult> {
    let signed = false;
    const signer = this.deps.signer;
    // The SDK's scheme keeps its domain and payload checks; the guard sits immediately before A1 signs.
    const guarded = new Proxy(signer, { get: (target, property, receiver) => property === 'signX402' ? async (shape: X402Shape) => {
      if (signed) throw new Error('One signature per payment operation');
      if (new URL(shape.resourceUrl).href !== new URL(args.url).href) throw new Error('Seller resource URL differs from the requested URL');
      await this.guard(id, { type: 'x402', ...shape }, args.reason, args.url, approved);
      signed = true;
      this.save(id, { signing_started: true });
      let result;
      try {
        result = await target.signX402(shape, id);
      } catch (error) {
        if (error instanceof SettlementWindowError && error.code === 'window-too-short') this.save(id, { signing_started: false });
        throw error;
      }
      this.save(id, { status: 'signed', reservation: result.reservation as unknown as Record<string, unknown>, near_tx_hash: result.txHash });
      return result;
    } : Reflect.get(target, property, receiver) });
    try {
      const response = await nearX402Fetch(guarded, this.deps.fetch)(sellerUrl(args.url, this.deps.allowedOrigins), {
        method: args.method, body: args.method === 'POST' ? args.body : undefined,
        redirect: 'error', signal: AbortSignal.timeout(180_000),
      });
      const header = response.headers.get('payment-response');
      if (!signed || !header) throw new Error('No verified payment settlement response; inspect the receipt before retrying');
      const settlement = decodePaymentResponseHeader(header);
      if (!settlement.success || settlement.network !== 'eip155:84532' || !/^0x[0-9a-f]{64}$/i.test(settlement.transaction)) {
        throw new Error('Facilitator did not report a successful Base Sepolia settlement');
      }
      const claimed = this.save(id, { outcome: 'pending', tx_hash: settlement.transaction });
      let confirmed = false;
      let detail = 'Claimed settlement is not confirmed by matching USDC logs on Base Sepolia';
      try { confirmed = await this.deps.verifySettlement(claimed, settlement.transaction); }
      catch (error) { detail = `Settlement confirmation unavailable: ${safeDetail(error, this.deps.secrets)}`; }
      if (!confirmed) {
        // Keep the bounded resource privately so a delayed chain receipt does not require repurchase.
        this.save(id, { resource_status: response.status });
        let body;
        try { body = await readLimitedText(response, 64_000); }
        catch (error) {
          this.save(id, { resource_error: safeDetail(error, this.deps.secrets) });
          throw error;
        }
        this.save(id, { response: body, detail });
        return { status: 'pending', request_id: id, tx_hash: settlement.transaction, detail: `${detail}; inspect get_receipt for confirmation and the saved resource` };
      }
      const receipt = this.save(id, { outcome: 'paid', completed_at: new Date().toISOString() });
      const body = await readLimitedText(response, 64_000);
      this.save(id, { response: body, resource_status: response.status });
      return { status: 'paid', request_id: id, amount: receipt.amount, pay_to: receipt.payee, tx_hash: settlement.transaction, response: body, scam_check: receipt.scam_check, ...(response.ok ? {} : { detail: `Payment settled, resource returned HTTP ${response.status}` }) };
    } catch (error) { return this.fail(id, error); }
  }

  async paySepa(input: unknown): Promise<PaymentResult> {
    const raw = sepaInput.parse(input);
    const args = { ...raw, amount: canonicalAmount(raw.amount), invoice_amount: canonicalAmount(raw.invoice_amount) };
    const id = this.begin('sepa', args);
    const shape = { type: 'payout', supplier: args.supplier, iban: args.iban, salt: args.salt, amount: args.amount, invoice_id: args.invoice_id, invoice_amount: args.invoice_amount, timestamp: Math.floor(Date.now() / 1000) };
    this.save(id, { shape, payee: args.iban, amount: args.amount });
    return this.executeSepa(id, args, shape);
  }
  private async executeSepa(id: string, args: ReturnType<typeof sepaInput.parse>, shape: Record<string, unknown>, approved = false): Promise<PaymentResult> {
    try {
      await this.guard(id, shape, [args.invoice, args.reason].filter(Boolean).join('\n'), 'agent invoice', approved, args.memo);
      this.save(id, { signing_started: true });
      const signed = await this.deps.call('request_signature', { request_id: id, shape });
      const reservation = object(signed.value);
      this.save(id, { near_tx_hash: signed.hash, reservation });
      if (reservation.shape !== 'payout' || reservation.status !== 'signed' || !reservation.signature) throw new Error('Payout is not signed; M1 was not called');
      this.save(id, { status: 'signed' });
      // M1 reads and verifies the signature from get_request; no Monerium credentials cross this boundary.
      const result = await this.deps.submit({ agent: this.deps.signer.agent, request_id: id, iban: args.iban, amount: args.amount, memo: args.memo });
      if (result.request_id !== id || !['submitted', 'blocked', 'failed', 'pending'].includes(String(result.status))) throw new Error('Invalid M1 payout response');
      if (result.status === 'submitted' && typeof result.monerium_order_id !== 'string') throw new Error('M1 omitted the accepted order id');
      const answer = result as PaymentResult;
      this.save(id, { outcome: answer.status, ...(answer.status === 'submitted' ? { completed_at: new Date().toISOString() } : {}), monerium_order_id: answer.monerium_order_id, error_code: answer.error_code, detail: answer.detail });
      return { ...answer, scam_check: this.deps.store.get(id)?.scam_check };
    } catch (error) { return this.fail(id, error); }
  }

  async revoke(): Promise<{ revoked: boolean; key_deleted?: boolean; tx_hash: string }> {
    const outcome = await this.deps.call('revoke_self', {});
    const value = object(outcome.value);
    if (value.agent !== this.deps.signer.agent || typeof value.revoked !== 'boolean' || typeof value.key_deleted !== 'boolean') throw new Error('Invalid RevokeResult; check get_agent state');
    this.revoked = value.revoked;
    return { revoked: value.revoked, key_deleted: value.key_deleted, tx_hash: outcome.hash };
  }

  async getReceipt(id: string): Promise<Receipt> {
    receiptInput.parse({ request_id: id });
    const local = this.deps.store.get(id);
    if (local && local.agent !== this.deps.signer.agent) throw new Error('Receipt belongs to another agent');
    if (local?.status === 'held' || local?.status === 'blocked') return this.publicReceipt(local);
    const reservation = await this.deps.view('get_request', { key: { agent: this.deps.signer.agent, caller: { kind: 'agent' }, request_id: id } });
    if (reservation) {
      const r = object(reservation);
      const statuses = ['pending', 'signed', 'unknown', 'spent', 'released', 'revoked'];
      if (!statuses.includes(String(r.status))) throw new Error('Invalid reservation status');
      const latest = this.deps.store.get(id);
      // A concurrent payment completion wins over the view started before it.
      if (latest && latest.status !== local?.status) return this.publicReceipt(latest);
      const receipt = { ...(latest ?? { request_id: id, agent: this.deps.signer.agent, rail: r.shape === 'payout' || r.rail === 'sepa' ? 'sepa' as const : 'x402' as const }), status: r.status as Receipt['status'], reservation: r };
      this.deps.store.put(receipt);
      return this.publicReceipt(await this.refreshSettlement(receipt));
    }
    if (!local) throw new Error('Receipt not found');
    return this.publicReceipt(await this.refreshSettlement(local));
  }
  private async refreshSettlement(receipt: Receipt): Promise<Receipt> {
    if (receipt.rail !== 'x402' || receipt.outcome !== 'pending' || !receipt.tx_hash) return receipt;
    try {
      if (await this.deps.verifySettlement(receipt, receipt.tx_hash)) {
        const latest = this.deps.store.get(receipt.request_id) ?? receipt;
        const detail = latest.resource_error ? `Payment settled; resource delivery failed: ${latest.resource_error}`
          : latest.resource_status !== undefined && (latest.resource_status < 200 || latest.resource_status >= 300)
            ? `Payment settled, resource returned HTTP ${latest.resource_status}` : undefined;
        return this.save(receipt.request_id, { outcome: 'paid', completed_at: new Date().toISOString(), error_code: undefined, detail });
      }
      return receipt;
    } catch (error) {
      return this.save(receipt.request_id, { detail: `Settlement confirmation unavailable: ${safeDetail(error, this.deps.secrets)}` });
    }
  }
  private publicReceipt(receipt: Receipt): Receipt {
    const { operation, shape, response, ...result } = receipt;
    if (operation && !['pay_x402', 'pay_sepa'].includes(operation.tool)) throw new Error('Invalid stored operation');
    if (shape && !['x402', 'payout'].includes(String(shape.type))) throw new Error('Invalid stored shape');
    return result.outcome === 'paid' && response !== undefined ? { ...result, response } : result;
  }

  /** Only resume known locally held requests after verifying the owner's decision. */
  async processDecisions(): Promise<void> {
    const decisions = await (this.deps.readHeld ?? readHeldQueue)() as HeldDecision[];
    const nonce = (id: string) => decisions.find(item => item.request_id === id)?.decided_nonce ?? 0;
    const receipts = this.deps.store.all().filter(r => r.agent === this.deps.signer.agent && r.status === 'held').sort((a, b) => nonce(a.request_id) - nonce(b.request_id));
    for (const receipt of receipts) {
      if (this.running.has(receipt.request_id)) continue;
      const item = decisions.find(d => d.agent === receipt.agent && d.request_id === receipt.request_id);
      if (!item || item.status === 'held') continue;
      this.running.add(receipt.request_id);
      try {
        if (!receipt.held_id || item.id !== receipt.held_id || !item.decided_at || !receipt.shape || !equalShape(item.shape, receipt.shape)) throw new Error('Held decision does not match the saved payment');
        await this.deps.verifyDecision(item);
        if (item.status === 'rejected') {
          this.save(receipt.request_id, { status: 'blocked', outcome: 'blocked', decision_nonce: item.decided_nonce, detail: 'Owner rejected held request' });
          continue;
        }
        if (item.status !== 'approved') throw new Error('Invalid held decision');
        this.save(receipt.request_id, { status: 'pending', outcome: 'pending', decision_nonce: item.decided_nonce });
        const op = receipt.operation;
        let executionId = receipt.request_id;
        let result: PaymentResult;
        if (op?.tool === 'pay_x402') result = await this.executeX402(executionId, x402Input.parse(op.args), true);
        else if (op?.tool === 'pay_sepa') {
          // By design, approval creates a fresh reservation; never replay the held ID.
          const args = sepaInput.parse(op.args);
          executionId = this.begin('sepa', args);
          const shape = { ...receipt.shape, timestamp: Math.floor(Date.now() / 1000) };
          this.save(executionId, { shape, payee: receipt.payee, amount: receipt.amount, scam_check: receipt.scam_check, held_id: receipt.held_id, decision_nonce: item.decided_nonce, approved_from_request_id: receipt.request_id });
          // Consume and link the original before requesting any signature, including on interruption.
          this.save(receipt.request_id, { status: 'blocked', outcome: 'blocked', replacement_request_id: executionId, detail: 'Owner approval created a fresh payout reservation; inspect replacement_request_id' });
          result = await this.executeSepa(executionId, args, shape, true);
        } else throw new Error('Held request has no saved payment operation');
        if (result.request_id !== executionId) throw new Error('Held payment returned a different request id');
      } catch (error) {
        const detail = safeDetail(error, this.deps.secrets);
        this.save(receipt.request_id, { status: 'blocked', outcome: 'blocked', error_code: 'OWNER_APPROVAL_INVALID', detail });
        this.deps.notifyOwner?.(`Held request ${receipt.request_id} blocked: ${detail}`);
      } finally { this.running.delete(receipt.request_id); }
    }
  }
}
