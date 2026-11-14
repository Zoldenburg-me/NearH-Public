// Top-up recipient and token never come from the NEAR RPC view: a stubbed RPC that returns an
// attacker evm_address or token is refused. No network; the passkey file is a dummy in a temp dir.
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, test } from "node:test";
import { agentEvmAddress } from "../../near/src/derive.ts";
import { pinnedTokens, type Config } from "../../near/src/near.ts";
import { agentFloat, loadAgent } from "../src/agent.ts";
import { transferCallData } from "../src/base.ts";

const CFG: Config = { rpc: "https://rpc.testnet.near.org", contractId: "mandate.testnet", mpcContract: "v1.signer-prod.testnet", keyDir: "/k" };
const AGENT = "a1";
const SAFE = "0x5afe000000000000000000000000000000000001";
const ATTACKER = "0x000000000000000000000000000000000000dead";
const EOA = agentEvmAddress(CFG, AGENT);
const { usdc: USDC, eure: EURE } = pinnedTokens();

let agent: any;
let mandate: any;
const realFetch = globalThis.fetch;
const env = { ...process.env };

beforeEach(() => {
  const dir = mkdtempSync(join(tmpdir(), "nearh-agent-"));
  // A valid P-256 point (the generator), public material only.
  const x = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
  const y = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
  writeFileSync(join(dir, "safe-passkey.json"), JSON.stringify({ credential_id: "c", x: `0x${x}`, y: `0x${y}`, safe_address: SAFE }));
  process.env.OWNER_KEY_DIR = dir;
  delete process.env.USDC_ADDRESS;
  delete process.env.EURE_ADDRESS;
  agent = { agent: AGENT, public_key: null, evm_address: EOA, revoked: false, sweep_config: { safe_address: SAFE, usdc_address: USDC, eure_address: EURE, chain_id: 84532 } };
  mandate = { usdc_address: USDC, eure_address: EURE, chain_id: 84532, float_cap: { usdc: "25000000", eure: "25000000000000000000" } };
  globalThis.fetch = (async (url: string, init: RequestInit) => {
    assert.equal(url, CFG.rpc);
    const { params } = JSON.parse(String(init.body));
    const out = params.method_name === "get_agent" ? agent : params.method_name === "get_mandate" ? mandate : assert.fail(`unexpected view ${params.method_name}`);
    return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result: { result: [...Buffer.from(JSON.stringify(out))] } }));
  }) as typeof fetch;
});
afterEach(() => {
  globalThis.fetch = realFetch;
  process.env = { ...env };
});

test("an honest RPC: the EOA is the derived one and the token the pinned one", async () => {
  const f = await agentFloat(CFG, AGENT, "usdc");
  assert.equal(f.eoa, EOA);
  assert.equal(f.asset, USDC);
  assert.equal(f.cap, 25_000_000n);
  assert.match(transferCallData(f.eoa, 1n), new RegExp(EOA.slice(2)));
  assert.equal((await agentFloat(CFG, AGENT, "eure")).asset, EURE);
});

test("an RPC returning an attacker evm_address is refused, for top-up and sweep", async () => {
  agent.evm_address = ATTACKER;
  await assert.rejects(agentFloat(CFG, AGENT, "usdc"), /RPC reports evm_address 0x0+dead .* refusing/);
  await assert.rejects(loadAgent(CFG, AGENT), /refusing/);
  agent.evm_address = EOA.toUpperCase().replace("0X", "0x"); // case alone is not a mismatch
  assert.equal((await loadAgent(CFG, AGENT)).eoa, EOA);
});

test("an RPC returning an attacker token is refused", async () => {
  mandate.usdc_address = ATTACKER;
  await assert.rejects(agentFloat(CFG, AGENT, "usdc"), /mandate usdc_address 0x0+dead is not the pinned USDC .* refusing/);
  mandate.usdc_address = USDC;
  mandate.eure_address = USDC; // a real token, but not the pinned EURe
  await assert.rejects(agentFloat(CFG, AGENT, "eure"), /not the pinned EURE/);
});

test("the token pin follows the owner's USDC_ADDRESS, not the mandate", async () => {
  process.env.USDC_ADDRESS = ATTACKER.replace("dead", "beef");
  await assert.rejects(agentFloat(CFG, AGENT, "usdc"), /not the pinned USDC/);
});

test("an MPC contract with no pinned root key is refused", async () => {
  await assert.rejects(agentFloat({ ...CFG, mpcContract: "other-mpc.testnet" }, AGENT, "usdc"), /no pinned root key/);
});
