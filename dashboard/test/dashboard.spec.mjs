// DB1 smoke tests: the shipped server (serve.mjs) on a temp copy of the held file, a mocked
// NEAR RPC, and a Chromium virtual authenticator holding a P-256 owner passkey whose key the
// mock contract reports. Every relayed owner call is checked here as assert_owner checks it.

import { expect, test } from "@playwright/test";
import { createServer } from "node:http";
import { copyFileSync, mkdtempSync, readFileSync } from "node:fs";
import { createHash, generateKeyPairSync, randomBytes, verify } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { b64url, ownerChallenge, resolveArgs, revokeArgs } from "../public/owner.js";
import { startServer } from "../serve.mjs";

const CONTRACT = "mandate-demo.testnet";
const RPC = "https://rpc.testnet.near.org";
const sha256 = (b) => createHash("sha256").update(b).digest();
const nowSecs = () => Math.floor(Date.now() / 1000);
async function freePort() {
  const s = createServer();
  await new Promise((r) => s.listen(0, "127.0.0.1", r));
  const { port } = s.address();
  await new Promise((r) => s.close(r));
  return port;
}

const MANDATE = {
  x402: { amount_range: { min: "1", max: "1000000" }, budget: "20000000", period_secs: 604800 },
  sepa: { amount_range: { min: "1", max: "50000000000000000000" }, budget: "200000000000000000000", period_secs: 604800 },
  usdc_address: "0x036cbd53842c5426634e7929541ec2318f3dcf7e",
  eure_address: "0x29f37f6adca168b79b8d9567eab9be3fbf21db85",
  chain_id: 84532,
  float_cap: { usdc: "25000000", eure: "250000000000000000000" },
  max_validity_secs: 300,
};

function reservation(request_id, status, extra = {}) {
  return {
    key: { agent: "agent-1", caller: { kind: "agent" }, request_id },
    shape: "x402",
    rail: "x402",
    amount: "10000",
    period_start_ms: 1793550000000,
    created_at_ms: 1793555551000,
    valid_before: 1793555881,
    release_after: 1793555881,
    digest: "0x" + "00".repeat(32),
    payload: { kind: "message", text: "" },
    status,
    counts_against_budget: true,
    signature: null,
    ...extra,
  };
}

/** Owner passkey: the private key goes into the virtual authenticator, the public key into get_config. */
function ownerKey() {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = publicKey.export({ format: "jwk" });
  const x = Buffer.from(jwk.x, "base64url");
  const y = Buffer.from(jwk.y, "base64url");
  const compressed = Buffer.concat([Buffer.from([y[31] & 1 ? 3 : 2]), x]);
  return { privateKey, publicKey, compressed };
}

/** What the contract's assert_owner checks (contract/src/owner.rs), against the mock's state. */
async function checkAssertion(call, st, borshArgs) {
  const a = call.assertion;
  expect(Object.keys(a).sort()).toEqual(["authenticator_data", "client_data_json", "expires_at", "owner_nonce", "signature"]);
  const client = JSON.parse(a.client_data_json);
  expect(client.type).toBe("webauthn.get");
  const challenge = await ownerChallenge(CONTRACT, "testnet", call.method, borshArgs, a.owner_nonce, a.expires_at);
  expect(client.challenge).toBe(b64url(challenge));
  expect(client.origin).toBe(st.origin);
  const authData = Buffer.from(a.authenticator_data, "base64");
  expect(authData.subarray(0, 32).equals(sha256("localhost"))).toBe(true);
  expect(authData[32] & 0x01).toBe(0x01); // user present
  expect(authData[32] & 0x04).toBe(0x04); // user verified (userVerification: required)
  expect(a.owner_nonce).toBe(st.owner_nonce + 1);
  expect(a.expires_at).toBeGreaterThan(nowSecs());
  expect(a.expires_at).toBeLessThanOrEqual(nowSecs() + 600);
  const sig = Buffer.from(a.signature, "base64");
  expect(sig.length).toBe(64);
  const signed = Buffer.concat([authData, sha256(Buffer.from(a.client_data_json, "utf8"))]);
  // node's verify hashes `signed` once more: p256_verify(sig, sha256(signed), key).
  expect(verify("sha256", signed, { key: st.key.publicKey, dsaEncoding: "ieee-p1363" }, sig)).toBe(true);
}

let open = [];
test.afterEach(async () => {
  await Promise.all(open.map((s) => s.close()));
  open = [];
});

/** Starts serve.mjs on a temp held file and mocks the contract behind the NEAR RPC. */
async function setup(page, { requests = [], chainId = "testnet", originOverride } = {}) {
  const heldFile = join(mkdtempSync(join(tmpdir(), "db1-")), "held.jsonl");
  copyFileSync(new URL("./fixtures/held.jsonl", import.meta.url), heldFile);
  const st = { owner_nonce: 4, revoked: false, requests, relayed: [], key: ownerKey(), origin: "" };

  const relay = async (call) => {
    const borshArgs = call.method === "revoke" ? revokeArgs(call.args.agent) : resolveArgs(call.args.key, call.args.outcome);
    await checkAssertion(call, st, borshArgs);
    st.relayed.push(call);
    st.owner_nonce = call.assertion.owner_nonce;
    if (call.method === "revoke") st.revoked = true;
    else st.requests.find((r) => r.key.request_id === call.args.key.request_id).status = call.args.outcome;
    return { txHash: "mock", ownerNonce: st.owner_nonce };
  };
  // The owner origin names the port, so pick it before the server starts and checks it.
  const port = await freePort();
  const base = `http://localhost:${port}`;
  st.origin = base;

  const views = {
    get_config: () => ({
      owner: { mode: "passkey", public_key: st.key.compressed.toString("base64"), rp_id: "localhost", origin: originOverride ?? st.origin },
      owner_nonce: st.owner_nonce,
      network: "testnet",
      mpc_contract: "v1.signer-prod.testnet",
      relayer: null,
    }),
    list_agents: () => [
      {
        agent: "agent-1",
        public_key: st.revoked ? null : "ed25519:EuRa2phH1QCNW9fkjXArT71XybokoeCCR8z6RA5eXMvJ",
        sweep_config: { safe_address: "0x5afe000000000000000000000000000000000001", usdc_address: MANDATE.usdc_address, eure_address: MANDATE.eure_address, chain_id: 84532 },
        evm_address: "0xbbc0320e02d371a71f18a40b7b15404df218d880",
        linked: true,
        revoked: st.revoked,
      },
    ],
    get_mandate: () => (st.revoked ? null : MANDATE),
    get_budget: ({ rail }) => {
      // Rail is snake_case in the contract; anything else fails to deserialize.
      if (rail !== "x402" && rail !== "sepa") throw new Error(`unknown variant \`${rail}\``);
      // sepa: the mandate now says 7 days, but the current window still runs 2 days (D7).
      return st.revoked ? null : { rail, period_start_ms: 1793550000000, period_secs: rail === "sepa" ? 172800 : 604800, budget: MANDATE[rail].budget, reserved: rail === "x402" ? "10000" : "0" };
    },
    list_requests: () => st.requests,
  };
  // The server reads get_config() itself, at start and for held decisions; it sees the same mock
  // contract. A mismatched origin (originOverride) would stop it starting, so that test skips the
  // start check to reach the page's own refusal.
  const server = await startServer({ port, contractId: CONTRACT, nearRpc: RPC, heldFile, relay, getConfig: async () => views.get_config(), checkOwnerOrigin: !originOverride });
  open.push(server);
  await page.route(RPC, async (route) => {
    const { id, method, params } = route.request().postDataJSON();
    let result;
    if (method === "status") result = { chain_id: chainId };
    else {
      const args = JSON.parse(Buffer.from(params.args_base64, "base64").toString("utf8"));
      try {
        result = { result: [...Buffer.from(JSON.stringify(views[params.method_name](args)))] };
      } catch (e) {
        result = { error: `wasm execution failed: ${e.message}` };
      }
    }
    await route.fulfill({ contentType: "application/json", body: JSON.stringify({ jsonrpc: "2.0", id, result }) });
  });
  return { base, st, heldFile };
}

async function addPasskey(page, st) {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
  });
  await cdp.send("WebAuthn.addCredential", {
    authenticatorId,
    credential: {
      credentialId: randomBytes(16).toString("base64"),
      isResidentCredential: true,
      rpId: "localhost",
      privateKey: st.key.privateKey.export({ format: "der", type: "pkcs8" }).toString("base64"),
      userHandle: Buffer.from("owner").toString("base64"),
      signCount: 0,
    },
  });
}

const heldItems = (file) => readFileSync(file, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));

test("a held item appears and can be released", async ({ page }) => {
  const { base, st, heldFile } = await setup(page);
  await addPasskey(page, st);
  await page.goto(base);
  const item = page.locator('[data-held-id="held-0b6c1d2e-3f40-4a51-8b62-7c83d94ea5f6"]');
  await expect(item.getByTestId("status")).toHaveText("held");
  await expect(item).toContainText("GB33BUKB20201555555555");
  await expect(page.locator('[data-count="held"]')).toHaveText("held 2");

  await item.getByRole("button", { name: "Approve" }).click();
  await expect(item.getByTestId("status")).toHaveText("approved");
  await expect(item.getByRole("button")).toHaveCount(0);
  await expect(page.locator('[data-count="held"]')).toHaveText("held 1");
  const [first, second] = heldItems(heldFile);
  expect([first.id, first.status, second.status]).toEqual(["held-0b6c1d2e-3f40-4a51-8b62-7c83d94ea5f6", "approved", "held"]);
  expect(first.decided_at).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
  // Signed with the passkey under the held queue's own nonce; the contract's nonce is untouched.
  expect([first.decided_nonce, st.owner_nonce]).toEqual([1, 4]);
  await expect(page.locator("#errors li")).toHaveCount(0);
});

test("Revoke signs with the passkey and flips the agent to revoked", async ({ page }) => {
  const { base, st } = await setup(page, { requests: [reservation("pay-0001", "signed")] });
  await addPasskey(page, st);
  await page.goto(base);
  const row = page.locator('[data-agent="agent-1"]');
  await expect(row.getByTestId("status")).toHaveText("active");
  await expect(page.locator('[data-mandate="agent-1"] [data-rail="x402"] [data-testid="budget"]')).toHaveText("0.01 USDC of 20 USDC");
  await expect(page.locator('[data-mandate="agent-1"] [data-rail="sepa"] [data-testid="budget"]')).toHaveText("0 EURe of 200 EURe");
  await expect(page.locator('[data-mandate="agent-1"] [data-rail="sepa"] td').nth(3)).toHaveText("2 days");
  await expect(page.locator('[data-count="allowed"]')).toHaveText("allowed 1");

  await row.getByRole("button", { name: "Revoke" }).click();
  await expect(row.getByTestId("status")).toHaveText("revoked");
  // Revoking again stays possible: it retries a failed DeleteKey (D1).
  await expect(row.getByRole("button", { name: "Revoke", exact: true })).toHaveCount(0);
  await expect(row.getByRole("button", { name: "Retry key deletion" })).toBeEnabled();
  expect(st.relayed.map((c) => [c.method, c.args, c.assertion.owner_nonce])).toEqual([["revoke", { agent: "agent-1" }, 5]]);
  await expect(page.locator("#errors li")).toHaveCount(0);
});

test("Resolve unknown: one call per click, Released only after release_after, fresh nonce each time", async ({ page }) => {
  const past = reservation("inv-past", "unknown", { release_after: nowSecs() - 10 });
  const future = reservation("inv-future", "unknown", { release_after: nowSecs() + 3600 });
  const { base, st } = await setup(page, { requests: [past, future] });
  await addPasskey(page, st);
  await page.goto(base);
  const pastRow = page.locator('[data-unknown="inv-past"]');
  const futureRow = page.locator('[data-unknown="inv-future"]');
  await expect(futureRow.getByRole("button", { name: "Released" })).toBeDisabled();
  await expect(pastRow.getByRole("button", { name: "Released" })).toBeEnabled();

  await pastRow.getByRole("button", { name: "Released" }).click();
  await expect(page.locator('[data-request="inv-past"] [data-testid="status"]')).toHaveText("released");
  await futureRow.getByRole("button", { name: "Spent" }).click();
  await expect(page.locator('[data-request="inv-future"] [data-testid="status"]')).toHaveText("spent");

  expect(st.relayed.map((c) => [c.args.key.request_id, c.args.outcome, c.assertion.owner_nonce])).toEqual([
    ["inv-past", "released", 5],
    ["inv-future", "spent", 6],
  ]);
  await expect(page.locator("#unknown")).toContainText("No unknown reservations.");
});

test("held-item text from email is shown as text and never runs", async ({ page }) => {
  const dialogs = [];
  page.on("dialog", (d) => (dialogs.push(d.message()), d.dismiss()));
  const { base } = await setup(page);
  await page.goto(base);
  const item = page.locator('[data-held-id="held-1c7d2e3f-4051-4b62-9c73-8d94ea5fb607"]');
  await expect(item.getByTestId("invoice")).toHaveText(`<img src=x onerror="window.__xss='invoice'"><script>window.__xss='invoice-script'</script>`);
  await expect(item).toContainText("memo: <script>window.__xss='memo'</script>");
  await expect(item).toContainText(`to <img src=x onerror="window.__xss='iban'">`);
  expect(await page.locator("#held img, #held script").count()).toBe(0);
  expect(await page.evaluate(() => window.__xss)).toBeUndefined();
  expect(dialogs).toEqual([]);
});

test("refuses to sign when the page is not the contract's owner origin", async ({ page }) => {
  const { base, st } = await setup(page, { originOverride: "http://localhost:1" });
  await addPasskey(page, st);
  await page.goto(base);
  await page.locator('[data-agent="agent-1"]').getByRole("button", { name: "Revoke" }).click();
  await expect(page.locator("#errors")).toContainText("refusing to sign");
  expect(st.relayed).toEqual([]);
  await expect(page.locator('[data-agent="agent-1"]').getByTestId("status")).toHaveText("active");
});

test("refuses an RPC that is not on testnet", async ({ page }) => {
  const { base } = await setup(page, { chainId: "mainnet" });
  await page.goto(base);
  await expect(page.locator("#errors")).toContainText("is on mainnet, not testnet");
  await expect(page.locator("[data-agent]")).toHaveCount(0);
});
