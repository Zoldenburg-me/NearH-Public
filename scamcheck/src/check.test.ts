import { test, mock } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import {
  checkScam,
  checkAndHold,
  heldPath,
  readHeldQueue,
  type CheckParams,
  type CheckResult,
  type PayeeEntry,
} from "./check.ts";

// Assigning undefined to process.env stores the string "undefined", so delete instead.
function restoreEnv(name: string, prev: string | undefined): void {
  if (prev === undefined) delete process.env[name];
  else process.env[name] = prev;
}

function makeParams(overrides: Partial<CheckParams> = {}): CheckParams {
  return {
    agent: "agent-1",
    rail: "sepa",
    request_id: "inv-0001",
    shape: {
      type: "payout",
      iban: "DE89370400440532013000",
      amount: "42.50",
      timestamp: 1793700000,
    },
    memo: "Invoice 2026-0001",
    invoice: { text: "Payment for services", source: "email" },
    payee_known: true,
    payee_history: [],
    ...overrides,
  };
}

test("skipped when NEAR_AI_API_KEY is not set", async () => {
  const prev = process.env.NEAR_AI_API_KEY;
  delete process.env.NEAR_AI_API_KEY;
  try {
    const result = await checkScam(makeParams());
    assert.equal(result.result, "skipped");
    assert.equal(result.reason, "No NEAR AI API key configured");
  } finally {
    restoreEnv("NEAR_AI_API_KEY", prev);
  }
});

test("deterministic: unknown payee is suspicious", async () => {
  const prev = process.env.NEAR_AI_API_KEY;
  process.env.NEAR_AI_API_KEY = "test-key";
  try {
    const result = await checkScam(makeParams({ payee_known: false }));
    assert.equal(result.result, "suspicious");
    assert.match(result.reason!, /unknown payee/i);
  } finally {
    restoreEnv("NEAR_AI_API_KEY", prev);
  }
});

test("deterministic: urgency wording is suspicious", async () => {
  const prev = process.env.NEAR_AI_API_KEY;
  process.env.NEAR_AI_API_KEY = "test-key";
  try {
    const result = await checkScam(makeParams({
      invoice: { text: "URGENT: our bank details changed, pay today", source: "email" },
    }));
    assert.equal(result.result, "suspicious");
    assert.match(result.reason!, /urgency/i);
  } finally {
    restoreEnv("NEAR_AI_API_KEY", prev);
  }
});

test("deterministic: changed payTo is suspicious", async () => {
  const prev = process.env.NEAR_AI_API_KEY;
  process.env.NEAR_AI_API_KEY = "test-key";
  try {
    const result = await checkScam(makeParams({
      rail: "x402",
      shape: {
        type: "x402",
        resourceUrl: "http://localhost:4021/weather",
        payTo: "0x9999999999999999999999999999999999999999",
        amount: "10000",
      },
      payee_history: [{ payee: "0xeea5e3bcc1e058aef9586a1c5c4cadc9cfdbc74f", amounts: ["5000"], last_seen: "2026-11-01" }],
    }));
    assert.equal(result.result, "suspicious");
    assert.match(result.reason!, /changed payTo/i);
  } finally {
    restoreEnv("NEAR_AI_API_KEY", prev);
  }
});

test("deterministic: amount spike is suspicious", async () => {
  const prev = process.env.NEAR_AI_API_KEY;
  process.env.NEAR_AI_API_KEY = "test-key";
  try {
    const result = await checkScam(makeParams({
      shape: {
        type: "payout",
        iban: "DE89370400440532013000",
        amount: "50000",
        timestamp: 1793700000,
      },
      payee_history: [{ payee: "DE89370400440532013000", amounts: ["10", "12", "11"], last_seen: "2026-11-01" }],
    }));
    assert.equal(result.result, "suspicious");
    assert.match(result.reason!, /amount spike/i);
  } finally {
    restoreEnv("NEAR_AI_API_KEY", prev);
  }
});

test("deterministic: known payee with normal amount passes pre-check", async () => {
  const prev = process.env.NEAR_AI_API_KEY;
  process.env.NEAR_AI_API_KEY = "test-key";
  const mockFetch = async () =>
    new Response(JSON.stringify({ choices: [{ message: { content: '{"result":"ok","reason":"all good"}' } }] }), { status: 200 });
  try {
    const result = await checkScam(makeParams({
      payee_history: [{ payee: "DE89370400440532013000", amounts: ["40", "45"], last_seen: "2026-11-01" }],
    }), { fetch: mockFetch as typeof globalThis.fetch });
    // Pre-checks pass → model called.
    assert.equal(result.result, "ok");
  } finally {
    restoreEnv("NEAR_AI_API_KEY", prev);
  }
});

test("timeout with injectable fetch", async () => {
  const prev = process.env.NEAR_AI_API_KEY;
  process.env.NEAR_AI_API_KEY = "test-key";
  try {
    const result = await checkScam(makeParams(), {
      timeoutMs: 50,
      fetch: async (url, init) => {
        await new Promise<void>((_, reject) => {
          const done = setTimeout(reject, 10_000, new Error("timeout fixture"));
          (init?.signal as AbortSignal)?.addEventListener("abort", () => {
            clearTimeout(done);
            reject(new DOMException("aborted", "AbortError"));
          });
        });
        return new Response("ok");
      },
    });
    assert.equal(result.result, "timeout");
    assert.equal(result.reason, null);
  } finally {
    restoreEnv("NEAR_AI_API_KEY", prev);
  }
});

test("API error returns suspicious not timeout", async () => {
  const prev = process.env.NEAR_AI_API_KEY;
  process.env.NEAR_AI_API_KEY = "test-key";
  try {
    const mockFetch = async () => new Response(null, { status: 401 });
    const result = await checkScam(makeParams(), { fetch: mockFetch as typeof globalThis.fetch });
    assert.equal(result.result, "suspicious");
    assert.match(result.reason!, /401/);
  } finally {
    restoreEnv("NEAR_AI_API_KEY", prev);
  }
});

test("held item with correct format", async () => {
  const prevKey = process.env.NEAR_AI_API_KEY;
  const prevDir = process.env.SCAMCHECK_HELD_DIR;
  const dir = mkdtempSync(join(tmpdir(), "scamcheck-test-"));
  process.env.SCAMCHECK_HELD_DIR = dir;
  process.env.NEAR_AI_API_KEY = "test-key";
  try {
    const mockFetch = async () =>
      new Response(JSON.stringify({ choices: [{ message: { content: '{"result":"ok","reason":"all good"}' } }] }), { status: 200 });
    const params = makeParams();
    const result = await checkAndHold(params, { fetch: mockFetch as typeof globalThis.fetch });

    assert.equal(result.status, "approved");
    assert.equal(result.verdict.result, "ok");
    assert.equal(result.item, undefined);

    // ok verdict → nothing written to disk
    const q = await readHeldQueue();
    assert.equal(q.length, 0);
  } finally {
    restoreEnv("SCAMCHECK_HELD_DIR", prevDir);
    restoreEnv("NEAR_AI_API_KEY", prevKey);
    rmSync(dir, { recursive: true, force: true });
  }
});

test("duplicate payee history aggregates amounts from all entries", async () => {
  const prev = process.env.NEAR_AI_API_KEY;
  process.env.NEAR_AI_API_KEY = "test-key";
  const mockFetch = async () =>
    new Response(JSON.stringify({ choices: [{ message: { content: '{"result":"ok","reason":"all good"}' } }] }), { status: 200 });
  try {
    // First entry alone: median=100, 60 < 500 → not suspicious → would pass with only first entry.
    // Both entries aggregated: [100,9,11] → median=11, 60 > 55 → suspicious.
    // The test fails without aggregating the second entry's amounts.
    const result = await checkScam(makeParams({
      shape: {
        type: "payout",
        iban: "DE89370400440532013000",
        amount: "60",
        timestamp: 1793700000,
      },
      payee_history: [
        { payee: "DE89370400440532013000", amounts: ["100"], last_seen: "2026-10-01" },
        { payee: "DE89370400440532013000", amounts: ["9", "11"], last_seen: "2026-11-01" },
      ],
    }), { fetch: mockFetch as typeof globalThis.fetch });
    assert.equal(result.result, "suspicious");
    assert.match(result.reason!, /amount spike/i);
  } finally {
    restoreEnv("NEAR_AI_API_KEY", prev);
  }
});

test("suspicious verdict writes held item to disk", async () => {
  const prevKey = process.env.NEAR_AI_API_KEY;
  const prevDir = process.env.SCAMCHECK_HELD_DIR;
  const dir = mkdtempSync(join(tmpdir(), "scamcheck-test-"));
  process.env.SCAMCHECK_HELD_DIR = dir;
  process.env.NEAR_AI_API_KEY = "test-key";
  try {
    const params = makeParams({
      invoice: { text: "URGENT: pay now", source: "email" },
    });
    const result = await checkAndHold(params);
    assert.equal(result.status, "held");
    assert.equal(result.verdict.result, "suspicious");
    assert.ok(result.item);

    const q = await readHeldQueue();
    assert.equal(q.length, 1);
    assert.equal(q[0].verdict.result, "suspicious");
    assert.equal(q[0].request_id, "inv-0001");
  } finally {
    restoreEnv("SCAMCHECK_HELD_DIR", prevDir);
    restoreEnv("NEAR_AI_API_KEY", prevKey);
    rmSync(dir, { recursive: true, force: true });
  }
});

test("IBAN with spaces matches the same IBAN without spaces", async () => {
  const prev = process.env.NEAR_AI_API_KEY;
  process.env.NEAR_AI_API_KEY = "test-key";
  const mockFetch = async () =>
    new Response(JSON.stringify({ choices: [{ message: { content: '{"result":"ok","reason":"all good"}' } }] }), { status: 200 });
  try {
    const result = await checkScam(makeParams({
      payee_history: [{ payee: "DE89 3704 0044 0532 0130 00", amounts: ["40", "45"], last_seen: "2026-11-01" }],
    }), { fetch: mockFetch as typeof globalThis.fetch });
    assert.equal(result.result, "ok");
  } finally {
    restoreEnv("NEAR_AI_API_KEY", prev);
  }
});

test("concurrent holds get distinct ids", async () => {
  const prevKey = process.env.NEAR_AI_API_KEY;
  const prevDir = process.env.SCAMCHECK_HELD_DIR;
  const dir = mkdtempSync(join(tmpdir(), "scamcheck-test-"));
  process.env.SCAMCHECK_HELD_DIR = dir;
  process.env.NEAR_AI_API_KEY = "test-key";
  try {
    const params = makeParams({ payee_known: false });
    const [a, b] = await Promise.all([checkAndHold(params), checkAndHold(params)]);
    assert.equal(a.status, "held");
    assert.equal(b.status, "held");
    assert.notEqual(a.item!.id, b.item!.id);

    const q = await readHeldQueue();
    assert.equal(q.length, 2);
    assert.equal(new Set(q.map(i => i.id)).size, 2);
  } finally {
    restoreEnv("SCAMCHECK_HELD_DIR", prevDir);
    restoreEnv("NEAR_AI_API_KEY", prevKey);
    rmSync(dir, { recursive: true, force: true });
  }
});

test("default held path is in the package dir, not the cwd", async () => {
  const prevDir = process.env.SCAMCHECK_HELD_DIR;
  const prevCwd = process.cwd();
  const cwd = mkdtempSync(join(tmpdir(), "scamcheck-cwd-"));
  delete process.env.SCAMCHECK_HELD_DIR;
  try {
    const pkgHeld = resolve(dirname(fileURLToPath(import.meta.url)), "..", ".held", "held.jsonl");
    assert.equal(heldPath(), pkgHeld);
    process.chdir(cwd);
    assert.equal(heldPath(), pkgHeld);
    // A relative SCAMCHECK_HELD_DIR is resolved against the package dir too.
    process.env.SCAMCHECK_HELD_DIR = "queue";
    assert.equal(heldPath(), resolve(dirname(pkgHeld), "..", "queue", "held.jsonl"));
  } finally {
    process.chdir(prevCwd);
    restoreEnv("SCAMCHECK_HELD_DIR", prevDir);
    rmSync(cwd, { recursive: true, force: true });
  }
});

test("IBAN with dashes matches the same IBAN without dashes", async () => {
  const prev = process.env.NEAR_AI_API_KEY;
  process.env.NEAR_AI_API_KEY = "test-key";
  const mockFetch = async () =>
    new Response(JSON.stringify({ choices: [{ message: { content: '{"result":"ok","reason":"all good"}' } }] }), { status: 200 });
  try {
    const result = await checkScam(makeParams({
      payee_history: [{ payee: "DE89-3704-0044-0532-0130-00", amounts: ["40", "45"], last_seen: "2026-11-01" }],
    }), { fetch: mockFetch as typeof globalThis.fetch });
    assert.equal(result.result, "ok");
  } finally {
    restoreEnv("NEAR_AI_API_KEY", prev);
  }
});

test("last_seen must be an ISO 8601 UTC date or timestamp", async () => {
  const prev = process.env.NEAR_AI_API_KEY;
  process.env.NEAR_AI_API_KEY = "test-key";
  const mockFetch = async () =>
    new Response(JSON.stringify({ choices: [{ message: { content: '{"result":"ok","reason":"all good"}' } }] }), { status: 200 });
  const run = (last_seen: string) => checkScam(makeParams({
    payee_history: [{ payee: "DE89370400440532013000", amounts: ["40", "45"], last_seen }],
  }), { fetch: mockFetch as typeof globalThis.fetch });
  try {
    for (const bad of ["02.11.2026", "2026-11-01T10:00:00+02:00", "2026-11-01T10:00:00", "2026-13-01"]) {
      const result = await run(bad);
      assert.equal(result.result, "suspicious", bad);
      assert.match(result.reason!, /last_seen/, bad);
    }
    for (const good of ["2026-11-01", "2026-11-01T10:00:00Z", "2026-11-01T10:00:00.123Z"]) {
      assert.equal((await run(good)).result, "ok", good);
    }
  } finally {
    restoreEnv("NEAR_AI_API_KEY", prev);
  }
});

test("last_seen holds impossible calendar dates that Date.parse would roll over", async () => {
  const prev = process.env.NEAR_AI_API_KEY;
  process.env.NEAR_AI_API_KEY = "test-key";
  const mockFetch = async () =>
    new Response(JSON.stringify({ choices: [{ message: { content: '{"result":"ok","reason":"all good"}' } }] }), { status: 200 });
  const run = (last_seen: string) => checkScam(makeParams({
    payee_history: [{ payee: "DE89370400440532013000", amounts: ["40", "45"], last_seen }],
  }), { fetch: mockFetch as typeof globalThis.fetch });
  try {
    for (const bad of ["2026-02-30", "2026-02-30T00:00:00Z", "2026-04-31", "2026-10-31T24:00:00Z"]) {
      const result = await run(bad);
      assert.equal(result.result, "suspicious", bad);
      assert.match(result.reason!, /last_seen/, bad);
    }
    for (const good of ["2024-02-29", "2026-10-31T23:59:59Z"]) {
      assert.equal((await run(good)).result, "ok", good);
    }
  } finally {
    restoreEnv("NEAR_AI_API_KEY", prev);
  }
});

test("last_seen more than a day in the future holds the request", async () => {
  const prev = process.env.NEAR_AI_API_KEY;
  process.env.NEAR_AI_API_KEY = "test-key";
  const mockFetch = async () =>
    new Response(JSON.stringify({ choices: [{ message: { content: '{"result":"ok","reason":"all good"}' } }] }), { status: 200 });
  // Fixed clock years away from the real one: the test fails if checkScam reads Date.now() instead of opts.now.
  const NOW = Date.parse("2030-06-15T12:00:00Z");
  const run = (last_seen: string) => checkScam(makeParams({
    payee_history: [{ payee: "DE89370400440532013000", amounts: ["40", "45"], last_seen }],
  }), { fetch: mockFetch as typeof globalThis.fetch, now: () => NOW });
  const iso = (offsetMs: number) => new Date(NOW + offsetMs).toISOString();
  try {
    for (const bad of ["2099-01-01", iso(25 * 3600_000), iso(24 * 3600_000 + 1)]) {
      const result = await run(bad);
      assert.equal(result.result, "suspicious", bad);
      assert.match(result.reason!, /last_seen.*future/, bad);
    }
    // Clock skew of up to a day is tolerated.
    for (const good of [iso(0), iso(23 * 3600_000), iso(24 * 3600_000), "2030-06-16"]) {
      assert.equal((await run(good)).result, "ok", good);
    }
  } finally {
    restoreEnv("NEAR_AI_API_KEY", prev);
  }
});
