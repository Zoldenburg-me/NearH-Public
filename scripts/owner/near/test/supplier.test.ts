// Supplier helpers: exact euro caps, and the salt book that keeps a committed salt recoverable.
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { chmodSync, existsSync, lstatSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, statSync, symlinkSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { eurToBaseUnits, ibanCommitment, lockHooks, newSalt, reclaimStale, recordSalt, releaseLock, saltsFile, takeLock } from "../src/supplier.ts";

test("euro caps convert exactly to EURe base units, cents and beyond", () => {
  assert.equal(eurToBaseUnits("12"), "12000000000000000000");
  assert.equal(eurToBaseUnits("1.50"), "1500000000000000000");
  assert.equal(eurToBaseUnits("0.01"), "10000000000000000");
  assert.equal(eurToBaseUnits("0.000000000000000001"), "1");
  assert.equal(eurToBaseUnits("0.1"), "100000000000000000"); // no float drift
});

test("bad euro caps are rejected", () => {
  for (const bad of ["", "0", "0.00", "-1", "-1.5", "1.", ".5", "1,50", "1e3", " 1", "1.0000000000000000001", "abc"]) {
    assert.throws(() => eurToBaseUnits(bad), undefined, `accepted ${JSON.stringify(bad)}`);
  }
  assert.throws(() => eurToBaseUnits("340282366920938463464")); // above u128 in base units
});

test("recordSalt appends a 0600 line that reproduces the commitment", () => {
  const dir = mkdtempSync(join(tmpdir(), "salts-"));
  try {
    const file = join(dir, "supplier-salts.jsonl");
    writeFileSync(file, "", { mode: 0o644 }); // an existing, too-open file is tightened
    const iban = "DE89370400440532013000";
    const salt = newSalt();
    const commitment = ibanCommitment(iban, salt);
    recordSalt(file, { agent: "agent-1", supplier: "acme", iban, salt, commitment });
    recordSalt(file, { agent: "agent-1", supplier: "acme", iban, salt: newSalt(), commitment: "0x00" });
    assert.equal(statSync(file).mode & 0o777, 0o600);
    const lines = readFileSync(file, "utf8").trim().split("\n").map((l) => JSON.parse(l));
    assert.equal(lines.length, 2);
    assert.equal(ibanCommitment(lines[0].iban, lines[0].salt), commitment);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("recordSalt works in a searchable, writable but non-listable directory", { skip: process.getuid?.() === 0 }, () => {
  const dir = mkdtempSync(join(tmpdir(), "salts-"));
  try {
    const file = join(dir, "supplier-salts.jsonl");
    chmodSync(dir, 0o300);
    recordSalt(file, { agent: "agent-1", supplier: "acme", iban: "DE89370400440532013000", salt: newSalt(), commitment: "0x00" });
    chmodSync(dir, 0o700);
    assert.equal(JSON.parse(readFileSync(file, "utf8").trim()).supplier, "acme");
    assert.deepEqual(readdirSync(dir), ["supplier-salts.jsonl"]);
  } finally {
    chmodSync(dir, 0o700);
    rmSync(dir, { recursive: true, force: true });
  }
});

test("an existing world-readable salt book is never appended to in place", () => {
  const dir = mkdtempSync(join(tmpdir(), "salts-"));
  try {
    const file = join(dir, "supplier-salts.jsonl");
    writeFileSync(file, `${JSON.stringify({ supplier: "old" })}\n`, { mode: 0o644 });
    const inode = statSync(file).ino;
    recordSalt(file, { agent: "agent-1", supplier: "acme", iban: "DE89370400440532013000", salt: newSalt(), commitment: "0x00" });
    // A new 0600 inode means the IBAN was written to a private temp file and renamed in, never
    // into the old 0644 file; earlier lines are kept and no temp or lock file is left behind.
    assert.notEqual(statSync(file).ino, inode);
    assert.equal(statSync(file).mode & 0o777, 0o600);
    assert.deepEqual(readFileSync(file, "utf8").trim().split("\n").map((l) => JSON.parse(l).supplier), ["old", "acme"]);
    assert.deepEqual(readdirSync(dir), ["supplier-salts.jsonl"]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("concurrent owner scripts saving salts lose no entry", async () => {
  const dir = mkdtempSync(join(tmpdir(), "salts-"));
  try {
    const file = join(dir, "supplier-salts.jsonl");
    const mod = join(dirname(fileURLToPath(import.meta.url)), "../src/supplier.ts");
    const PROCS = 8;
    const EACH = 20;
    const script = `import { recordSalt } from ${JSON.stringify(mod)};
      for (let i = 0; i < ${EACH}; i++) recordSalt(process.env.BOOK, { agent: "a", supplier: process.env.WHO + "-" + i, iban: "DE89370400440532013000", salt: "0x00", commitment: "0x00" });`;
    const codes = await Promise.all(
      Array.from({ length: PROCS }, (_, p) => new Promise<number | null>((done) => {
        const child = spawn(process.execPath, ["--input-type=module", "-e", script], {
          env: { PATH: process.env.PATH, BOOK: file, WHO: `p${p}` },
          stdio: "inherit",
        });
        child.on("exit", done);
      })),
    );
    assert.deepEqual(codes, Array(PROCS).fill(0));
    const suppliers = new Set(readFileSync(file, "utf8").trim().split("\n").map((l) => JSON.parse(l).supplier));
    assert.equal(suppliers.size, PROCS * EACH);
    assert.deepEqual(readdirSync(dir), ["supplier-salts.jsonl"]); // no lock or temp left
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

const deadPid = () => spawnSync(process.execPath, ["-e", "process.stdout.write(String(process.pid))"], { encoding: "utf8" }).stdout;

/** A lock file holding `token`, last touched `ageMs` ago. */
function oldLock(path: string, token: string, ageMs: number): void {
  writeFileSync(path, token);
  const then = new Date(Date.now() - ageMs);
  utimesSync(path, then, then);
}

test("a lock left by a crashed script is recovered once it is stale", () => {
  const dir = mkdtempSync(join(tmpdir(), "salts-"));
  try {
    const file = join(dir, "supplier-salts.jsonl");
    oldLock(`${file}.lock`, `${deadPid()}:00`, 16_000);
    recordSalt(file, { agent: "a", supplier: "s", iban: "DE89370400440532013000", salt: newSalt(), commitment: "0x00" });
    assert.deepEqual(readdirSync(dir), ["supplier-salts.jsonl"]); // no lock or .stale left
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a stale lock whose PID now belongs to a live process is still recovered", () => {
  const dir = mkdtempSync(join(tmpdir(), "salts-"));
  try {
    const file = join(dir, "supplier-salts.jsonl");
    oldLock(`${file}.lock`, `${process.pid}:00`, 16_000); // the PID was reused by this live process
    recordSalt(file, { agent: "a", supplier: "s", iban: "DE89370400440532013000", salt: newSalt(), commitment: "0x00" });
    assert.deepEqual(readdirSync(dir), ["supplier-salts.jsonl"]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a fresh lock is never moved, even when its PID is dead", () => {
  const dir = mkdtempSync(join(tmpdir(), "salts-"));
  try {
    const lock = join(dir, "supplier-salts.jsonl.lock");
    oldLock(lock, `${deadPid()}:00`, 5_000);
    const inode = statSync(lock).ino;
    assert.equal(reclaimStale(lock), false);
    assert.equal(statSync(lock).ino, inode);
    assert.deepEqual(readdirSync(dir), ["supplier-salts.jsonl.lock"]);
    // A lock taken just now is left alone too; releasing it needs the holder's own token.
    rmSync(lock);
    const a = takeLock(lock);
    assert.equal(reclaimStale(lock), false);
    releaseLock(lock, `${process.pid}:ff`);
    assert.equal(readFileSync(lock, "utf8"), a);
    releaseLock(lock, a);
    assert.deepEqual(readdirSync(dir), []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a stale lock another waiter is reclaiming is left to it, and a dead reclaimer's guard is refused", () => {
  const dir = mkdtempSync(join(tmpdir(), "salts-"));
  try {
    const lock = join(dir, "supplier-salts.jsonl.lock");
    oldLock(lock, `${deadPid()}:00`, 16_000);
    oldLock(`${lock}.reclaim`, `${process.pid}:aa`, 0); // another waiter is mid-reclaim
    const inode = statSync(lock).ino;
    assert.equal(reclaimStale(lock), false);
    assert.equal(statSync(lock).ino, inode);
    oldLock(`${lock}.reclaim`, `${deadPid()}:aa`, 16_000); // that waiter died mid-reclaim
    assert.throws(() => reclaimStale(lock), /died while recovering/);
    assert.equal(statSync(lock).ino, inode);
    rmSync(`${lock}.reclaim`);
    assert.equal(reclaimStale(lock), true);
    assert.deepEqual(readdirSync(dir), []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// A review's interleaving, run step by step through the hooks rather than with timing:
// the reclaimer judges A's lock stale, A releases it, C takes a fresh lock, then the reclaimer moves on.
test("a reclaimer whose stale lock was released and retaken meanwhile puts the fresh lock back", () => {
  const dir = mkdtempSync(join(tmpdir(), "salts-"));
  try {
    const lock = join(dir, "supplier-salts.jsonl.lock");
    const a = `${deadPid()}:0:aa`;
    oldLock(lock, a, 16_000);
    let c = "";
    lockHooks.beforeMove = (why) => {
      if (why !== "reclaim") return;
      lockHooks.beforeMove = undefined;
      releaseLock(lock, a); // A was only paused, and releases its own lock
      c = takeLock(lock); // C takes the vacant path
    };
    try {
      assert.equal(reclaimStale(lock), false);
    } finally {
      lockHooks.beforeMove = undefined;
    }
    assert.ok(c);
    assert.equal(readFileSync(lock, "utf8"), c, "C's fresh lock was removed");
    assert.deepEqual(readdirSync(dir), ["supplier-salts.jsonl.lock"]); // no guard or tombstone left
    releaseLock(lock, c);
    assert.deepEqual(readdirSync(dir), []);
  } finally {
    lockHooks.beforeMove = undefined;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a fresh lock moved by mistake is never put back over a newer one; its holder loses it and writes nothing", () => {
  const dir = mkdtempSync(join(tmpdir(), "salts-"));
  try {
    const lock = join(dir, "supplier-salts.jsonl.lock");
    const a = `${deadPid()}:0:aa`;
    oldLock(lock, a, 16_000);
    let c = "";
    let d = "";
    lockHooks.beforeMove = (why) => {
      if (why !== "reclaim") return;
      lockHooks.beforeMove = undefined;
      releaseLock(lock, a);
      c = takeLock(lock);
    };
    lockHooks.afterMove = (why) => {
      if (why !== "reclaim") return;
      lockHooks.afterMove = undefined;
      d = takeLock(lock); // D takes the path while C's lock sits in the tombstone
    };
    try {
      assert.equal(reclaimStale(lock), false);
    } finally {
      lockHooks.beforeMove = lockHooks.afterMove = undefined;
    }
    assert.equal(readFileSync(lock, "utf8"), d, "D's lock was overwritten");
    assert.deepEqual(readdirSync(dir), ["supplier-salts.jsonl.lock"]);
    releaseLock(lock, c); // C has lost it: its release leaves D's lock alone
    assert.equal(readFileSync(lock, "utf8"), d);
  } finally {
    lockHooks.beforeMove = lockHooks.afterMove = undefined;
    rmSync(dir, { recursive: true, force: true });
  }
});

// The review's second interleaving: B releases while the reclaimer has B's fresh lock in its
// tombstone. The release must delete it there, or the reclaimer links back a lock nobody holds.
test("a lock released while a reclaimer has it moved aside is not put back", () => {
  const dir = mkdtempSync(join(tmpdir(), "salts-"));
  try {
    const lock = join(dir, "supplier-salts.jsonl.lock");
    const a = `${deadPid()}:0:aa`;
    oldLock(lock, a, 16_000);
    let b = "";
    lockHooks.beforeMove = (why) => {
      if (why !== "reclaim") return;
      lockHooks.beforeMove = undefined;
      releaseLock(lock, a);
      b = takeLock(lock);
    };
    lockHooks.afterMove = (why) => {
      if (why !== "reclaim") return;
      lockHooks.afterMove = undefined;
      assert.equal(existsSync(lock), false);
      releaseLock(lock, b); // B finishes while its lock sits in the tombstone
    };
    try {
      assert.equal(reclaimStale(lock), false);
    } finally {
      lockHooks.beforeMove = lockHooks.afterMove = undefined;
    }
    assert.ok(b);
    assert.deepEqual(readdirSync(dir), [], "a released lock was put back");
    const c = takeLock(lock); // and the next script takes it at once
    releaseLock(lock, c);
  } finally {
    lockHooks.beforeMove = lockHooks.afterMove = undefined;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a release that finds another script's lock after its check puts it back", () => {
  const dir = mkdtempSync(join(tmpdir(), "salts-"));
  try {
    const lock = join(dir, "supplier-salts.jsonl.lock");
    const a = takeLock(lock);
    let b = "";
    lockHooks.beforeMove = (why) => {
      if (why !== "release") return;
      lockHooks.beforeMove = undefined;
      rmSync(lock); // A's lock went stale and was reclaimed...
      b = takeLock(lock); // ...and B took the path
    };
    try {
      releaseLock(lock, a);
    } finally {
      lockHooks.beforeMove = undefined;
    }
    assert.equal(readFileSync(lock, "utf8"), b, "B's lock was removed");
    assert.deepEqual(readdirSync(dir), ["supplier-salts.jsonl.lock"]);
  } finally {
    lockHooks.beforeMove = undefined;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a holder whose lock was reclaimed writes nothing", () => {
  const dir = mkdtempSync(join(tmpdir(), "salts-"));
  try {
    const file = join(dir, "supplier-salts.jsonl");
    writeFileSync(file, `${JSON.stringify({ supplier: "old" })}\n`, { mode: 0o600 });
    // The child swaps in another script's lock while recordSalt reads the book: the stand-in for
    // a holder paused past the stale age whose lock a waiter reclaimed and took.
    const mod = join(dirname(fileURLToPath(import.meta.url)), "../src/supplier.ts");
    const script = `import fs from "node:fs"; import { syncBuiltinESMExports } from "node:module";
      const read = fs.readFileSync;
      fs.readFileSync = (p, ...r) => { const out = read(p, ...r); if (String(p).endsWith("/supplier-salts.jsonl")) fs.writeFileSync(p + ".lock", "1:other"); return out; };
      syncBuiltinESMExports();
      const { recordSalt } = await import(${JSON.stringify(mod)});
      recordSalt(process.env.BOOK, { agent: "a", supplier: "new", iban: "DE89370400440532013000", salt: "0x00", commitment: "0x00" });`;
    const r = spawnSync(process.execPath, ["--input-type=module", "-e", script], {
      encoding: "utf8",
      env: { PATH: process.env.PATH, BOOK: file },
    });
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /lost the salt book lock/);
    assert.equal(readFileSync(file, "utf8"), `${JSON.stringify({ supplier: "old" })}\n`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("concurrent scripts that all find the same stale lock lose no entry", async () => {
  const dir = mkdtempSync(join(tmpdir(), "salts-"));
  try {
    const file = join(dir, "supplier-salts.jsonl");
    const mod = join(dirname(fileURLToPath(import.meta.url)), "../src/supplier.ts");
    const PROCS = 8;
    const EACH = 10;
    for (let round = 0; round < 5; round++) {
      oldLock(`${file}.lock`, `${deadPid()}:00`, 16_000);
      // Each child waits for a shared start time so all of them meet the dead lock together.
      const start = Date.now() + 300;
      const script = `import { recordSalt } from ${JSON.stringify(mod)};
        while (Date.now() < ${start});
        for (let i = 0; i < ${EACH}; i++) recordSalt(process.env.BOOK, { agent: "a", supplier: process.env.WHO + "-" + i, iban: "DE89370400440532013000", salt: "0x00", commitment: "0x00" });`;
      const codes = await Promise.all(
        Array.from({ length: PROCS }, (_, p) => new Promise<number | null>((done) => {
          const child = spawn(process.execPath, ["--input-type=module", "-e", script], {
            env: { PATH: process.env.PATH, BOOK: file, WHO: `r${round}p${p}` },
            stdio: "inherit",
          });
          child.on("exit", done);
        })),
      );
      assert.deepEqual(codes, Array(PROCS).fill(0));
      assert.deepEqual(readdirSync(dir), ["supplier-salts.jsonl"]); // no lock, .stale or temp left
    }
    const suppliers = new Set(readFileSync(file, "utf8").trim().split("\n").map((l) => JSON.parse(l).supplier));
    assert.equal(suppliers.size, 5 * PROCS * EACH);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a symlinked salt book is written through to its target, and a dangling link is refused", () => {
  const dir = mkdtempSync(join(tmpdir(), "salts-"));
  try {
    const target = join(dir, "book.jsonl");
    const link = join(dir, "supplier-salts.jsonl");
    writeFileSync(target, `${JSON.stringify({ supplier: "old" })}\n`, { mode: 0o600 });
    symlinkSync(target, link);
    const entry = { agent: "a", supplier: "acme", iban: "DE89370400440532013000", salt: newSalt(), commitment: "0x00" };
    assert.equal(recordSalt(link, entry), realpathSync(target));
    assert.ok(lstatSync(link).isSymbolicLink(), "the link was replaced");
    assert.deepEqual(readFileSync(target, "utf8").trim().split("\n").map((l) => JSON.parse(l).supplier), ["old", "acme"]);
    rmSync(target);
    assert.throws(() => recordSalt(link, entry), /symlink to a missing file/);
    assert.ok(lstatSync(link).isSymbolicLink());
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a failed save removes its temp file and lock, and the temp name is gitignored", () => {
  const dir = mkdtempSync(join(tmpdir(), "salts-"));
  try {
    const file = join(dir, "salts.jsonl");
    writeFileSync(file, `${JSON.stringify({ supplier: "old" })}\n`, { mode: 0o600 });
    // A BigInt makes JSON.stringify throw after the temp file is open: a stand-in for any write error.
    const bad = { agent: "a", supplier: 1n, iban: "DE89370400440532013000", salt: newSalt(), commitment: "0x00" } as never;
    assert.throws(() => recordSalt(file, bad), TypeError);
    assert.deepEqual(readdirSync(dir), ["salts.jsonl"]);
    assert.equal(readFileSync(file, "utf8"), `${JSON.stringify({ supplier: "old" })}\n`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  const root = join(dirname(fileURLToPath(import.meta.url)), "../../../..");
  for (const p of ["demo/supplier-salts.0a1b2c3d4e5f.tmp.jsonl", "demo/supplier-salts.jsonl.lock"]) {
    const r = spawnSync("git", ["check-ignore", "-q", "--no-index", p], { cwd: root });
    assert.equal(r.status, 0, `${p} is not gitignored`);
  }
});

test("the salt book defaults to a private path outside the repo and can be overridden", () => {
  assert.equal(saltsFile({ HOME: "/home/o" }), "/home/o/.config/nearh/supplier-salts.jsonl");
  assert.equal(saltsFile({ HOME: "/home/o", XDG_CONFIG_HOME: "/cfg" }), "/cfg/nearh/supplier-salts.jsonl");
  assert.equal(saltsFile({ SUPPLIER_SALTS_FILE: "/tmp/x.jsonl" }), "/tmp/x.jsonl");
  const home = mkdtempSync(join(tmpdir(), "home-"));
  try {
    const file = recordSalt(saltsFile({ HOME: home }), { agent: "a", supplier: "s", iban: "DE89370400440532013000", salt: newSalt(), commitment: "0x00" });
    assert.equal(statSync(dirname(file)).mode & 0o777, 0o700);
    assert.equal(statSync(file).mode & 0o777, 0o600);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test("a salt book that lands in the repo is gitignored wherever it lands", () => {
  const root = join(dirname(fileURLToPath(import.meta.url)), "../../../..");
  for (const p of ["supplier-salts.jsonl", "scripts/owner/near/supplier-salts.jsonl", "demo/supplier-salts-old.jsonl"]) {
    const r = spawnSync("git", ["check-ignore", "-q", "--no-index", p], { cwd: root });
    assert.equal(r.status, 0, `${p} is not gitignored`);
  }
});

// The owner CLIs save the salt before the owner call, so a call that fails (here: the RPC is down,
// the stand-in for any failure after submit) still leaves the salt recoverable.
const CLI = join(dirname(fileURLToPath(import.meta.url)), "../src/cli");
const OFFLINE = `data:text/javascript,globalThis.fetch=async()=>{throw new Error("offline")}`;
for (const [cli, args] of [
  ["add-payee.ts", ["agent-1", "sepa", "acme", "Acme", "DE89370400440532013000", "1.50"]],
  ["change-supplier-iban.ts", ["agent-1", "acme", "DE89370400440532013000"]],
] as const) {
  test(`${cli} saves the salt before the owner call and keeps it when the call fails`, () => {
    const dir = mkdtempSync(join(tmpdir(), "salts-"));
    try {
      const file = join(dir, "salts.jsonl");
      const r = spawnSync(process.execPath, ["--import", OFFLINE, join(CLI, cli), ...args], {
        encoding: "utf8",
        env: { PATH: process.env.PATH, CONTRACT_ID: "c.testnet", OWNER_KEY_DIR: dir, SUPPLIER_SALTS_FILE: file },
      });
      assert.notEqual(r.status, 0, "the call should have failed");
      assert.match(r.stderr, /offline/);
      assert.equal(statSync(file).mode & 0o777, 0o600);
      const [line, ...more] = readFileSync(file, "utf8").trim().split("\n").map((l) => JSON.parse(l));
      assert.equal(more.length, 0);
      assert.equal(line.supplier, "acme");
      assert.equal(ibanCommitment(line.iban, line.salt), line.commitment);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
}
