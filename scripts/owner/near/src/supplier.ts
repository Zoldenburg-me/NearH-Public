// Supplier IBAN commitments (PRIV1), as `contract/src/shapes/payout.rs` `iban_commitment`:
// sha256("nearh:iban-commitment:v1" || salt || iban), salt 32 bytes, IBAN as ASCII.

import { randomBytes } from "node:crypto";
import {
  chmodSync,
  closeSync,
  existsSync,
  fstatSync,
  fsyncSync,
  futimesSync,
  linkSync,
  lstatSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  statSync,
  writeSync,
} from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join } from "node:path";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, concatBytes, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";

const DOMAIN = utf8ToBytes("nearh:iban-commitment:v1");
const IBAN = /^[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}$/;
const SALT = /^0x[0-9a-fA-F]{64}$/;

/** `0x` plus 64 lowercase hex digits. */
export function ibanCommitment(iban: string, salt: string): string {
  if (!IBAN.test(iban)) throw new Error("iban must be uppercase without spaces");
  if (!SALT.test(salt)) throw new Error("salt must be 0x plus 64 hex digits");
  return `0x${bytesToHex(sha256(concatBytes(DOMAIN, hexToBytes(salt.slice(2)), utf8ToBytes(iban))))}`;
}

/** A fresh random salt, one per supplier IBAN. */
export function newSalt(): string {
  return `0x${randomBytes(32).toString("hex")}`;
}

const EURE_DECIMALS = 18;
const U128_MAX = (1n << 128n) - 1n;

/** A positive euro amount ("12", "1.50", up to 18 decimals) as exact EURe base units; no floats. */
export function eurToBaseUnits(eur: string): string {
  const m = /^([0-9]+)(?:\.([0-9]{1,18}))?$/.exec(eur);
  if (!m) throw new Error(`cap must be a positive euro amount with at most ${EURE_DECIMALS} decimals`);
  const units = BigInt(m[1]) * 10n ** BigInt(EURE_DECIMALS) + BigInt((m[2] ?? "").padEnd(EURE_DECIMALS, "0"));
  if (units === 0n || units > U128_MAX) throw new Error("cap must be above zero and fit in a u128");
  return units.toString();
}

/**
 * Where `recordSalt` writes: `SUPPLIER_SALTS_FILE`, else `$XDG_CONFIG_HOME/nearh/supplier-salts.jsonl`
 * (default `~/.config/nearh/`), outside the repo so no working directory leaves it committable.
 */
export function saltsFile(env: NodeJS.ProcessEnv = process.env): string {
  if (env.SUPPLIER_SALTS_FILE) return env.SUPPLIER_SALTS_FILE;
  const config = env.XDG_CONFIG_HOME || join(env.HOME || homedir(), ".config");
  return join(config, "nearh", "supplier-salts.jsonl");
}

// A lock older than LOCK_STALE_MS was left by a crashed script (a save takes milliseconds), whatever
// has become of its PID; waiters outlast that age, so they recover it instead of timing out.
const LOCK_STALE_MS = 15_000;
const LOCK_WAIT_MS = 20_000;

/**
 * Adds one line to the owner's private salt book (mode 0600) before the owner call is sent, so
 * a committed salt survives a failed check or an interrupted run. An existing book is tightened
 * to 0600 first, and the new book is written to a 0600 temp file and renamed over the old one,
 * so the IBAN is never readable by others, even mid-write. A `.lock` file next to the book makes
 * concurrent owner scripts take turns, so no entry is lost. A symlinked book is written through
 * to its target. The temp file is named `supplier-salts.*.tmp.jsonl`, so the repo-wide ignore
 * rule covers it if a run is killed mid-write. Returns the book's real path.
 */
export function recordSalt(
  file: string,
  entry: { agent: string; supplier: string; iban: string; salt: string; commitment: string },
): string {
  const book = realBook(file);
  mkdirSync(dirname(book), { recursive: true, mode: 0o700 });
  const lock = `${book}.lock`;
  const token = takeLock(lock);
  try {
    let before = "";
    if (existsSync(book)) {
      chmodSync(book, 0o600);
      before = readFileSync(book, "utf8");
    }
    refreshLock(lock, token);
    const tmp = join(dirname(book), `supplier-salts.${randomBytes(6).toString("hex")}.tmp.jsonl`);
    const fd = openSync(tmp, "wx", 0o600);
    try {
      try {
        chmodSync(tmp, 0o600); // the umask can only narrow it; this makes 0600 explicit
        writeSync(fd, `${before}${JSON.stringify({ ...entry, at: new Date().toISOString() })}\n`);
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
      refreshLock(lock, token); // a slow fsync may have let the lock go stale; never rename after losing it
      renameSync(tmp, book);
    } catch (e) {
      rmSync(tmp, { force: true });
      throw e;
    }
  } finally {
    releaseLock(lock, token);
  }
  return book;
}

/** The book's target if `file` is a symlink, so the rename replaces the target, not the link. */
function realBook(file: string): string {
  try {
    return realpathSync(file);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e;
    let link = false;
    try {
      link = lstatSync(file).isSymbolicLink();
    } catch {}
    if (link) throw new Error(`salt book ${file} is a symlink to a missing file; fix the link or SUPPLIER_SALTS_FILE`);
    return file; // a new book
  }
}

/**
 * Takes `lock`, waiting with backoff, and returns this holder's token (`pid:time:nonce`, unique to
 * this take). A lock older than `LOCK_STALE_MS` is removed by `reclaimStale`, which never removes
 * a fresh lock.
 */
export function takeLock(lock: string): string {
  const deadline = Date.now() + LOCK_WAIT_MS;
  for (let wait = 5; ; wait = Math.min(wait * 2, 200)) {
    const token = placeLock(lock);
    if (token) return token;
    if (reclaimStale(lock)) continue;
    if (Date.now() > deadline) {
      throw new Error(`salt book is locked by another owner script; if none is running, remove ${lock}`);
    }
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, wait + Math.random() * wait);
  }
}

/**
 * Removes `lock` only if it still holds `token`, so a holder never removes another's lock. A
 * missing lock is not taken as released: a reclaimer may have it in a tombstone, about to link
 * it back. So the holder also deletes any tombstone holding its token, which makes that link
 * fail, and looks at the path again in case the link landed first.
 */
export function releaseLock(lock: string, token: string): void {
  for (let pass = 0; pass < 4; pass++) {
    let found = false;
    if (readLock(lock) === token) {
      found = true;
      lockHooks.beforeMove?.("release", lock);
      removeIfHolds(lock, token, `release.${randomBytes(6).toString("hex")}`, false);
    }
    if (dropTombstones(lock, token)) found = true;
    if (!found) return;
  }
}

/** Deletes reclaim tombstones of `lock` that hold `token`; true if one was found. */
function dropTombstones(lock: string, token: string): boolean {
  const prefix = `${basename(lock)}.reclaim.`;
  let found = false;
  let names: string[];
  try {
    names = readdirSync(dirname(lock));
  } catch (e) {
    // A searchable but non-listable directory: the book is already saved, so don't fail the
    // release. Tombstones can't be found here; a leftover one only ever ages out as stale.
    const code = (e as NodeJS.ErrnoException).code;
    if (code === "EACCES" || code === "EPERM") return false;
    throw e;
  }
  for (const name of names) {
    if (!name.startsWith(prefix)) continue;
    const tomb = join(dirname(lock), name);
    if (readLock(tomb) !== token) continue;
    const mine = `${lock}.release.${randomBytes(6).toString("hex")}`;
    try {
      renameSync(tomb, mine); // the reclaimer's tombstone is gone, so its link back fails
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "ENOENT") continue;
      throw e;
    }
    found = true;
    if (readLock(mine) === token) rmSync(mine, { force: true });
    else renameSync(mine, tomb);
  }
  return found;
}

/**
 * Fails if `lock` no longer holds `token` (it went stale and was reclaimed), else marks it fresh.
 * The time is set through the open file, so it lands on the lock whose token was read, and the
 * path must still name that file afterwards.
 */
function refreshLock(lock: string, token: string): void {
  const lost = () => new Error("lost the salt book lock; nothing was written, run again");
  let fd: number;
  try {
    fd = openSync(lock, "r");
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") throw lost();
    throw e;
  }
  try {
    if (readFileSync(fd, "utf8") !== token) throw lost();
    const now = new Date();
    futimesSync(fd, now, now);
    let ino: number | undefined;
    try {
      ino = statSync(lock).ino;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e;
    }
    if (ino !== fstatSync(fd).ino) throw lost();
  } finally {
    closeSync(fd);
  }
}

/**
 * Removes a stale `lock` and returns true, so the caller can take it; false if it is fresh or
 * another waiter is reclaiming it. Reclaimers take turns through `${lock}.reclaim`, made the
 * same exclusive way as the lock, and read the lock's token and age again once they hold it.
 * The lock is never removed by path: it is renamed to a tombstone only this reclaimer names,
 * and the tombstone is deleted only if it holds the token judged stale and is still stale.
 * Anything else (the judged lock was released and a fresh one taken in between) is linked back
 * at once; if a newer lock took the path meanwhile, the link fails and the moved lock's holder
 * fails its next check, so it writes nothing. The guard is held for a few syscalls; one older
 * than `LOCK_STALE_MS` means a script died mid-reclaim, and is left for the owner to remove.
 */
export function reclaimStale(lock: string): boolean {
  if (!isStale(lock)) return !existsSync(lock);
  const guard = `${lock}.reclaim`;
  const mine = placeLock(guard);
  if (!mine) {
    if (isStale(guard)) throw new Error(`a script died while recovering the salt book lock; if none is running, remove ${guard}`);
    return false;
  }
  try {
    const judged = readLock(lock); // the token first, then the age, so a stale age is never pinned on a newer token
    if (judged === null) return true; // released meanwhile
    if (!isStale(lock)) return !existsSync(lock); // reclaimed and retaken meanwhile, or released
    lockHooks.beforeMove?.("reclaim", lock);
    return removeIfHolds(lock, judged, `reclaim.${mine.split(":")[2]}`, true);
  } finally {
    releaseLock(guard, mine);
  }
}

/**
 * Test seam: called just before a lock is moved to its tombstone and just after, so a test can
 * run another script's steps at exactly those points. Unset in normal runs.
 */
export const lockHooks: {
  beforeMove?: (why: "reclaim" | "release", lock: string) => void;
  afterMove?: (why: "reclaim" | "release", lock: string) => void;
} = {};

/**
 * Renames `lock` to `${lock}.${tag}` and deletes it only if it holds `token` (and, when `stale`,
 * is still stale); anything else is linked back to `lock`, which fails safely if a newer lock is
 * there. True if the path was vacated of the lock with `token`, or was already vacant.
 */
function removeIfHolds(lock: string, token: string, tag: string, stale: boolean): boolean {
  const tomb = `${lock}.${tag}`;
  try {
    renameSync(lock, tomb);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return true;
    throw e;
  }
  try {
    lockHooks.afterMove?.(stale ? "reclaim" : "release", lock);
    if (readLock(tomb) === token && (!stale || isStale(tomb))) return true;
    try {
      linkSync(tomb, lock);
    } catch (e) {
      // EEXIST: a newer lock took the path. ENOENT: the holder released it from the tombstone.
      const code = (e as NodeJS.ErrnoException).code;
      if (code !== "EEXIST" && code !== "ENOENT") throw e;
    }
    return false;
  } finally {
    rmSync(tomb, { force: true });
  }
}

/** True if `path` exists and was last touched more than `LOCK_STALE_MS` ago. */
function isStale(path: string): boolean {
  try {
    return Date.now() - statSync(path).mtimeMs >= LOCK_STALE_MS;
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw e;
  }
}

/** Creates `path` holding a fresh token, complete before it appears (a hard link fails if it exists); null if taken. */
function placeLock(path: string): string | null {
  const token = `${process.pid}:${Date.now()}:${randomBytes(8).toString("hex")}`;
  const tmp = `${path}.${randomBytes(6).toString("hex")}`;
  const fd = openSync(tmp, "wx", 0o600);
  try {
    writeSync(fd, token);
  } finally {
    closeSync(fd);
  }
  try {
    linkSync(tmp, path);
    return token;
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
    return null;
  } finally {
    rmSync(tmp, { force: true });
  }
}

function readLock(path: string): string | null {
  try {
    return readFileSync(path, "utf8");
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw e;
  }
}
