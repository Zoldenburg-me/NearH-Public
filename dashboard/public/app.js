// DB1 dashboard page. Every value from the chain or the held queue goes into the DOM through
// textContent (el() below), never innerHTML: invoice text comes straight from inbound email.

import { b64, HELD_DECIDE_METHOD, heldDecideArgs, resolveArgs, revokeArgs, signOwnerCall } from "./owner.js";

const $ = (id) => document.getElementById(id);
const utf8 = new TextEncoder();
const DECIMALS = { x402: 6, sepa: 18 };
const TOKEN = { x402: "USDC", sepa: "EURe" };
const RAILS = ["x402", "sepa"];
/** Contract status → the label DB1 shows. `signed` is a request the mandate allowed. */
const STATUS_LABEL = { signed: "allowed", pending: "pending", unknown: "unknown", revoked: "revoked", spent: "spent", released: "released" };
const COUNTED = ["allowed", "held", "blocked", "pending", "unknown", "revoked", "spent", "released"];

let local; // /config.json: { contract_id, near_rpc, network }
let state = { agents: [], held: [] };
let busy = false;

function el(tag, props = {}, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "text") e.textContent = v;
    else if (k === "onclick") e.addEventListener("click", v);
    else if (k === "disabled") e.disabled = Boolean(v);
    else e.setAttribute(k, v);
  }
  for (const c of children) e.append(c ?? "");
  return e;
}

const badge = (label) => el("span", { class: `badge status-${label}`, "data-testid": "status", text: label });

function showError(msg) {
  $("errors").append(el("li", { text: msg }));
}

async function getJson(path) {
  const res = await fetch(path);
  const body = await res.json();
  if (!res.ok) throw new Error(`${path}: ${body.error ?? res.status}`);
  return body;
}

async function postJson(path, payload) {
  const res = await fetch(path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) });
  const body = await res.json();
  if (!res.ok) throw new Error(body.error ?? `${path}: HTTP ${res.status}`);
  return body;
}

async function rpc(method, params) {
  const res = await fetch(local.near_rpc, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: "dashboard", method, params }),
  });
  const body = await res.json();
  if (body.error) throw new Error(`${method}: ${JSON.stringify(body.error)}`);
  return body.result;
}

async function view(method, args) {
  const r = await rpc("query", {
    request_type: "call_function",
    finality: "final",
    account_id: local.contract_id,
    method_name: method,
    args_base64: b64(utf8.encode(JSON.stringify(args))),
  });
  if (r.error) throw new Error(`${method}: ${r.error}`);
  return JSON.parse(new TextDecoder().decode(Uint8Array.from(r.result)));
}

function formatUnits(amount, rail) {
  const d = DECIMALS[rail];
  if (d === undefined) return String(amount);
  const v = BigInt(amount);
  const whole = v / 10n ** BigInt(d);
  const frac = (v % 10n ** BigInt(d)).toString().padStart(d, "0").replace(/0+$/, "");
  return `${whole}${frac ? "." + frac : ""} ${TOKEN[rail]}`;
}

async function load() {
  $("errors").replaceChildren();
  local = await getJson("/config.json");
  if (local.network !== "testnet") throw new Error(`network must be testnet, got ${local.network}`);
  const status = await rpc("status", []);
  if (status?.chain_id !== local.network) throw new Error(`the NEAR RPC ${local.near_rpc} is on ${status?.chain_id}, not ${local.network}`);
  const config = await view("get_config", {});
  if (config.network !== local.network) throw new Error(`the contract is on ${config.network}, not ${local.network}`);
  $("contract").textContent = `${local.contract_id} · owner ${config.owner.mode} · owner_nonce ${config.owner_nonce}`;

  const agents = [];
  for (const record of await view("list_agents", { from_index: 0, limit: 100 })) {
    const a = { record, mandate: null, budgets: {}, requests: [] };
    agents.push(a);
    const step = async (what, fn) => {
      try {
        await fn();
      } catch (e) {
        showError(`${record.agent}: ${what}: ${e.message}`);
      }
    };
    await step("get_mandate", async () => (a.mandate = await view("get_mandate", { agent: record.agent })));
    for (const rail of RAILS) {
      await step(`get_budget ${rail}`, async () => (a.budgets[rail] = await view("get_budget", { agent: record.agent, rail })));
    }
    await step("list_requests", async () => (a.requests = await view("list_requests", { agent: record.agent, from_index: 0, limit: 100 })));
  }
  let held = [];
  try {
    const h = await getJson("/api/held");
    held = h.items;
    $("held-file").textContent = `reading ${h.file}`;
    h.errors.forEach(showError);
  } catch (e) {
    showError(`held queue: ${e.message}`);
  }
  state = { config, agents, held };
  render();
}

function render() {
  renderAgents();
  renderMandates();
  renderRequests();
  renderUnknown();
  renderHeld();
}

function renderAgents() {
  const rows = state.agents.map(({ record }) =>
    el(
      "tr",
      { "data-agent": record.agent },
      el("td", { text: record.agent }),
      el("td", {}, badge(record.revoked ? "revoked" : "active")),
      el("td", { text: record.evm_address ?? "" }),
      el("td", { text: record.linked ? "linked" : "not linked" }),
      // A revoked agent's DeleteKey may have failed (D1); revoking again retries it, or does
      // nothing if the key is already gone.
      el("td", {}, el("button", { type: "button", text: record.revoked ? "Retry key deletion" : "Revoke", onclick: (e) => revoke(record.agent, e.target) })),
    ),
  );
  $("agents").replaceChildren(el("tr", {}, ...["Agent", "Status", "EOA", "Link", ""].map((t) => el("th", { text: t }))), ...rows);
}

function renderMandates() {
  const blocks = state.agents.map(({ record, mandate, budgets }) => {
    if (!mandate) return el("p", { text: `${record.agent}: no mandate` });
    const rows = RAILS.map((rail) => {
      const m = mandate[rail];
      const b = budgets[rail];
      return el(
        "tr",
        { "data-rail": rail },
        el("td", { text: rail }),
        el("td", { text: `${formatUnits(m.amount_range.min, rail)} – ${formatUnits(m.amount_range.max, rail)}` }),
        el("td", { "data-testid": "budget", text: b ? `${formatUnits(b.reserved, rail)} of ${formatUnits(b.budget, rail)}` : "?" }),
        // The current window's length; a changed period_secs applies from the next window (D7).
        el("td", { text: `${(b?.period_secs ?? m.period_secs) / 86400} days` }),
      );
    });
    return el(
      "div",
      { "data-mandate": record.agent },
      el("h3", { text: record.agent }),
      el("table", {}, el("tr", {}, ...["Rail", "Per payment", "Used this period", "Period"].map((t) => el("th", { text: t }))), ...rows),
    );
  });
  $("mandates").replaceChildren(...blocks);
}

function renderRequests() {
  const counts = Object.fromEntries(COUNTED.map((s) => [s, 0]));
  const rows = [];
  for (const { requests } of state.agents) {
    for (const r of requests) {
      const label = STATUS_LABEL[r.status] ?? r.status;
      counts[label] = (counts[label] ?? 0) + 1;
      rows.push(
        el(
          "tr",
          { "data-request": r.key.request_id },
          el("td", { text: r.key.agent }),
          el("td", { text: r.key.request_id }),
          el("td", { text: r.shape }),
          el("td", { text: r.rail ? formatUnits(r.amount, r.rail) : "—" }),
          el("td", {}, badge(label)),
        ),
      );
    }
  }
  for (const h of state.held) {
    if (h.status === "held") counts.held++;
    if (h.status === "rejected") counts.blocked++;
  }
  $("counts").replaceChildren(...Object.entries(counts).map(([s, n]) => el("li", { "data-count": s }, badge(s), ` ${n}`)));
  $("requests").replaceChildren(el("tr", {}, ...["Agent", "Request", "Shape", "Amount", "Status"].map((t) => el("th", { text: t }))), ...rows);
}

function renderUnknown() {
  const nowSecs = Date.now() / 1000;
  const rows = [];
  for (const { requests } of state.agents) {
    for (const r of requests.filter((r) => r.status === "unknown")) {
      const early = nowSecs < r.release_after;
      rows.push(
        el(
          "tr",
          { "data-unknown": r.key.request_id },
          el("td", { text: `${r.key.agent} / ${r.key.request_id}` }),
          el("td", { text: r.rail ? formatUnits(r.amount, r.rail) : "—" }),
          el("td", {}, el("button", { type: "button", text: "Spent", onclick: (e) => resolve(r.key, "spent", e.target) })),
          el(
            "td",
            {},
            el("button", {
              type: "button",
              text: "Released",
              disabled: early,
              title: early ? `available after ${new Date(r.release_after * 1000).toISOString()}` : "",
              onclick: (e) => resolve(r.key, "released", e.target, r.release_after),
            }),
          ),
        ),
      );
    }
  }
  $("unknown").replaceChildren(...(rows.length ? rows : [el("tr", {}, el("td", { text: "No unknown reservations." }))]));
}

function renderHeld() {
  const items = state.held.map((h) => {
    const s = h.shape ?? {};
    const payee = s.iban ?? s.pay_to ?? s.payTo ?? s.requirements?.payTo ?? "";
    const buttons =
      h.status === "held"
        ? [
            el("button", { type: "button", text: "Approve", onclick: (e) => decide(h.id, "approved", e.target) }),
            el("button", { type: "button", text: "Reject", onclick: (e) => decide(h.id, "rejected", e.target) }),
          ]
        : [];
    return el(
      "div",
      { class: "held-item", "data-held-id": h.id },
      el("div", {}, badge(h.status), ` ${h.id} · ${h.agent} · ${h.rail} · ${h.request_id}`),
      el("div", { text: `${s.type ?? "?"} ${s.amount ?? ""} to ${payee}` }),
      el("div", { text: `memo: ${h.memo ?? ""}` }),
      el("pre", { "data-testid": "invoice", text: h.invoice?.text ?? "" }),
      el("div", { text: `verdict: ${h.verdict?.result ?? "?"}${h.verdict?.reason ? " — " + h.verdict.reason : ""}` }),
      el("div", {}, ...buttons),
    );
  });
  $("held").replaceChildren(...(items.length ? items : [el("p", { text: "The held queue is empty." })]));
}

/** A held decision, signed with the passkey for this id and status and the queue's next nonce. */
async function decide(id, status, button) {
  if (busy) return;
  busy = true;
  button.disabled = true;
  try {
    const config = await view("get_config", {});
    const { held_nonce } = await getJson("/api/held");
    const { assertion } = await signOwnerCall({
      config,
      contractId: local.contract_id,
      method: HELD_DECIDE_METHOD,
      args: { id, status },
      borshArgs: heldDecideArgs(id, status),
      credentials: navigator.credentials,
      origin: location.origin,
      nowMs: Date.now(),
      ownerNonce: held_nonce + 1,
    });
    await postJson("/api/held/decide", { id, status, assertion });
    await load();
  } catch (e) {
    showError(`${id}: ${e.message}`);
    button.disabled = false;
  } finally {
    busy = false;
  }
}

/** One signed owner call: reads owner_nonce fresh, signs with the passkey, relays, reloads. */
async function ownerCall(method, args, borshArgs, button) {
  if (busy) return;
  busy = true;
  button.disabled = true;
  try {
    const config = await view("get_config", {});
    const call = await signOwnerCall({
      config,
      contractId: local.contract_id,
      method,
      args,
      borshArgs,
      credentials: navigator.credentials,
      origin: location.origin,
      nowMs: Date.now(),
    });
    await postJson("/api/owner-call", call);
    await load();
  } catch (e) {
    showError(`${method}: ${e.message}`);
    button.disabled = false;
  } finally {
    busy = false;
  }
}

function revoke(agent, button) {
  return ownerCall("revoke", { agent }, revokeArgs(agent), button);
}

function resolve(key, outcome, button, releaseAfter = 0) {
  if (outcome === "released" && Date.now() / 1000 < releaseAfter) {
    showError(`${key.request_id}: Released is refused until ${new Date(releaseAfter * 1000).toISOString()}`);
    return;
  }
  return ownerCall("resolve_reservation", { key, outcome }, resolveArgs(key, outcome), button);
}

$("refresh").addEventListener("click", () => load().catch((e) => showError(e.message)));
load().catch((e) => showError(e.message));
// Enables Released once release_after passes without waiting for a refresh.
setInterval(() => state.agents.length && renderUnknown(), 15_000);
