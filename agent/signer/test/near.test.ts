import { strict as assert } from "node:assert";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { it } from "node:test";
import { httpRpc, RpcError } from "../src/near.ts";

it("httpRpc fails a stalled NEAR RPC with a TIMEOUT_ERROR after its deadline", async (t) => {
  // Reads the request, then never answers.
  const server = createServer((req) => req.resume());
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
  t.after(() => { server.closeAllConnections(); server.close(); });
  const rpc = httpRpc(`http://127.0.0.1:${(server.address() as AddressInfo).port}`, 50);
  await assert.rejects(rpc("query", {}), (e) => e instanceof RpcError && e.isTimeout && /query: .*did not answer within 50 ms/.test(e.message));
});

it("httpRpc fails a NEAR RPC whose body stalls after its headers with a TIMEOUT_ERROR", async (t) => {
  // Sends the status line, headers and part of the JSON, then stalls.
  const server = createServer((req, res) => {
    req.resume();
    res.writeHead(200, { "content-type": "application/json" });
    res.write('{"jsonrpc":"2.0","id":1,');
  });
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
  t.after(() => { server.closeAllConnections(); server.close(); });
  const rpc = httpRpc(`http://127.0.0.1:${(server.address() as AddressInfo).port}`, 100);
  await assert.rejects(rpc("send_tx", {}), (e) => e instanceof RpcError && e.isTimeout && /send_tx: .*did not answer within 100 ms/.test(e.message));
});

it("httpRpc maps an AbortError from a timed-out body read to a TIMEOUT_ERROR", async (t) => {
  // Some fetch versions reject a body read cut off by the signal with AbortError, not TimeoutError.
  const realFetch = globalThis.fetch;
  // AbortSignal.timeout's timer is unref'd and the stub holds no socket: keep the event loop alive until the signal fires.
  const keepAlive = setTimeout(() => {}, 5_000);
  t.after(() => { globalThis.fetch = realFetch; clearTimeout(keepAlive); });
  globalThis.fetch = (async (_url: unknown, init?: RequestInit) => ({
    json: () => new Promise((_, reject) => init!.signal!.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")))),
  })) as unknown as typeof fetch;
  const rpc = httpRpc("http://127.0.0.1:1", 50);
  await assert.rejects(rpc("send_tx", {}), (e) => e instanceof RpcError && e.isTimeout);
});
