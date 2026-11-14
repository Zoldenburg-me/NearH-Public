"""Off-chain check of one OutLayer attestation record (runs/attestation-*.json).

Recomputes the V1 task hash the worker puts in TDX REPORTDATA
(worker/src/tdx_attestation.rs in out-layer/outlayer) and compares it with
quote bytes [568:600]. Also checks input_hash against the input we sent and
output_hash against the worker stdout we were handed (the bootstrap output
that carries `pk`), byte for byte. Prints `pin: <pk>` only if every check
passes; otherwise exits 1 and prints no key to pin.
It does NOT verify the quote's Intel signature chain or the measurements
(that needs dcap-qvl + Intel collateral); see RESULT.md.
Usage: python3 -I verify_attestation.py <record.json> '<input_data>' <output-file>
  <output-file>: the worker stdout exactly as returned (no trailing newline).
"""
import base64, hashlib, json, sys


def report_data(rec):
    h = hashlib.sha256()
    h.update(rec["task_type"].encode())
    h.update(rec["task_id"].to_bytes(8, "little", signed=True))
    for k in ("build_target", "wasm_hash", "input_hash"):
        if rec.get(k):
            h.update(rec[k].encode())
    h.update(rec["output_hash"].encode())
    h.update(rec["block_height"].to_bytes(8, "little"))
    for k in ("caller_account_id", "project_id", "secrets_ref"):
        if rec.get(k):
            h.update(rec[k].encode())
    h.update(rec["timestamp"].to_bytes(8, "little", signed=True))
    if rec.get("attached_usd") is not None:
        h.update(str(rec["attached_usd"]).encode())
    return h.digest()


def check(rec, input_data, output):
    """Returns (checks, pk). pk is set only if all checks pass and the output has one."""
    quote = base64.b64decode(rec["tdx_quote"])
    checks = {
        "report_data binds task fields": report_data(rec) == quote[568:600],
        "input_hash matches input": hashlib.sha256(input_data.encode()).hexdigest() == rec["input_hash"],
        "output_hash matches output": hashlib.sha256(output).hexdigest() == rec["output_hash"],
        "executed wasm == pinned hash": rec["executed_wasm_sha256"] == rec["wasm_hash"],
    }
    pk = None
    if all(checks.values()):
        pk = json.loads(output).get("pk") or None
    return checks, pk


def main(argv):
    with open(argv[1]) as f:
        rec = json.load(f)
    with open(argv[3], "rb") as f:
        output = f.read()
    checks, pk = check(rec, argv[2], output)
    for name, ok in checks.items():
        print(f"{name}:", ok)
    print("wasm_hash:", rec["wasm_hash"])
    print("worker_measurement:", rec["worker_measurement"])
    # Five measurements from the TD report body (quote v4: 48-byte header, MRTD at 184,
    # RTMR0..3 at 376/424/472/520), for is_measurements_approved on worker.outlayer.testnet.
    quote = base64.b64decode(rec["tdx_quote"])
    m = {k: quote[o:o + 48].hex() for k, o in
         (("mrtd", 184), ("rtmr0", 376), ("rtmr1", 424), ("rtmr2", 472), ("rtmr3", 520))}
    print("measurements:", json.dumps({"measurements": m}))
    if not all(checks.values()):
        print("FAIL: do not pin any key from this output")
        return 1
    if pk:
        print("pin:", pk)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
