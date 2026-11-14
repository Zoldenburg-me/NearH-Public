"""Tests for verify_attestation.py against the recorded testnet runs.
Run: python3 -I -m unittest discover -s spikes/outlayer -p 'test_*.py'
"""
import json, os, subprocess, sys, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
RUNS = os.path.join(HERE, "runs")
INPUT_14662 = '{"payee":"payee-1","nonce":"caller2.nearh-cc2-ol-1794222360.testnet:0"}'
PK_14662 = "62312c69d02acf6533bdd75ad80150c86dae83d6edd315b6d8aa72f5b3198b26"


def run(record, input_data, output):
    return subprocess.run(
        [sys.executable, "-I", os.path.join(HERE, "verify_attestation.py"),
         os.path.join(RUNS, record), input_data, os.path.join(RUNS, output)],
        capture_output=True, text=True)


class VerifyAttestation(unittest.TestCase):
    def test_bootstrap_output_is_pinned(self):
        r = run("attestation-req14662.json", INPUT_14662, "output-req14662.json")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("output_hash matches output: True", r.stdout)
        self.assertIn(f"pin: {PK_14662}", r.stdout)

    def test_substituted_bootstrap_output_is_refused(self):
        r = run("attestation-req14662.json", INPUT_14662, "output-req14662-forged.json")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("output_hash matches output: False", r.stdout)
        self.assertNotIn("pin:", r.stdout)
        with open(os.path.join(RUNS, "output-req14662-forged.json")) as f:
            forged = json.load(f)
        self.assertNotIn(forged["pk"], r.stdout)

    def test_output_with_trailing_newline_is_refused(self):
        with open(os.path.join(RUNS, "output-req14662.json"), "rb") as f:
            data = f.read()
        tmp = os.path.join(RUNS, ".tmp-output-newline.json")
        try:
            with open(tmp, "wb") as f:
                f.write(data + b"\n")
            r = run("attestation-req14662.json", INPUT_14662, os.path.basename(tmp))
        finally:
            os.remove(tmp)
        self.assertEqual(r.returncode, 1)
        self.assertNotIn("pin:", r.stdout)

    def test_wrong_input_is_refused(self):
        r = run("attestation-req14662.json", INPUT_14662.replace("payee-1", "payee-2"),
                "output-req14662.json")
        self.assertEqual(r.returncode, 1)
        self.assertNotIn("pin:", r.stdout)

    def test_v1_output_verifies_without_a_key(self):
        r = run("attestation-req14619.json", '{"payee":"payee-1"}', "output-req14619.json")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertNotIn("pin:", r.stdout)


if __name__ == "__main__":
    unittest.main()
