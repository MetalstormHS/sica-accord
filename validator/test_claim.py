"""Tests for the exclusive-claim registry sketch."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sign import generate_keypair, private_key_from_seed, sign_layer  # noqa: E402
from validator.claim import ClaimRegistry  # noqa: E402

CLAIM_FIELDS = [
    "schema_name", "schema_version", "seq", "resource", "claimant",
    "intent", "timestamp",
]

IDENTITIES = {"L0": "orchestrator", "L1": "specialist"}


def _claim(seq, resource, claimant):
    return {
        "schema_name": "claim.v1",
        "schema_version": "1",
        "seq": seq,
        "resource": resource,
        "claimant": claimant,
        "intent": "probe",
        "timestamp": "2026-09-29T19:41:00+08:00",
    }


class ClaimRegistryTests(unittest.TestCase):
    def setUp(self):
        self.schema = {"frozen_fields": CLAIM_FIELDS}
        self.a_seed, self.a_pub = generate_keypair()
        self.b_seed, self.b_pub = generate_keypair()
        self.keyring = {"L0": self.a_pub, "L1": self.b_pub}

    def _reg(self):
        return ClaimRegistry(self.keyring, self.schema, identities=IDENTITIES)

    def _sign(self, body, layer, seed):
        return [sign_layer(layer, body, {}, private_key_from_seed(seed))]

    def test_first_claim_holds(self):
        reg = self._reg()
        body = _claim(1, "workstation-07", "orchestrator")
        out = reg.register(body, self._sign(body, "L0", self.a_seed))
        self.assertEqual(out["status"], "HELD")

    def test_conflicting_claim_refused(self):
        reg = self._reg()
        c1 = _claim(1, "workstation-07", "orchestrator")
        c2 = _claim(2, "workstation-07", "specialist")
        reg.register(c1, self._sign(c1, "L0", self.a_seed))
        out = reg.register(c2, self._sign(c2, "L1", self.b_seed))
        self.assertEqual(out["status"], "REFUSED")
        self.assertIn("CLAIM_CONFLICT", out["reason"])

    def test_distinct_resource_holds(self):
        reg = self._reg()
        c1 = _claim(1, "workstation-07", "orchestrator")
        c2 = _claim(2, "workstation-09", "specialist")
        reg.register(c1, self._sign(c1, "L0", self.a_seed))
        out = reg.register(c2, self._sign(c2, "L1", self.b_seed))
        self.assertEqual(out["status"], "HELD")

    def test_unvalidated_claim_refused(self):
        reg = self._reg()
        body = _claim(1, "workstation-07", "orchestrator")
        layers = self._sign(body, "L0", self.a_seed)
        body["extra"] = 1  # drift the body after signing
        out = reg.register(body, layers)
        self.assertEqual(out["status"], "REFUSED")

    def test_claimant_bound_to_key_mismatch_refused(self):
        # A body asserting "orchestrator" but signed by L1 (identity
        # "specialist") must be refused — identity comes from the key.
        reg = self._reg()
        body = _claim(1, "workstation-07", "orchestrator")
        out = reg.register(body, self._sign(body, "L1", self.b_seed))
        self.assertEqual(out["status"], "REFUSED")
        self.assertIn("CLAIMANT_KEY_MISMATCH", out["reason"])

    def test_zero_layers_refused(self):
        reg = self._reg()
        body = _claim(1, "workstation-07", "orchestrator")
        out = reg.register(body, [])
        self.assertEqual(out["status"], "REFUSED")
        self.assertIn("CLAIM_REQUIRES_ONE_LAYER", out["reason"])

    def test_two_layers_refused(self):
        reg = self._reg()
        body = _claim(1, "workstation-07", "orchestrator")
        layers = [
            sign_layer("L0", body, {}, private_key_from_seed(self.a_seed)),
            sign_layer("L1", body, {}, private_key_from_seed(self.b_seed)),
        ]
        out = reg.register(body, layers)
        self.assertEqual(out["status"], "REFUSED")
        self.assertIn("CLAIM_REQUIRES_ONE_LAYER", out["reason"])


if __name__ == "__main__":
    unittest.main()
