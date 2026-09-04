"""Tests for the hop validator."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sign import (  # noqa: E402
    body_hash,
    generate_keypair,
    private_key_from_seed,
    sign_layer,
)
from validator import validate  # noqa: E402

CHAIN = ["L0", "L1"]


def _sign(body, layer, fields, seed):
    return sign_layer(layer, body, fields, private_key_from_seed(seed))


class ValidatorTests(unittest.TestCase):
    def setUp(self):
        self.schema = {"frozen_fields": ["seq", "note", "target"]}
        self.body = {"seq": 42, "note": "", "target": "workstation-07"}
        self.l0_seed, self.l0_pub = generate_keypair()
        self.l1_seed, self.l1_pub = generate_keypair()
        self.keyring = {"L0": self.l0_pub, "L1": self.l1_pub}

    def _chain(self):
        l0 = _sign(self.body, "L0", {"hop": 0}, self.l0_seed)
        l1 = _sign(self.body, "L1", {"hop": 1}, self.l1_seed)
        return [l0, l1]

    def _l0(self):
        return _sign(self.body, "L0", {"hop": 0}, self.l0_seed)

    def _l1(self):
        return _sign(self.body, "L1", {"hop": 1}, self.l1_seed)

    # --- regression: the pristine two-hop card still accepts ---
    def test_pristine_accepts(self):
        result = validate(self.body, self.schema, self._chain(), self.keyring,
                          expected_layers=CHAIN)
        self.assertTrue(result.ok, result.reasons)

    def test_missing_expected_layers_refused(self):
        # No expected chain named: the safe default is refusal, even for a
        # card that would otherwise be a well-formed full chain.
        result = validate(self.body, self.schema, self._chain(), self.keyring)
        self.assertFalse(result.ok)
        self.assertIn("NO_EXPECTED_LAYERS", result.reasons)

    # --- schema freeze (regression) ---
    def test_extra_field_rejects(self):
        drifted = {**self.body, "entry_class": None}
        result = validate(drifted, self.schema, self._chain(), self.keyring,
                          expected_layers=CHAIN)
        self.assertFalse(result.ok)
        self.assertIn("SCHEMA_EXTRA_FIELD:entry_class", result.reasons)

    def test_missing_field_rejects(self):
        dropped = {k: v for k, v in self.body.items() if k != "target"}
        result = validate(dropped, self.schema, self._chain(), self.keyring,
                          expected_layers=CHAIN)
        self.assertFalse(result.ok)
        self.assertIn("SCHEMA_MISSING_FIELD:target", result.reasons)

    # --- signatures (regression) ---
    def test_flipped_signature_rejects(self):
        l0, l1 = self._chain()
        first = int(l1["signature"][:2], 16)
        l1["signature"] = f"{first ^ 0x01:02x}" + l1["signature"][2:]
        result = validate(self.body, self.schema, [l0, l1], self.keyring,
                          expected_layers=CHAIN)
        self.assertFalse(result.ok)
        self.assertIn("INVALID_SIGNATURE L1", result.reasons)

    def test_unknown_layer_rejects(self):
        l0 = self._l0()
        result = validate(self.body, self.schema, [l0], {"L1": self.l1_pub},
                          expected_layers=["L0"])
        self.assertFalse(result.ok)
        self.assertIn("MISSING_PUBKEY:L0", result.reasons)

    def test_wrong_key_rejects(self):
        l0 = self._l0()
        result = validate(self.body, self.schema, [l0], {"L0": self.l1_pub},
                          expected_layers=["L0"])
        self.assertFalse(result.ok)
        self.assertIn("INVALID_SIGNATURE L0", result.reasons)

    def test_manifest_hash_mismatch_rejects(self):
        result = validate(self.body, self.schema, self._chain(), self.keyring,
                          manifest_hash="0" * 64, expected_layers=CHAIN)
        self.assertFalse(result.ok)
        self.assertTrue(any("BODY_HASH_MISMATCH" in r for r in result.reasons))

    # --- C1: chain shape ---
    def test_empty_layers_refused(self):
        result = validate(self.body, self.schema, [], self.keyring,
                          expected_layers=CHAIN)
        self.assertFalse(result.ok)

    def test_empty_layers_refused_without_expected(self):
        result = validate(self.body, self.schema, [], self.keyring)
        self.assertFalse(result.ok)
        self.assertIn("NO_EXPECTED_LAYERS", result.reasons)

    def test_only_downstream_hop_refused(self):
        result = validate(self.body, self.schema, [self._l1()], self.keyring,
                          expected_layers=CHAIN)
        self.assertFalse(result.ok)
        self.assertIn("MISSING_LAYER:L0", result.reasons)

    def test_only_upstream_hop_refused(self):
        result = validate(self.body, self.schema, [self._l0()], self.keyring,
                          expected_layers=CHAIN)
        self.assertFalse(result.ok)
        self.assertIn("MISSING_LAYER:L1", result.reasons)

    def test_reversed_layer_order_refused(self):
        result = validate(self.body, self.schema, [self._l1(), self._l0()],
                          self.keyring, expected_layers=CHAIN)
        self.assertFalse(result.ok)
        self.assertIn("LAYER_OUT_OF_ORDER", result.reasons)

    def test_duplicated_layer_refused(self):
        result = validate(self.body, self.schema, [self._l0(), self._l0()],
                          self.keyring, expected_layers=CHAIN)
        self.assertFalse(result.ok)
        self.assertIn("DUPLICATE_LAYER:L0", result.reasons)

    def test_duplicated_layer_refused_without_expected(self):
        result = validate(self.body, self.schema, [self._l0(), self._l0()],
                          self.keyring)
        self.assertFalse(result.ok)
        self.assertIn("NO_EXPECTED_LAYERS", result.reasons)

    def test_unexpected_extra_layer_refused(self):
        extra_seed, extra_pub = generate_keypair()
        l2 = _sign(self.body, "L2", {"hop": 2}, extra_seed)
        keyring = {"L0": self.l0_pub, "L1": self.l1_pub, "L2": extra_pub}
        result = validate(self.body, self.schema,
                          [self._l0(), self._l1(), l2], keyring,
                          expected_layers=CHAIN)
        self.assertFalse(result.ok)
        self.assertIn("UNEXPECTED_LAYER:L2", result.reasons)

    # --- C2: signature replay / reserved keys ---
    def test_replay_signature_over_different_body_refused(self):
        # A legit signature over a harmless body is replayed onto a malicious
        # body by injecting {"body": harmless} into layer_fields.
        harmless = self.body
        malicious = {**harmless, "target": "workstation-99"}
        legit = _sign(harmless, "L0", {"role": "orchestrator"}, self.l0_seed)
        forged = {
            "layer": "L0",
            "body_hash": body_hash(malicious),  # attacker-set, unsigned
            "signature": legit["signature"],
            "layer_fields": {"role": "orchestrator", "body": harmless},
            "pub_hex": legit["pub_hex"],
        }
        result = validate(malicious, self.schema, [forged], {"L0": self.l0_pub},
                          expected_layers=["L0"])
        self.assertFalse(result.ok)
        self.assertTrue(
            any("reserved_key_in_layer_fields" in r for r in result.reasons)
        )

    def test_plain_body_swap_refused(self):
        # Even without a reserved-key override, replaying a signature onto a
        # different body must fail signature verification.
        malicious = {**self.body, "target": "workstation-99"}
        legit = _sign(self.body, "L0", {"role": "orchestrator"}, self.l0_seed)
        result = validate(malicious, self.schema, [legit], {"L0": self.l0_pub},
                          expected_layers=["L0"])
        self.assertFalse(result.ok)
        self.assertIn("INVALID_SIGNATURE L0", result.reasons)

    def test_layer_fields_containing_body_refused(self):
        # The sign side refuses to *produce* such an envelope (signed_view
        # raises), so forge one to exercise the verify-side guard.
        legit = _sign(self.body, "L0", {"role": "orchestrator"}, self.l0_seed)
        forged = {
            "layer": "L0",
            "signature": legit["signature"],
            "layer_fields": {"role": "orchestrator", "body": self.body},
            "pub_hex": legit["pub_hex"],
        }
        result = validate(self.body, self.schema, [forged], {"L0": self.l0_pub},
                          expected_layers=["L0"])
        self.assertFalse(result.ok)
        self.assertTrue(
            any("reserved_key_in_layer_fields" in r for r in result.reasons)
        )

    def test_layer_fields_containing_layer_refused(self):
        legit = _sign(self.body, "L0", {"role": "orchestrator"}, self.l0_seed)
        forged = {
            "layer": "L0",
            "signature": legit["signature"],
            "layer_fields": {"role": "orchestrator", "layer": "ADMIN"},
            "pub_hex": legit["pub_hex"],
        }
        result = validate(self.body, self.schema, [forged], {"L0": self.l0_pub},
                          expected_layers=["L0"])
        self.assertFalse(result.ok)
        self.assertTrue(
            any("reserved_key_in_layer_fields" in r for r in result.reasons)
        )

    def test_lying_dict_subclass_refused_at_validate(self):
        # A forged envelope whose layer_fields is a dict subclass is refused at
        # the boundary (exact-type): the validator does not trust a subclass.
        class Sneaky(dict):
            def __contains__(self, key):
                return False

        legit = _sign(self.body, "L0", {"role": "orchestrator"}, self.l0_seed)
        sneaky = Sneaky()
        dict.__setitem__(sneaky, "role", "orchestrator")
        dict.__setitem__(sneaky, "body", self.body)
        forged = {
            "layer": "L0",
            "signature": legit["signature"],
            "layer_fields": sneaky,
            "pub_hex": legit["pub_hex"],
        }
        result = validate(self.body, self.schema, [forged], {"L0": self.l0_pub},
                          expected_layers=["L0"])
        self.assertFalse(result.ok)
        self.assertIn("MALFORMED_LAYER:0", result.reasons)

    def test_lying_envelope_get_refused(self):
        # A dict subclass envelope (overriding .get) is refused at the boundary
        # (exact-type), so a lying .get cannot substitute a clean layer_fields.
        class LyingEnv(dict):
            def get(self, key, default=None):
                if key == "layer_fields":
                    return {}
                return dict.get(self, key, default)

        legit = _sign(self.body, "L0", {"role": "orchestrator"}, self.l0_seed)
        env = LyingEnv()
        dict.__setitem__(env, "layer", "L0")
        dict.__setitem__(env, "signature", legit["signature"])
        dict.__setitem__(env, "layer_fields", {"body": self.body})
        dict.__setitem__(env, "pub_hex", legit["pub_hex"])

        result = validate(self.body, self.schema, [env], {"L0": self.l0_pub},
                          expected_layers=["L0"])
        self.assertFalse(result.ok)
        self.assertIn("MALFORMED_LAYER:0", result.reasons)

    def test_lying_body_refused(self):
        # The v4 finding: a dict-subclass BODY whose accessors diverge from its
        # storage. The signature must cover exactly the value acted on, so a
        # subclass body is refused outright rather than signed-then-misread.
        class LyingBody(dict):
            def get(self, key, default=None):
                if key == "target":
                    return "ws-MALICIOUS"
                return dict.get(self, key, default)

        liar = LyingBody()
        dict.__setitem__(liar, "seq", 42)
        dict.__setitem__(liar, "note", "")
        dict.__setitem__(liar, "target", "workstation-07")

        env = _sign(self.body, "L0", {"role": "orchestrator"}, self.l0_seed)
        result = validate(liar, self.schema, [env], {"L0": self.l0_pub},
                          expected_layers=["L0"])
        self.assertFalse(result.ok)
        self.assertIn("MALFORMED_BODY", result.reasons)

    def test_json_roundtrip_documents_wire_vs_api(self):
        # API level: a lying dict subclass is refused outright (see the sibling
        # test). On the WIRE, a JSON round-trip collapses the subclass into a
        # plain dict with the reserved key as a plain string — still refused.
        # This pins the distinction: the wire was always closed; the API now is.
        import json

        class Sneaky(dict):
            def __contains__(self, key):
                return False

        legit = _sign(self.body, "L0", {"role": "orchestrator"}, self.l0_seed)
        sneaky = Sneaky()
        dict.__setitem__(sneaky, "role", "orchestrator")
        dict.__setitem__(sneaky, "body", self.body)
        forged = {
            "layer": "L0",
            "signature": legit["signature"],
            "layer_fields": sneaky,
            "pub_hex": legit["pub_hex"],
        }

        api_result = validate(self.body, self.schema, [forged],
                              {"L0": self.l0_pub}, expected_layers=["L0"])
        self.assertFalse(api_result.ok)

        wire = json.loads(json.dumps(forged))
        self.assertIs(type(wire["layer_fields"]), dict)  # normalised to plain dict
        wire_result = validate(self.body, self.schema, [wire],
                               {"L0": self.l0_pub}, expected_layers=["L0"])
        self.assertFalse(wire_result.ok)
        self.assertTrue(
            any("reserved_key_in_layer_fields" in r for r in wire_result.reasons)
        )

    # --- M3: canonical body ---
    def test_non_string_key_in_body_refused(self):
        result = validate({**self.body, 1: "x"}, self.schema, self._chain(),
                          self.keyring, expected_layers=CHAIN)
        self.assertFalse(result.ok)
        self.assertIn("NON_CANONICAL_BODY", result.reasons[0])

    def test_nan_in_body_refused(self):
        result = validate({**self.body, "note": float("nan")}, self.schema,
                          self._chain(), self.keyring, expected_layers=CHAIN)
        self.assertFalse(result.ok)
        self.assertIn("NON_CANONICAL_BODY", result.reasons[0])

    def test_infinity_in_body_refused(self):
        result = validate({**self.body, "note": float("inf")}, self.schema,
                          self._chain(), self.keyring, expected_layers=CHAIN)
        self.assertFalse(result.ok)
        self.assertIn("NON_CANONICAL_BODY", result.reasons[0])

    # --- M2: malformed input refuses, never raises ---
    def test_malformed_envelope_missing_layer_refused(self):
        result = validate(self.body, self.schema, [{"signature": "ab"}],
                          self.keyring, expected_layers=CHAIN)
        self.assertFalse(result.ok)
        self.assertIn("MALFORMED_LAYER:0", result.reasons)

    def test_malformed_envelope_null_layer_fields_refused(self):
        env = self._l0()
        env["layer_fields"] = None
        result = validate(self.body, self.schema, [env], self.keyring,
                          expected_layers=CHAIN)
        self.assertFalse(result.ok)
        self.assertIn("MALFORMED_LAYER:0", result.reasons)

    def test_malformed_envelope_wrong_type_signature_refused(self):
        env = self._l0()
        env["signature"] = 123
        result = validate(self.body, self.schema, [env], self.keyring,
                          expected_layers=CHAIN)
        self.assertFalse(result.ok)
        self.assertIn("MALFORMED_LAYER:0", result.reasons)

    def test_malformed_keyring_bad_hex_refused(self):
        result = validate(self.body, self.schema, self._chain(),
                          {"L0": "zz", "L1": self.l1_pub}, expected_layers=CHAIN)
        self.assertFalse(result.ok)
        self.assertIn("MALFORMED_PUBKEY:L0", result.reasons)

    def test_malformed_keyring_wrong_length_refused(self):
        result = validate(self.body, self.schema, self._chain(),
                          {"L0": "00", "L1": self.l1_pub}, expected_layers=CHAIN)
        self.assertFalse(result.ok)
        self.assertIn("MALFORMED_PUBKEY:L0", result.reasons)

    def test_malformed_keyring_none_refused(self):
        result = validate(self.body, self.schema, self._chain(),
                          {"L0": None, "L1": self.l1_pub}, expected_layers=CHAIN)
        self.assertFalse(result.ok)
        self.assertIn("MALFORMED_PUBKEY:L0", result.reasons)

    def test_body_none_refused(self):
        result = validate(None, self.schema, self._chain(), self.keyring,
                          expected_layers=CHAIN)
        self.assertFalse(result.ok)
        self.assertIn("MALFORMED_BODY", result.reasons)

    def test_schema_missing_frozen_fields_refused(self):
        result = validate(self.body, {}, self._chain(), self.keyring,
                          expected_layers=CHAIN)
        self.assertFalse(result.ok)
        self.assertIn("MALFORMED_SCHEMA", result.reasons)

    def test_bad_expected_layers_spec_raises(self):
        # A malformed chain spec is a programmer error, not a card problem.
        with self.assertRaises(ValueError):
            validate(self.body, self.schema, self._chain(), self.keyring,
                     expected_layers=[])
        with self.assertRaises(ValueError):
            validate(self.body, self.schema, self._chain(), self.keyring,
                     expected_layers=["L0", "L0"])


if __name__ == "__main__":
    unittest.main()
