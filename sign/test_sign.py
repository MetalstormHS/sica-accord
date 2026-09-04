"""Tests for the canonical-hash and Ed25519 sign/verify layer."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sign import (  # noqa: E402
    CanonicalizationError,
    body_hash,
    canonical_bytes,
    generate_keypair,
    private_key_from_seed,
    sign_layer,
    signed_view,
    verify_layer,
)


class CanonicalRuleTests(unittest.TestCase):
    def test_sorted_keys_compact_separators(self):
        self.assertEqual(canonical_bytes({"b": 2, "a": 1}), b'{"a":1,"b":2}')

    def test_hash_is_order_independent(self):
        body = {"seq": 42, "note": "", "target": "workstation-07"}
        reordered = dict(reversed(list(body.items())))
        self.assertEqual(body_hash(body), body_hash(reordered))

    def test_nested_order_is_significant(self):
        a = {"k": [1, 2]}
        b = {"k": [2, 1]}
        self.assertNotEqual(canonical_bytes(a), canonical_bytes(b))

    def test_non_string_key_rejected(self):
        with self.assertRaises(CanonicalizationError):
            canonical_bytes({1: "a"})

    def test_int_and_string_key_no_longer_collide(self):
        # A string key is fine; the integer-key twin is refused, so the two
        # can never silently share bytes.
        self.assertEqual(canonical_bytes({"1": "a"}), b'{"1":"a"}')
        with self.assertRaises(CanonicalizationError):
            canonical_bytes({1: "a"})

    def test_nan_rejected(self):
        with self.assertRaises(CanonicalizationError):
            canonical_bytes({"x": float("nan")})

    def test_infinity_rejected(self):
        with self.assertRaises(CanonicalizationError):
            canonical_bytes({"x": float("inf")})
        with self.assertRaises(CanonicalizationError):
            canonical_bytes({"x": float("-inf")})

    def test_non_json_type_rejected(self):
        with self.assertRaises(CanonicalizationError):
            canonical_bytes({"x": (1, 2)})
        with self.assertRaises(CanonicalizationError):
            canonical_bytes({"x": b"bytes"})

    def test_float_rejected(self):
        # Floats have no language-independent canonical form (Python's repr
        # crosses from fixed to scientific notation, and 1 vs 1.0 differ), so
        # a governance contract forbids them outright.
        with self.assertRaises(CanonicalizationError):
            canonical_bytes({"x": 1.0})

    def test_ensure_ascii_escapes(self):
        # No Unicode normalisation is performed; non-ASCII is escaped.
        nfc = "\u00e9"
        nfd = "e\u0301"
        self.assertEqual(canonical_bytes({"s": nfc}), b'{"s":"\\u00e9"}')
        self.assertNotEqual(canonical_bytes({"s": nfc}), canonical_bytes({"s": nfd}))

    def test_dict_subclass_rejected(self):
        # A dict subclass is rejected (exact-type), not read — a lying items()
        # cannot inject duplicate keys into the signed bytes.
        class DupBody(dict):
            def items(self):
                return [("a", 1), ("a", 2)]

        d = DupBody()
        dict.__setitem__(d, "a", 1)
        with self.assertRaises(CanonicalizationError):
            canonical_bytes({"body": d})

    def test_list_subclass_rejected(self):
        # A list subclass is rejected (exact-type), not read.
        class LyingList(list):
            def __iter__(self):
                return iter([])

        lst = LyingList()
        list.append(lst, 1)
        list.append(lst, 2)
        with self.assertRaises(CanonicalizationError):
            canonical_bytes({"x": lst})

    def test_deep_nesting_refused(self):
        obj = {}
        cur = obj
        for _ in range(2000):
            cur["n"] = {}
            cur = cur["n"]
        with self.assertRaises(CanonicalizationError):
            canonical_bytes(obj)

    def test_cyclic_refused(self):
        obj = {}
        obj["self"] = obj
        with self.assertRaises(CanonicalizationError):
            canonical_bytes(obj)

    def test_large_integer_rejected(self):
        # 2**53 is the JS Number exact boundary: at it is accepted, beyond it
        # (2**53 + 1) a foreign verifier loses precision, so it is rejected.
        self.assertEqual(canonical_bytes({"n": 2**53}), b'{"n":9007199254740992}')
        with self.assertRaises(CanonicalizationError):
            canonical_bytes({"n": 2**53 + 1})

    def test_canonical_golden_vectors(self):
        import json

        root = Path(__file__).resolve().parent.parent
        data = json.loads(
            (root / "schema" / "canonical_golden.json").read_text(encoding="utf-8")
        )
        for case in data["cases"]:
            with self.subTest(name=case["name"]):
                self.assertEqual(
                    canonical_bytes(case["input"]).hex(), case["canonical_hex"]
                )


class SignVerifyTests(unittest.TestCase):
    def test_roundtrip(self):
        seed, pub_hex = generate_keypair()
        priv = private_key_from_seed(seed)
        body = {"seq": 42, "note": ""}
        env = sign_layer("L0", body, {"hop": 0}, priv)
        self.assertTrue(verify_layer(env, body, pub_hex))

    def test_body_drift_breaks_signature(self):
        seed, pub_hex = generate_keypair()
        priv = private_key_from_seed(seed)
        body = {"seq": 42, "note": ""}
        env = sign_layer("L0", body, {}, priv)
        drifted = {**body, "entry_class": None}
        self.assertFalse(verify_layer(env, drifted, pub_hex))

    def test_layer_fields_are_part_of_the_contract(self):
        seed, pub_hex = generate_keypair()
        priv = private_key_from_seed(seed)
        body = {"seq": 42}
        env = sign_layer("L0", body, {"verdict": "APPROVE"}, priv)
        env["layer_fields"] = {"verdict": "REJECT"}
        self.assertFalse(verify_layer(env, body, pub_hex))

    def test_wrong_key_fails(self):
        seed, pub_hex = generate_keypair()
        _, other_pub = generate_keypair()
        priv = private_key_from_seed(seed)
        body = {"seq": 42}
        env = sign_layer("L0", body, {}, priv)
        self.assertFalse(verify_layer(env, body, other_pub))

    def test_signed_view_splats_layer_fields(self):
        view = signed_view("L1", {"seq": 42}, {"hop": 2, "verdict": "APPROVE"})
        self.assertEqual(view["layer"], "L1")
        self.assertEqual(view["body"]["seq"], 42)
        self.assertEqual(view["hop"], 2)
        self.assertEqual(view["verdict"], "APPROVE")
        self.assertNotIn("layer_fields", view)

    def test_signed_view_rejects_reserved_body_key(self):
        with self.assertRaises(ValueError):
            signed_view("L0", {"seq": 42}, {"body": {"evil": True}})

    def test_signed_view_rejects_reserved_layer_key(self):
        with self.assertRaises(ValueError):
            signed_view("L0", {"seq": 42}, {"layer": "ADMIN"})

    def test_sign_layer_rejects_reserved_body_key(self):
        seed, _ = generate_keypair()
        priv = private_key_from_seed(seed)
        with self.assertRaises(ValueError):
            sign_layer("L0", {"seq": 42}, {"body": {"evil": True}}, priv)

    def test_sign_layer_rejects_reserved_layer_key(self):
        seed, _ = generate_keypair()
        priv = private_key_from_seed(seed)
        with self.assertRaises(ValueError):
            sign_layer("L0", {"seq": 42}, {"layer": "ADMIN"}, priv)

    def test_envelope_carries_no_unsigned_body_hash(self):
        seed, _ = generate_keypair()
        priv = private_key_from_seed(seed)
        env = sign_layer("L0", {"seq": 42}, {}, priv)
        self.assertNotIn("body_hash", env)

    def test_lying_dict_subclass_rejected_at_sign(self):
        # A dict subclass is refused at the boundary (exact-type): no subclass
        # can slip a reserved key past the guard via a lying __contains__.
        class Sneaky(dict):
            def __contains__(self, key):
                return False

        seed, _ = generate_keypair()
        priv = private_key_from_seed(seed)

        lf = Sneaky()
        dict.__setitem__(lf, "role", "orchestrator")
        dict.__setitem__(lf, "body", {"hidden": True})

        with self.assertRaises(TypeError):
            signed_view("L0", {"seq": 42}, lf)
        with self.assertRaises(TypeError):
            sign_layer("L0", {"seq": 42}, lf, priv)

    def test_malformed_inputs_return_false_not_raise(self):
        seed, pub = generate_keypair()
        priv = private_key_from_seed(seed)
        body = {"seq": 42}
        env = sign_layer("L0", body, {}, priv)
        # Malformed key hex, wrong-length key, None key, missing layer, bad
        # signature type: all return False, none raise.
        self.assertFalse(verify_layer(env, body, "zz"))
        self.assertFalse(verify_layer(env, body, "00"))
        self.assertFalse(verify_layer(env, body, None))
        self.assertFalse(verify_layer({"signature": env["signature"]}, body, pub))
        bad = dict(env)
        bad["signature"] = 123
        self.assertFalse(verify_layer(bad, body, pub))


if __name__ == "__main__":
    unittest.main()
