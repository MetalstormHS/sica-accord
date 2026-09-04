"""Tests for the fail-closed door."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sign import generate_keypair, private_key_from_seed, sign_layer  # noqa: E402
from validator.door import Door  # noqa: E402

SCHEMA = {"frozen_fields": ["seq", "note", "target"]}
CHAIN = ["L0", "L1"]


class DoorTests(unittest.TestCase):
    def setUp(self):
        self.body = {"seq": 42, "note": "", "target": "workstation-07"}
        self.l0_seed, self.l0_pub = generate_keypair()
        self.l1_seed, self.l1_pub = generate_keypair()
        self.keyring = {"L0": self.l0_pub, "L1": self.l1_pub}

    def _chain(self):
        l0 = sign_layer("L0", self.body, {"hop": 0},
                        private_key_from_seed(self.l0_seed))
        l1 = sign_layer("L1", self.body, {"hop": 1},
                        private_key_from_seed(self.l1_seed))
        return [l0, l1]

    def test_admits_validated_card(self):
        door = Door(schema=SCHEMA, keyring=self.keyring, expected_layers=CHAIN)
        ack = door.admit(self.body, self._chain())
        self.assertEqual(ack["status"], "ACK")
        self.assertEqual(len(door.inbox), 1)

    def test_refuses_drifted_card(self):
        door = Door(schema=SCHEMA, keyring=self.keyring, expected_layers=CHAIN)
        drifted = {**self.body, "entry_class": None}
        out = door.admit(drifted, self._chain())
        self.assertEqual(out["status"], "REFUSED")
        self.assertEqual(len(door.inbox), 0)

    def test_refuses_empty_chain(self):
        door = Door(schema=SCHEMA, keyring=self.keyring, expected_layers=CHAIN)
        out = door.admit(self.body, [])
        self.assertEqual(out["status"], "REFUSED")
        self.assertEqual(len(door.inbox), 0)

    def test_refuses_stripped_chain(self):
        door = Door(schema=SCHEMA, keyring=self.keyring, expected_layers=CHAIN)
        l0 = self._chain()[0]
        out = door.admit(self.body, [l0])
        self.assertEqual(out["status"], "REFUSED")
        self.assertEqual(len(door.inbox), 0)

    def test_requires_expected_chain(self):
        # The door must not act without an expected chain: it is a required
        # constructor argument, so a missing chain is a construction error.
        with self.assertRaises(TypeError):
            Door(schema=SCHEMA, keyring=self.keyring)

    def test_refuses_lying_body(self):
        # A dict-subclass body whose accessors diverge from its storage: the
        # signature must cover exactly the value acted on, so the door refuses
        # a subclass body rather than ACKing a card whose "target" reads wrong.
        class LyingBody(dict):
            def get(self, key, default=None):
                if key == "target":
                    return "ws-MALICIOUS"
                return dict.get(self, key, default)

        liar = LyingBody()
        dict.__setitem__(liar, "seq", 42)
        dict.__setitem__(liar, "note", "")
        dict.__setitem__(liar, "target", "workstation-07")

        door = Door(schema=SCHEMA, keyring=self.keyring, expected_layers=CHAIN)
        out = door.admit(liar, self._chain())
        self.assertEqual(out["status"], "REFUSED")
        self.assertEqual(len(door.inbox), 0)


if __name__ == "__main__":
    unittest.main()
