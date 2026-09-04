"""The fail-closed door.

A gate that acts on a card only after it has itself validated the card.
On ACCEPT the door acts (here: records an acknowledgement). On REJECT the
door refuses and records nothing. The door is fail-closed: it owns the
validation step rather than trusting a caller-supplied verdict, and it never
repairs, fills in, or guesses.
"""
from __future__ import annotations

from validator import validate


class Door:
    """A fail-closed gate. Validates each card itself and acts only on a
    card that validates exactly.

    ``expected_layers`` is **required**: the door has no default chain and
    will not act on a card without an expected layer sequence to enforce.
    """

    def __init__(
        self,
        schema: dict,
        keyring: dict[str, str],
        expected_layers: list[str],
        manifest_hash: str | None = None,
        inbox: list[dict] | None = None,
    ) -> None:
        self.schema = schema
        self.keyring = keyring
        self.expected_layers = expected_layers
        self.manifest_hash = manifest_hash
        self.inbox: list[dict] = inbox if inbox is not None else []

    def admit(self, body: dict, layers: list[dict]) -> dict:
        """Validate a card and admit it, or refuse it.

        The door re-runs ``validate()`` against the card it is given, so an
        ACK can only be produced for a card that actually validates under the
        door's own schema, key ring, and expected chain.

        Gives back ``{"status": "ACK", ...}`` on ACCEPT and
        ``{"status": "REFUSED", "reason": ...}`` on REJECT. Only an ACK is
        recorded in the inbox.
        """
        result = validate(
            body,
            self.schema,
            layers,
            self.keyring,
            manifest_hash=self.manifest_hash,
            expected_layers=self.expected_layers,
        )
        if not result.ok:
            reason = result.reasons[0] if result.reasons else "VALIDATION_FAILED"
            return {"status": "REFUSED", "reason": reason}

        ack = {
            "status": "ACK",
            "card_id": result.card_id,
            "sha256": result.digest,
        }
        self.inbox.append(ack)
        return ack
