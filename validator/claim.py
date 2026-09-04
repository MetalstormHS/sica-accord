"""Exclusive-claim registry — the Pauli-exclusion sketch.

A sketch (illustrative, not production) of one more check a governed
organisation can put at a hop: an exclusive claim. Some resources may be held
by at most one agent at a time — a task being worked, a role being filled, a
budget line being reserved. The analogy is the Pauli exclusion principle: no
two agents may occupy the same claim state at once.

The registry is fail-closed: a claim must first validate (schema + signature
against the trusted key ring) before it is admitted, and a second, different
signer on an already-held resource is refused.

Identity is derived from the *signing layer's key*, not from the free-text
``claimant`` field in the body. The ``claimant`` field, when present, is
checked against the identity mapped to the signer (``identities``); a
mismatch is refused, so no caller can simply assert someone else's name.

Mutual exclusion is enforced with an in-process lock, so two threads cannot
both observe a free resource and hold it. The lock does **not** provide
cross-process exclusion: a production deployment must back ``held`` with an
atomic store (e.g. a database unique constraint). This module is a sketch;
treat the exclusion as advisory outside a single process.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field

from validator import validate


@dataclass
class ClaimRegistry:
    """An exclusive-claim registry keyed by resource identifier.

    ``identities`` maps a layer label to the human-readable identity that
    layer is allowed to claim as. When omitted, a layer's own label is its
    identity. The ``held`` map keys resources to the *signer identity*
    derived from the key, never to unverified body text.

    The check-then-set on ``held`` is guarded by ``_lock`` (in-process only;
    see the module docstring for the cross-process caveat).
    """

    keyring: dict[str, str]
    schema: dict
    identities: dict[str, str] | None = None
    held: dict[str, str] = field(default_factory=dict)  # resource -> signer identity
    _lock: threading.Lock = field(
        default_factory=threading.Lock, init=False, repr=False
    )

    def register(self, body: dict, layers: list[dict]) -> dict:
        """Admit a signed claim if it validates and the resource is free.

        A claim must be signed by exactly one layer. Gives back
        ``{"status": "HELD", ...}`` on a fresh claim,
        ``{"status": "REFUSED", "reason": ...}`` otherwise. A claim for a
        resource already held by a different signer is refused
        (``CLAIM_CONFLICT``).
        """
        if type(layers) is not list or len(layers) != 1 or type(layers[0]) is not dict:
            return {"status": "REFUSED", "reason": "CLAIM_REQUIRES_ONE_LAYER"}

        # Exact-type: a dict subclass is refused by validate(), not laundered
        # here. layers[0] is already confirmed an exact dict, so reading its
        # "layer" is safe; the body is exact-type-checked by validate().
        signer = layers[0].get("layer")
        if not isinstance(signer, str):
            return {"status": "REFUSED", "reason": "CLAIM_REQUIRES_ONE_LAYER"}

        result = validate(
            body, self.schema, layers, self.keyring, expected_layers=[signer]
        )
        if not result.ok:
            return {"status": "REFUSED", "reason": result.reasons[0]}

        resource = body.get("resource")
        if resource is None:
            return {"status": "REFUSED", "reason": "CLAIM_MISSING_FIELD"}

        # Identity comes from the signing layer's key, not from the body.
        identity = (self.identities or {}).get(signer, signer)
        asserted = body.get("claimant")
        if asserted is not None and asserted != identity:
            return {
                "status": "REFUSED",
                "reason": f"CLAIMANT_KEY_MISMATCH:{asserted} != {identity}",
            }

        # Check-then-set is atomic under the lock (in-process only).
        with self._lock:
            existing = self.held.get(resource)
            if existing is not None and existing != identity:
                return {
                    "status": "REFUSED",
                    "reason": f"CLAIM_CONFLICT:{resource} held by {existing}",
                }
            self.held[resource] = identity
        return {
            "status": "HELD",
            "resource": resource,
            "claimant": identity,
            "sha256": result.digest,
        }
