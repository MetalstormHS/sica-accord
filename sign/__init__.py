"""Canonical hash and Ed25519 sign/verify for SICA Accord.

This is the shared signing layer. Every signer and verifier in the system
must agree byte-for-byte on the canonical encoding of a body; otherwise a
signature produced at one hop will not verify at the next.

The canonical rule is pinned in full in ``schema/README.md`` and exercised by
the golden vectors in ``schema/canonical_golden.json``. In one line: JSON
with sorted keys, compact separators, ``ensure_ascii=True`` (RFC 8259 string
escaping), integers bounded to |n| <= 2**53, and **no floats**. See
``canonical_bytes``.

The contract signs *parsed objects*, not raw JSON text: duplicate keys in a
source document collapse at parse time before anything is signed, and no
Unicode normalisation is applied.

Boundary rule — exact types only. A ``dict``/``list`` subclass can override
``__contains__``, ``get``, ``items``, ``keys`` or ``__iter__`` so that a guard
reads one value while a later splat or serialisation reads another. Rather
than normalise subclasses (which relies on incidental CPython behaviour),
every container — ``layer_fields``, the envelope, and every dict/list in the
signed material — must be an exact ``dict``/``list``. A ``type(x) is dict``
object has no overridable methods, so the value that is SIGNED is necessarily
the value that is READ and ACTED ON. JSON parsing always yields exact
dicts/lists, so this costs nothing on the wire.

Layer fields are SPLATTED into the signed view (``{"layer", "body",
**layer_fields}``) — never nested under their own key — so the exact field
set of the signed view is part of the contract. The reserved keys ``layer``
and ``body`` may not appear inside ``layer_fields``: ``signed_view`` raises
``ValueError`` at sign time, and the validator refuses them at verify time.

Dependency: ``cryptography`` (Ed25519). Python 3.11 or later.
"""
from __future__ import annotations

import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


class CanonicalizationError(ValueError):
    """Raised when a value cannot be canonically encoded.

    Subclasses ``ValueError`` so callers that already catch ``ValueError``
    (for example ``verify_layer``) keep their existing semantics: a
    non-canonical input is a refusal, never a silent encoding.
    """


# Reserved layer-field keys. A ``layer_fields`` dict carrying either of
# these would shadow the signed view's own ``layer``/``body`` keys via the
# splat in ``signed_view``, letting a signature made over one body verify
# against another. Rejected at both sign and verify time.
RESERVED_LAYER_FIELD_KEYS = ("layer", "body")

# Integers must satisfy |n| <= 2**53: that is the exact range a JavaScript
# Number (IEEE 754 double) can represent, so a foreign verifier parsing a
# larger integer loses precision and produces different canonical bytes.
MAX_SAFE_INTEGER = 2**53


def _require_plain(obj: object) -> object:
    """Return ``obj`` as a fresh plain-JSON structure, rejecting anything else.

    Exact-type rule: dicts and lists must be *exact* ``dict``/``list`` — a
    subclass is rejected because it can override ``items``/``__iter__``/``get``
    and make a guard and a later serialisation disagree. Rejects non-string
    mapping keys, floats (a governance contract uses integers and strings,
    never floats), integers outside |n| <= 2**53, and any non-JSON type.
    Returns a fresh structure this module owns.
    """
    if isinstance(obj, dict):
        if type(obj) is not dict:
            raise CanonicalizationError(
                f"dict subclass is not permitted: {type(obj).__name__}"
            )
        out: dict = {}
        for key, value in obj.items():
            if not isinstance(key, str):
                raise CanonicalizationError(f"non-string mapping key: {key!r}")
            out[key] = _require_plain(value)
        return out
    if isinstance(obj, list):
        if type(obj) is not list:
            raise CanonicalizationError(
                f"list subclass is not permitted: {type(obj).__name__}"
            )
        return [_require_plain(value) for value in obj]
    if isinstance(obj, bool):
        return obj
    if isinstance(obj, int):
        if abs(obj) > MAX_SAFE_INTEGER:
            raise CanonicalizationError(
                f"integer out of safe range (|n| <= 2**53): {obj!r}"
            )
        return obj
    if isinstance(obj, float):
        raise CanonicalizationError(
            f"floats are not permitted in the canonical contract: {obj!r}"
        )
    if isinstance(obj, str) or obj is None:
        return obj
    raise CanonicalizationError(
        f"value is not JSON-encodable: {type(obj).__name__}"
    )


def canonical_bytes(obj: dict) -> bytes:
    """Encode a mapping under the canonical rule.

    Verifies the object is a plain JSON structure (see ``_require_plain``),
    then serialises with sorted keys, compact separators, ``ensure_ascii=True``
    (RFC 8259 string escaping) and ``allow_nan=False``. This is the
    byte-for-byte contract shared by every signer and verifier. Do not
    change it. The full rule, including the sort domain, the escape table and
    the integer bound, is pinned in ``schema/README.md``.

    Raises ``CanonicalizationError`` for any input with no single portable
    encoding: dict/list subclasses, non-string keys, floats, integers beyond
    |n| <= 2**53, non-JSON types, or input too deep/cyclic to encode.
    """
    try:
        plain = _require_plain(obj)
        return json.dumps(
            plain, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False,
        ).encode("utf-8")
    except RecursionError:
        raise CanonicalizationError(
            "input is too deeply nested or cyclic to encode"
        ) from None


def body_hash(body: dict) -> str:
    """The sha256 hex digest of the canonical body bytes."""
    return hashlib.sha256(canonical_bytes(body)).hexdigest()


def short_hash(hexdigest: str, n: int = 12) -> str:
    """The first ``n`` hex characters — the invariant printed at each hop."""
    return hexdigest[:n]


def generate_keypair() -> tuple[bytes, str]:
    """Generate a fresh Ed25519 keypair.

    Gives back ``(seed, pub_hex)`` where ``seed`` is the raw 32-byte private
    seed and ``pub_hex`` the hex public key.
    """
    priv = Ed25519PrivateKey.generate()
    seed = priv.private_bytes_raw()
    pub_hex = priv.public_key().public_bytes_raw().hex()
    return seed, pub_hex


def private_key_from_seed(seed: bytes) -> Ed25519PrivateKey:
    """Reconstruct a private key from a raw 32-byte seed."""
    return Ed25519PrivateKey.from_private_bytes(seed)


def public_key_from_hex(pub_hex: str) -> Ed25519PublicKey:
    """Reconstruct a public key from its hex form."""
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex.strip()))


def _require_plain_dict(obj: object, name: str) -> dict:
    """Require ``obj`` to be an exact ``dict`` and return it unchanged.

    Exact-type rule: a ``dict`` subclass is rejected because it can override
    ``__contains__``/``get``/``items``/``keys`` and make a guard disagree with
    a later splat. ``type(obj) is dict`` guarantees no override can exist, so
    no copy is needed — the object and every read of it agree.

    Raises ``TypeError`` if ``obj`` is not an exact dict.
    """
    if type(obj) is not dict:
        raise TypeError(f"{name} must be a plain dict, not {type(obj).__name__}")
    return obj


def reserved_keys_in_layer_fields(layer_fields: object) -> list[str]:
    """The reserved keys present in ``layer_fields``.

    Requires an exact dict first (so ``in`` cannot be lied to), then checks.
    Returns the offending reserved keys (empty list when none).
    """
    fields = _require_plain_dict(layer_fields, "layer_fields")
    return [k for k in RESERVED_LAYER_FIELD_KEYS if k in fields]


def signed_view(layer: str, body: dict, layer_fields: dict) -> dict:
    """Build the exact mapping that is signed for one layer.

    Layer fields are SPLATTED into the view — never nested under their own
    key. This is the SET-contract rule: the signed field set is the body
    plus the layer's own fields, and that exact set is what the verifier
    must reconstruct.

    ``layer_fields`` must be an exact ``dict`` (no subclass), so the
    reserved-key guard and the merge read the same value.

    Raises ``ValueError`` if ``layer_fields`` contains a reserved key
    (``layer`` or ``body``), which would otherwise shadow the fields the
    signature is meant to bind.
    """
    fields = _require_plain_dict(layer_fields, "layer_fields")
    offending = [k for k in RESERVED_LAYER_FIELD_KEYS if k in fields]
    if offending:
        raise ValueError(f"reserved key in layer_fields: {sorted(offending)}")
    return {"layer": layer, "body": body, **fields}


def sign_layer(
    layer: str, body: dict, layer_fields: dict, priv: Ed25519PrivateKey
) -> dict:
    """Sign one layer over the canonical signed view.

    Gives back an envelope with ``layer``, ``signature``, ``layer_fields``
    and ``pub_hex``. The private key never appears in the output. The body
    hash is *not* stored on the envelope: it is recomputed locally by the
    verifier, so there is no unsigned field an attacker could rewrite.
    """
    sig = priv.sign(canonical_bytes(signed_view(layer, body, layer_fields))).hex()
    pub_hex = priv.public_key().public_bytes_raw().hex()
    return {
        "layer": layer,
        "signature": sig,
        "layer_fields": layer_fields,
        "pub_hex": pub_hex,
    }


def verify_layer(envelope: dict, body: dict, pub_hex: str) -> bool:
    """Verify a layer envelope against a trusted public key.

    ``pub_hex`` is the expected public key for this layer (from a trusted
    key ring, not from the envelope itself). Gives back True only when the
    signature verifies over the canonical signed view.

    The envelope must be an exact ``dict``, so a subclass overriding ``.get``
    cannot substitute a clean ``layer_fields`` for the real one.

    Never raises on malformed input: a malformed envelope, signature, key, or
    body simply returns False. (Exceptions are reserved for programmer error,
    which is not what a malformed card in transit is.)
    """
    try:
        env = _require_plain_dict(envelope, "envelope")
        lf = env.get("layer_fields")
        view = signed_view(env["layer"], body, {} if lf is None else lf)
        pub = public_key_from_hex(pub_hex)
        pub.verify(bytes.fromhex(env["signature"]), canonical_bytes(view))
        return True
    except (InvalidSignature, ValueError, KeyError, TypeError, AttributeError):
        return False
