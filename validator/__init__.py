"""Hop validator, schema-drift checks, and the fail-closed verdict.

The validator answers one question at every delegation hop: is this signed
body exactly the contract that was agreed — with no fields added, removed,
or altered since the signer signed it, and signed by exactly the layers the
contract requires, in order?

Checks, in order:

1. Input shape: body, schema, layer envelopes, and key ring are well-formed.
   A malformed card is a refusal, never an exception.
2. Canonical body: the body is canonically encodable (string keys only, no
   non-finite numbers, JSON values only).
3. Chain shape: the supplied layer labels match the expected chain exactly —
   no missing, extra, duplicated, or out-of-order hops, and never empty.
4. Schema freeze: the body's field set matches the frozen schema exactly.
5. Manifest hash: if one is supplied, the body's canonical hash matches it.
6. Signatures: every layer signature verifies under the trusted public key
   for that layer (from a key ring, never from the envelope's self-declared
   key), and no layer field uses a reserved key.

Any failure rejects the card. The validator never repairs, never fills in a
missing value, and never falls back to a default — fail-closed means a card
either validates exactly or it does not pass.

All container inputs (body, schema, envelopes, key ring) are checked to be
exact ``dict``/``list`` types before any check runs: a dict/list subclass can
override ``__contains__``, ``get``, ``items``, ``keys`` or ``__iter__`` so a
guard and the value it later reads disagree. Requiring the exact type means
no override can exist, so the value signed is necessarily the value read.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from sign import (
    CanonicalizationError,
    body_hash,
    reserved_keys_in_layer_fields,
    verify_layer,
)


@dataclass
class Result:
    """The verdict of a validation run.

    ``ok`` is True only when all checks pass. ``reasons`` lists every
    failure found (the first is the most useful for a human reader).
    ``digest`` is the full sha256 of the canonical body; ``short`` its first
    12 characters (the invariant printed at each hop).
    """

    ok: bool
    reasons: list[str] = field(default_factory=list)
    card_id: str = ""
    seq: object = None
    digest: str = ""
    short: str = ""
    layers: list[str] = field(default_factory=list)


def _card_id(body: object) -> str:
    if not isinstance(body, dict):
        return "card/?"
    return f"{body.get('schema_name', 'card')}/{body.get('seq', '?')}"


def _seq(body: object) -> object:
    return body.get("seq") if isinstance(body, dict) else None


def _labels(layers: list[dict]) -> list[str]:
    # Only called after shape checks have guaranteed each envelope is a dict
    # with a string ``layer``.
    return [e["layer"] for e in layers]


def _check_expected_layers(expected_layers: list[str] | None) -> None:
    """Validate the caller-supplied chain spec. A bad spec is a programmer
    error (it is trusted configuration, not attacker data), so it raises."""
    if expected_layers is None:
        return
    if not isinstance(expected_layers, list) or not expected_layers:
        raise ValueError("expected_layers must be a non-empty list of labels")
    if len(set(expected_layers)) != len(expected_layers):
        raise ValueError("expected_layers must not contain duplicates")
    if not all(isinstance(l, str) for l in expected_layers):
        raise ValueError("expected_layers must contain only strings")


def _normalise_inputs(
    body: object,
    schema: object,
    layers: object,
    keyring: object,
    manifest_hash: object,
) -> tuple[list[str], tuple[dict, dict, list[dict], dict] | None]:
    """Type-gate and normalise all container inputs.

    Returns ``(errs, normalised)`` where ``normalised`` is the tuple
    ``(body, schema, layers, keyring)`` as fresh plain dicts, or ``None``
    when ``errs`` is non-empty. The gate uses an exact-type check
    (``type(x) is dict``/``list``), so a dict/list subclass — which can
    override ``__contains__``/``get``/``items``/``keys``/``__iter__`` and make
    a guard disagree with a later read — is refused rather than trusted.
    """
    errs: list[str] = []

    if type(body) is not dict:
        errs.append("MALFORMED_BODY")
    if type(schema) is not dict:
        errs.append("MALFORMED_SCHEMA")
    if type(layers) is not list:
        errs.append("MALFORMED_LAYERS")
    if type(keyring) is not dict:
        errs.append("MALFORMED_KEYRING")
    if manifest_hash is not None and not isinstance(manifest_hash, str):
        errs.append("MALFORMED_MANIFEST_HASH")
    if errs:
        return errs, None

    # The isinstance gates above guarantee these are dicts (any failure sets
    # errs and returns early); the asserts give the type checker that
    # narrowing, which it cannot derive through the shared `errs` return.
    assert type(body) is dict
    assert type(schema) is dict
    assert type(keyring) is dict
    n_body = dict(body)
    n_schema = dict(schema)
    n_keyring = dict(keyring)

    norm_layers: list[dict] = []
    for i, env in enumerate(layers):
        if type(env) is not dict:
            errs.append(f"MALFORMED_LAYER:{i}")
            continue
        norm_layers.append(dict(env))
    if errs:
        return errs, None

    # value-level shape checks on the normalised containers
    if not (
        isinstance(n_schema.get("frozen_fields"), list)
        and n_schema["frozen_fields"]
        and all(isinstance(f, str) for f in n_schema["frozen_fields"])
    ):
        errs.append("MALFORMED_SCHEMA")

    for i, env in enumerate(norm_layers):
        if not isinstance(env.get("layer"), str) or not env["layer"]:
            errs.append(f"MALFORMED_LAYER:{i}")
        if not isinstance(env.get("signature"), str):
            errs.append(f"MALFORMED_LAYER:{i}")
        if "layer_fields" in env and type(env.get("layer_fields")) is not dict:
            errs.append(f"MALFORMED_LAYER:{i}")

    for lbl, pub in n_keyring.items():
        if not isinstance(lbl, str) or not isinstance(pub, str):
            errs.append(f"MALFORMED_PUBKEY:{lbl}")
            continue
        try:
            raw = bytes.fromhex(pub)
        except ValueError:
            errs.append(f"MALFORMED_PUBKEY:{lbl}")
            continue
        if len(raw) != 32:
            errs.append(f"MALFORMED_PUBKEY:{lbl}")

    if errs:
        return errs, None
    return [], (n_body, n_schema, norm_layers, n_keyring)


def _chain_reasons(expected_layers: list[str] | None, labels: list[str]) -> list[str]:
    """Chain-shape failures.

    With an explicit ``expected_layers`` the supplied labels must match it
    exactly, in order. Without one (the safe default), the supplied set must
    at least be non-empty and free of duplicates — never a silent "no check".
    """
    reasons: list[str] = []

    if expected_layers is None:
        # No expected chain was named. The safe default is refusal, never a
        # permissive structural check: a governed card must name its chain.
        reasons.append("NO_EXPECTED_LAYERS")
        return reasons

    counts = Counter(labels)
    for lbl, c in counts.items():
        if c > 1:
            reasons.append(f"DUPLICATE_LAYER:{lbl}")
    for lbl in expected_layers:
        if lbl not in counts:
            reasons.append(f"MISSING_LAYER:{lbl}")
    for lbl in counts:
        if lbl not in expected_layers:
            reasons.append(f"UNEXPECTED_LAYER:{lbl}")
    if (
        labels != expected_layers
        and len(counts) == len(expected_layers)
        and all(c == 1 for c in counts.values())
    ):
        reasons.append("LAYER_OUT_OF_ORDER")

    return reasons


def validate(
    body: dict,
    schema: dict,
    layers: list[dict],
    keyring: dict[str, str],
    manifest_hash: str | None = None,
    expected_layers: list[str] | None = None,
) -> Result:
    """Validate a signed body against its frozen schema and layer envelopes.

    ``layers`` is a list of sign envelopes (one per hop, in order).
    ``keyring`` maps a layer label to its trusted hex public key. If
    ``manifest_hash`` is given, the body's canonical hash must match it.

    ``expected_layers`` names the layer labels the contract requires, in
    order. The supplied chain must match it exactly (missing, extra,
    duplicated, or out-of-order hops are each refused with their own reason).
    If ``expected_layers`` is omitted (``None``), the validator refuses with
    ``NO_EXPECTED_LAYERS`` — a governed card must name its chain; there is no
    permissive default.

    All container inputs are normalised to plain dicts before any check, so a
    dict subclass cannot make a guard and its later action disagree.

    Never raises for malformed card/keyring input: such input is refused with
    a deterministic reason. Exceptions are reserved for programmer error,
    chiefly a malformed ``expected_layers`` spec.
    """
    _check_expected_layers(expected_layers)

    errs, norm = _normalise_inputs(body, schema, layers, keyring, manifest_hash)
    if errs:
        return Result(ok=False, reasons=errs, card_id=_card_id(body),
                      seq=_seq(body))
    body, schema, layers, keyring = norm  # type: ignore[misc]

    try:
        bh = body_hash(body)
    except CanonicalizationError as exc:
        return Result(
            ok=False,
            reasons=[f"NON_CANONICAL_BODY:{exc}"],
            card_id=_card_id(body),
            seq=_seq(body),
            layers=_labels(layers),
        )

    card_id = _card_id(body)
    labels = _labels(layers)
    reasons: list[str] = []

    # --- check: chain shape ---
    reasons += _chain_reasons(expected_layers, labels)

    # --- check: schema freeze — field set must match exactly ---
    frozen = set(schema["frozen_fields"])
    body_keys = set(body.keys())
    for k in sorted(body_keys - frozen):
        reasons.append(f"SCHEMA_EXTRA_FIELD:{k}")
    for k in sorted(frozen - body_keys):
        reasons.append(f"SCHEMA_MISSING_FIELD:{k}")

    # --- check: manifest hash ---
    if manifest_hash is not None and manifest_hash != bh:
        reasons.append(f"BODY_HASH_MISMATCH:manifest {manifest_hash} != {bh}")

    # --- check: reserved keys + every signature under its trusted key ---
    for env in layers:
        lname = env["layer"]
        lf = env.get("layer_fields")
        if lf is not None and reserved_keys_in_layer_fields(lf):
            reasons.append(f"reserved_key_in_layer_fields:{lname}")
            continue
        pub = keyring.get(lname)
        if pub is None:
            reasons.append(f"MISSING_PUBKEY:{lname}")
        elif not verify_layer(env, body, pub):
            reasons.append(f"INVALID_SIGNATURE {lname}")

    return Result(ok=not reasons, reasons=reasons, card_id=card_id,
                  seq=body.get("seq"), digest=bh, short=bh[:12],
                  layers=labels)
