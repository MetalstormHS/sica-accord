#!/usr/bin/env python3
"""Demo 1 — one contract intact across delegation hops.

Runs the full governed-card flow end to end, offline and deterministically:

    frozen schema -> canonical hash -> Ed25519 sign (two hops) -> hop
    validator -> fail-closed door -> deliberate drift REJECTed -> a flipped
    signature REJECTed -> exclusive-claim sketch.

Exit 0 only if every expected ACCEPT and REJECT is observed. This script is
the repository's runnable demo and doubles as its smoke test.

Usage (from the repository root):

    python3 demo/run_demo.py

Requires only ``cryptography`` beyond the standard library.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from sign import body_hash, generate_keypair, private_key_from_seed, sign_layer  # noqa: E402
from validator import validate  # noqa: E402
from validator.claim import ClaimRegistry  # noqa: E402
from validator.door import Door  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"
SCHEMA_DIR = REPO_ROOT / "schema"

PASS = 0
FAIL = 1

# The work-order card must carry both hops, in this order.
CHAIN = ["L0", "L1"]


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    failures: list[str] = []

    # --- demo keys (in-memory, fresh each run; never written to disk) ---
    print("== DEMO 1: one contract, two hops, fail-closed door ==")
    print("generating demo Ed25519 keypairs (in-memory; nothing written to disk)")
    l0_seed, l0_pub = generate_keypair()
    l1_seed, l1_pub = generate_keypair()
    keyring = {"L0": l0_pub, "L1": l1_pub}

    # --- the contract: frozen schema + frozen body ---
    schema = _load(SCHEMA_DIR / "work_order.v1.fields.json")
    body = _load(FIXTURES / "work_order.v1.json")
    bh = body_hash(body)
    print(f"\n[contract] frozen schema {schema['schema_name']} "
          f"fields={sorted(schema['frozen_fields'])}")
    print(f"body12={bh[:12]}   <-- the invariant line (first 12 of 64)")

    # --- sign two hops ---
    print("\n-- H1: orchestrator signs L0 --")
    l0 = sign_layer("L0", body, _load(FIXTURES / "fields_l0.json"),
                    private_key_from_seed(l0_seed))
    print(f"  layer={l0['layer']} body12={bh[:12]}")

    print("\n-- H2: specialist signs L1 --")
    l1 = sign_layer("L1", body, _load(FIXTURES / "fields_l1.json"),
                    private_key_from_seed(l1_seed))
    print(f"  layer={l1['layer']} body12={bh[:12]}")
    layers = [l0, l1]

    # --- hop validator ---
    print("\n-- H3: hop validator --")
    result = validate(body, schema, layers, keyring, manifest_hash=bh,
                      expected_layers=CHAIN)
    if not result.ok:
        failures.append("pristine card was REJECTed")
        for r in result.reasons:
            print(f"REJECT {r}")
        print("VALIDATION FAILED")
    else:
        print(f"ACCEPT card={result.card_id} seq={body.get('seq')} "
              f"sha={result.short} layers={','.join(result.layers)}")
        print(f"body12={result.short}   <-- matches every hop")

    # --- fail-closed door ---
    print("\n-- H4: fail-closed door --")
    door = Door(schema=schema, keyring=keyring, expected_layers=CHAIN,
                manifest_hash=bh)
    ack = door.admit(body, layers)
    if ack["status"] != "ACK":
        failures.append("door REFUSED a validated card")
    print(f"{ack['status']} {result.card_id} sha={result.short}")
    if ack["status"] == "ACK":
        print(f"door recorded: {json.dumps(ack, sort_keys=True)}")

    # --- deliberate drift (the failure beat) ---
    print("\n-- FAILURE: one field the signer never signed --")
    drifted = {**body, "entry_class": None}
    drift_result = validate(drifted, schema, layers, keyring, manifest_hash=bh,
                            expected_layers=CHAIN)
    if drift_result.ok:
        failures.append("drifted card was ACCEPTed (should REJECT)")
    for r in drift_result.reasons:
        print(f"REJECT {r}")
    print("VALIDATION FAILED" if not drift_result.ok else "ACCEPT (BUG)")

    drift_ack = door.admit(drifted, layers)
    print(f"{drift_ack['status']} {drift_ack.get('reason', '')}")
    if drift_ack["status"] != "REFUSED":
        failures.append("door did not REFUSE the drifted card")
    if len(door.inbox) != 1:
        failures.append("door recorded an ack for a refused card")

    # --- flipped signature byte ---
    print("\n-- FAILURE: one flipped signature byte --")
    flipped = dict(l1)
    first = int(flipped["signature"][:2], 16)
    flipped["signature"] = f"{first ^ 0x01:02x}" + flipped["signature"][2:]
    flip_result = validate(body, schema, [l0, flipped], keyring, manifest_hash=bh,
                           expected_layers=CHAIN)
    if flip_result.ok:
        failures.append("flipped signature was ACCEPTed (should REJECT)")
    for r in flip_result.reasons:
        print(f"REJECT {r}")

    # --- missing hop (a hop that never happened) ---
    print("\n-- FAILURE: a hop that never happened (L1 missing) --")
    missing_result = validate(body, schema, [l0], keyring, manifest_hash=bh,
                              expected_layers=CHAIN)
    if missing_result.ok:
        failures.append("stripped chain was ACCEPTed (should REJECT)")
    for r in missing_result.reasons:
        print(f"REJECT {r}")

    # --- exclusive-claim sketch ---
    print("\n-- EXCLUSIVE-CLAIM SKETCH (Pauli-exclusion) --")
    claim_schema = _load(SCHEMA_DIR / "claim.v1.fields.json")
    registry = ClaimRegistry(
        keyring=keyring,
        schema=claim_schema,
        identities={"L0": "orchestrator", "L1": "specialist"},
    )
    claim_a = _load(FIXTURES / "claim_a.json")
    claim_b = _load(FIXTURES / "claim_b.json")
    claim_c = _load(FIXTURES / "claim_c.json")
    a_layers = [sign_layer("L0", claim_a, {}, private_key_from_seed(l0_seed))]
    b_layers = [sign_layer("L1", claim_b, {}, private_key_from_seed(l1_seed))]
    c_layers = [sign_layer("L1", claim_c, {}, private_key_from_seed(l1_seed))]
    for name, cbody, clayers in (("A", claim_a, a_layers),
                                 ("B", claim_b, b_layers),
                                 ("C", claim_c, c_layers)):
        out = registry.register(cbody, clayers)
        if out["status"] == "HELD":
            print(f"claim {name}: {out['status']} resource={out['resource']} "
                  f"claimant={out['claimant']}")
        else:
            print(f"claim {name}: {out['status']} {out['reason']}")
    if registry.held.get("workstation-07") != "orchestrator":
        failures.append("claim A did not hold its resource")
    if registry.held.get("workstation-09") != "specialist":
        failures.append("claim C did not hold its resource")
    b_out = registry.register(claim_b, b_layers)
    if b_out["status"] != "REFUSED":
        failures.append("conflicting claim B was not refused")

    # --- restore ---
    print("\n-- RESTORE: pristine card still validates --")
    restore = validate(body, schema, layers, keyring, manifest_hash=bh,
                       expected_layers=CHAIN)
    if not restore.ok:
        failures.append("pristine card failed to validate after the failure beats")
    else:
        print(f"ACCEPT card={restore.card_id} seq={body.get('seq')} "
              f"sha={restore.short}")

    print()
    if failures:
        print("DEMO FAILED:")
        for f in failures:
            print(f"  - {f}")
        return FAIL
    print("DEMO OK: ACCEPT + ACK on the pristine card; drift, missing hop,")
    print("byte-flip and conflicting claim all REJECTed/REFUSED; pristine card")
    print("still validates.")
    return PASS


if __name__ == "__main__":
    raise SystemExit(main())
