# SICA Accord

A contract and validation layer for governed multi-agent organisations.

## What this is

SICA Accord is a small, focused library and a runnable demo that make one
idea concrete: in a chain of agents that delegate work to one another, the
agreement between them is a data contract, and that contract can be checked
at every hop. An interface is derived from the contract, not improvised along
the way; a validator rejects any hand-off that has drifted from it.

The repository contains:

- a frozen field-set schema (the agreed set of fields),
- a canonical hash and Ed25519 sign/verify layer,
- a hop validator with fail-closed gates,
- a runnable demo that shows the whole flow, including the failure cases.

## What it does

Work moves through delegation hops. At each hop a signer attaches a signature
over a canonical encoding of the agreed body. Before anything proceeds, the
validator:

1. checks that the card and its key ring are well-formed (a malformed card is
   refused, never an error);
2. checks that the body is canonically encodable (string keys only, no
   non-finite numbers, JSON values only);
3. checks that the body's field set matches the frozen schema exactly (no
   extra fields, no missing fields);
4. checks that the supplied layer chain matches the expected chain exactly —
   the required layers, in order, with no missing, extra, duplicated, or
   out-of-order hops (and never an empty chain);
5. checks that every signature verifies under the expected public key, taken
   from a trusted key ring — never from the card's own claims.

Any failure stops the hand-off. The door re-runs this validation itself before
it acts, so it only ever acts on a card that actually validates.

> **Important — the expected chain is required.** `validate()` and `Door` will
> not act on a card unless you name the required layers, in order, via
> `expected_layers`. There is no default chain and no permissive fallback: a
> card without an expected chain is refused, and `Door` cannot be constructed
> without one. This is what makes the "checks the chain exactly" guarantee
> unconditional rather than best-effort.

> **Reserved-key matching is exact.** `layer` and `body` are rejected by exact
> code-point equality only. A look-alike key such as `b\u03bfdy` (Greek omicron
> `\u03bf` in place of `o`) is *not* a reserved key and is not caught. Treat
> layer-field names as a closed, self-chosen vocabulary and never rely on the
> reserved-key check to catch homographs.

## Quick start

Prerequisites: Python 3.11 or later.

```sh
git clone <this repository>
cd sica-accord
python3 -m pip install cryptography
python3 demo/run_demo.py
```

That is the whole demo: two signers, a validator, a fail-closed door, a
deliberate drift that is rejected, and an exclusive-claim sketch. Exit code 0
means every expected accept and reject happened. (The same command is the
repository's smoke test.)

Run the co-located unit tests with:

```sh
python3 -m unittest discover
```

## The demo flow

`demo/run_demo.py` walks through:

1. **Contract** — the frozen field set and the frozen body are shown; the
   body's hash (its first 12 hex characters) is the invariant printed at every
   hop.
2. **Sign** — an orchestrator signs the first hop, a specialist signs the
   second. Both print the same hash.
3. **Validate** — the hop validator accepts the card and prints the same hash.
4. **Door** — the fail-closed door validates the card itself and records it.
5. **Failure** — one field is added to a copy of the body. The validator
   rejects it; the door refuses it and records nothing.
6. **Exclusive claim** — two agents claim the same resource; the second claim
   is refused. (A sketch of one more check a governed organisation can add.)

## When validation fails

A rejected card prints a `REJECT` line naming the first problem found, and
the door prints `REFUSED`. The door is fail-closed: it validates before it
acts and does not repair, fill in, or guess. A card either validates exactly
or it does not pass. This is deliberate — a hand-off that "looks mostly
right" is still a broken contract.

## Repo map

```
schema/      the doctrine, frozen field sets, and the canonical rule
sign/        canonical hash and Ed25519 sign/verify
validator/   hop validator, schema-drift checks, and fail-closed gates (tests co-located)
demo/        the runnable Demo 1 and its fixtures
```

## What's not here

SICA Accord is the contract and validation layer only. There is deliberately
no deployment or execution environment here: no network services, no ledger,
no persistent key storage, and no configuration for a particular
installation. The demo keys are generated in memory and never written to
disk. A larger system can be built on top of this layer, but this repository
is the agreement, not the machinery that acts on it.

## Contributing

See CONTRIBUTING.md. In short: propose a schema or validator change in an
issue first, then open a pull request.
