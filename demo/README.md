# Demo

This directory holds the runnable Demo 1 and its fixtures.

`run_demo.py` runs the whole governed-card flow offline and
deterministically, and is also the repository's smoke test: exit code 0 means
every expected ACCEPT and REJECT happened.

Run it from the repository root:

```sh
python3 demo/run_demo.py
```

`fixtures/` holds the synthetic bodies and layer fields the demo signs. All
of it is fabricated for the demo; the keys are generated in memory at each
run and never written to disk.

The `hop` values in `fields_l0.json` and `fields_l1.json` are layer-field
metadata the signer attaches; the validator does not enforce them. Chain
ordering is enforced by the expected layer sequence passed to `validate()`
(here `["L0", "L1"]`), not by any `hop` number in the fixtures.
