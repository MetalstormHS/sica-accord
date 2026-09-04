# Contributing to SICA Accord

Thanks for the interest. This repository is small on purpose: it is the
contract and validation layer, nothing more. Contributions should stay within
that scope.

## Propose first

Open an issue before writing code for:

- a new or changed schema field set,
- a new validator check or gate,
- a change to the canonical encoding rule.

The canonical encoding rule is load-bearing: every signature depends on it
being byte-identical at every hop. Changing it is a breaking change and needs
to be discussed first.

## Pull requests

- Keep the dependency surface minimal (standard library first;
  `cryptography` for Ed25519).
- Co-locate tests with the code they cover.
- The demo must keep running from a clean clone: `python3 demo/run_demo.py`
  with exit code 0.
- No private material of any kind (keys, credentials, configuration, network
  addresses).

## License

By contributing you agree your contribution is under the Apache-2.0 license
(see LICENSE).
