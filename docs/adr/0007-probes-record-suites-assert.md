# Split live checks into probes that record and suites that assert

Every test runs nix-unit; only the `formatting` check, which runs treefmt, does not. A live check is split in two: a probe, a derivation that runs the package set's `nft` or the source tooling and records each run's exit status and output as JSON without judging it, and a nix-unit suite that asserts on that record. Probe outputs are build inputs of the nix-unit run, so the checks evaluate with import-from-derivation disabled.

## Consequences

`nix-unit --flake .#tests` covers only the evaluation-only suites: a live suite asserts on a probe's build output, which nix-unit could reach only through import-from-derivation. Running a live suite means building its check.

## Evidence

- `888bfb8` (#9): "Split each live-parser and source-tooling check into a probe and a nix-unit suite … so checks evaluate with IFD disabled."
- `1b6b7a4` (#10) documents the fast loop and its limit in `README.md` "Verification".
- `tests/probes/`, `tests/live.nix`, and `tests/nix-unit-check.nix`.
