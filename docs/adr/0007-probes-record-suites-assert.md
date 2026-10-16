# Split live checks into probes that record and suites that assert

Every test runs nix-unit; only the `formatting` check, which runs treefmt, and the `lint` check, a static guard on the repo's files, do not. A live check is split in two: a probe, a derivation that runs the package set's `nft` or the source tooling and records each run's exit status and output as JSON without judging it, and a nix-unit suite that asserts on that record. Probe outputs are build inputs of the nix-unit run, so the checks evaluate with import-from-derivation disabled.

## Consequences

`nix-unit tests/unit` runs the unit suites without building anything. An integration suite asserts on a probe's build output, so `nix-unit tests/integration` reaches the records only through import-from-derivation, which is acceptable for a local run but not for the checks. Each `integration-<suite>` check receives its records as build inputs instead.

## Evidence

- `888bfb8` (#9): "Split each live-parser and source-tooling check into a probe and a nix-unit suite … so checks evaluate with IFD disabled."
- `1b6b7a4` (#10) documents the fast loop and its limit in `README.md` "Verification".
- `tests/helpers/probes/`, `tests/integration/default.nix`, and `tests/runners/nix-unit.nix` (`tests/probes/`, `tests/live.nix`, and `tests/nix-unit-check.nix` before the move to the test standard).
