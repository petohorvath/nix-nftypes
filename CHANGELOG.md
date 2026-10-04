# Changelog

## Unreleased

### Breaking CI and test layout: project policy v0.5

Call [nixos-project-policy](https://github.com/petohorvath/nixos-project-policy/blob/v0.5/POLICY.md) `v0.5` from `.github/workflows/check.yml`, with no caller inputs, and remove `ci.yml`. The policy checks the inputs, public outputs, development shell, and formatter, runs root `nix flake check` on `x86_64-linux` and `aarch64-linux` with the locked `nixpkgs` and with the policy's stable and unstable pins, and builds the VM tests on `x86_64-linux` with KVM. A new `formatting` check replaces the `format` job.

Move the live parser and renderer tests from `checks.<system>` to `legacyPackages.<system>.vmTests`, keeping their names: `integration-tests`, `text-integration-tests`, `text-block-integration-tests`, `render-equivalence-tests`, `comment-safety-integration-tests`, `ifname-safety-integration-tests`, `nftables-roundtrip-tests`, and their `-unstable` variants. Their probes create private user and network namespaces, which hosted runners deny inside the build sandbox, so one NixOS VM per package set runs them. The VM tests run only with the locked inputs; the policy's stable and unstable pin runs cover the remaining checks. The weekly canary builds them on a KVM-enabled runner and no longer installs the AppArmor profile.

The required statuses on `main` become `Policy / Check (<system>)`, `Policy / Tests (locked|stable|unstable, <system>)` for both Linux systems, and `Policy / VM tests`, replacing `tests` and `format`.

Add the MIT license.
