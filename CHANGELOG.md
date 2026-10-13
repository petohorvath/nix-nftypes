# Changelog

## Unreleased

### Breaking CI and test layout: project policy v0.6

Call [nixos-project-policy](https://github.com/petohorvath/nixos-project-policy/blob/v0.6/POLICY.md) `v0.6` from `.github/workflows/check.yml`, with no caller inputs, and remove `ci.yml`. The policy checks the inputs, public outputs, development shell, and formatter, and builds the checks on `x86_64-linux` and `aarch64-linux` with the locked `nixpkgs` and with the policy's stable and unstable pins. A new `formatting` check replaces the `format` job.

The live parser and renderer tests stay in `checks.<system>` with their names: `integration-tests`, `text-integration-tests`, `text-block-integration-tests`, `render-equivalence-tests`, `comment-safety-integration-tests`, `ifname-safety-integration-tests`, and `nftables-roundtrip-tests`. Their probes create private user and network namespaces, which hosted runners deny inside the build sandbox, so one NixOS VM runs them. They declare `requiredSystemFeatures = [ "kvm" "nixos-test" ]`, which makes them VM tests: the policy builds them in its VM jobs with all three nixpkgs versions, and a runner without KVM reports them as skipped. Plain `nix flake check` now needs KVM. The weekly canary builds them on a KVM-enabled runner and no longer installs the AppArmor profile.

The required statuses on `main` become `Policy / Check (<system>)`, `Policy / Tests (locked|stable|unstable, <system>)`, and `Policy / VM tests (locked|stable|unstable, <system>)` for both Linux systems, replacing `tests` and `format`.

Add the MIT license.

### Breaking flake outputs: a single `nixpkgs` input

Drop the `nixpkgs-unstable` flake input. The checks and VM tests are built once from `nixpkgs`, and the policy's stable and unstable pin runs, which override `nixpkgs`, test the other nixpkgs versions. This removes the `packages.<system>.nftables-source-unstable` package and every `-unstable` check in `checks.<system>`, including the `-unstable` VM tests. The policy's unstable pin runs build the VM tests against unstable instead.

The weekly upstream-sync workflow overrides `nixpkgs` with the tips of the `nixos-26.05` and `nixos-unstable` branches. The unstable source watch now compares the locked stable source with the unstable tip, so its drift issue stays open while unstable carries a newer nftables. A new drift issue closes the older open ones for the same branch.

### Added

- Model the named `ct count` object from nftables 1.1.7: `add`, `create`, `delete`, `destroy`, and `list` commands, `dsl.table` `ctCounts`, `dsl.create.ctCount` and the other command builders, and text rendering as `ct count NAME { over|until N; }`. `ct count` statements also accept a reference to the object, through `dsl.ctCount.ref`. nftables 1.1.6 and earlier reject both.
- Accept a map expression as the named-object reference of the `counter`, `quota`, `limit`, `synproxy`, and `ct count` statements (`quota name tcp dport map { … }`), and render it as text. The corpus baseline drops its four `stmt-map` categories.
