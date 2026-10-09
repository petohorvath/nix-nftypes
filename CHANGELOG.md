# Changelog

## Unreleased

### Breaking CI and test layout: project policy v0.5

Call [nixos-project-policy](https://github.com/petohorvath/nixos-project-policy/blob/v0.5/POLICY.md) `v0.5` from `.github/workflows/check.yml`, with no caller inputs, and remove `ci.yml`. The policy checks the inputs, public outputs, development shell, and formatter, runs root `nix flake check` on `x86_64-linux` and `aarch64-linux` with the locked `nixpkgs` and with the policy's stable and unstable pins, and builds the VM tests on `x86_64-linux` with KVM. A new `formatting` check replaces the `format` job.

Move the live parser and renderer tests from `checks.<system>` to `legacyPackages.<system>.vmTests`, keeping their names: `integration-tests`, `text-integration-tests`, `text-block-integration-tests`, `render-equivalence-tests`, `comment-safety-integration-tests`, `ifname-safety-integration-tests`, and `nftables-roundtrip-tests`. Their probes create private user and network namespaces, which hosted runners deny inside the build sandbox, so one NixOS VM runs them. The VM tests run only with the locked `nixpkgs`; the policy's stable and unstable pin runs cover the remaining checks. The weekly canary builds them on a KVM-enabled runner and no longer installs the AppArmor profile.

The required statuses on `main` become `Policy / Check (<system>)`, `Policy / Tests (locked|stable|unstable, <system>)` for both Linux systems, and `Policy / VM tests`, replacing `tests` and `format`.

Add the MIT license.

### Breaking flake outputs: a single `nixpkgs` input

Drop the `nixpkgs-unstable` flake input. The checks and VM tests are built once from `nixpkgs`, and the policy's stable and unstable pin runs, which override `nixpkgs`, test the other nixpkgs versions. This removes the `packages.<system>.nftables-source-unstable` package, every `-unstable` check in `checks.<system>`, and every `-unstable` VM test in `legacyPackages.<system>.vmTests`. CI no longer builds VM tests against unstable; the weekly canary still does.

The weekly upstream-sync workflow overrides `nixpkgs` with the tips of the `nixos-26.05` and `nixos-unstable` branches. The unstable source watch now compares the locked stable source with the unstable tip, so its drift issue stays open while unstable carries a newer nftables.

### Added

- Model the named `ct count` object from nftables 1.1.7: `add`, `create`, `delete`, `destroy`, and `list` commands, `dsl.table` `ctCounts`, `dsl.create.ctCount` and the other command builders, and text rendering as `ct count NAME { over|until N; }`. `ct count` statements also accept a reference to the object, through `dsl.ctCount.ref`. nftables 1.1.6 and earlier reject both.
- Accept a map expression as the named-object reference of the `counter`, `quota`, `limit`, `synproxy`, and `ct count` statements (`quota name tcp dport map { … }`), and render it as text. The corpus baseline drops its four `stmt-map` categories.
