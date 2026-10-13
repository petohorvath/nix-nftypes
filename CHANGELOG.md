# Changelog

## Unreleased

### Breaking CI and test layout: project policy v0.6

Call [nixos-project-policy](https://github.com/petohorvath/nixos-project-policy/blob/v0.6/POLICY.md) `v0.6` from `.github/workflows/check.yml`, with no caller inputs, and remove `ci.yml`. The policy checks the inputs, public outputs, development shell, and formatter, and builds the checks on `x86_64-linux` and `aarch64-linux` with the locked `nixpkgs` and with the policy's stable and unstable pins. A new `formatting` check replaces the `format` job.

The live parser and renderer tests stay in `checks.<system>` with their names: `integration-tests`, `text-integration-tests`, `text-block-integration-tests`, `render-equivalence-tests`, `comment-safety-integration-tests`, `ifname-safety-integration-tests`, and `nftables-roundtrip-tests`. Their probes create private user and network namespaces, which hosted runners deny inside the build sandbox, so one NixOS VM runs them. They declare `requiredSystemFeatures = [ "kvm" "nixos-test" ]`, which makes them VM tests: the policy builds them in its VM jobs with all three nixpkgs versions, and a runner without KVM reports them as skipped. Plain `nix flake check` now needs KVM.

The required statuses on `main` become `Policy / Check (<system>)`, `Policy / Tests (locked|stable|unstable, <system>)`, and `Policy / VM tests (locked|stable|unstable, <system>)` for both Linux systems, replacing `tests` and `format`.

Add the MIT license.

### Breaking flake outputs: a single `nixpkgs` input

Drop the `nixpkgs-unstable` flake input. The checks and VM tests are built once from `nixpkgs`, and the policy's stable and unstable pin runs, which override `nixpkgs`, test the other nixpkgs versions. This removes the `packages.<system>.nftables-source-unstable` package and every `-unstable` check in `checks.<system>`, including the `-unstable` VM tests. The policy's unstable pin runs build the VM tests against unstable instead.

The upstream-sync workflow now runs daily and reads the stable and unstable pins from the policy checker that `check.yml` calls and overrides `nixpkgs` with each pin, instead of resolving the `nixos-26.05` and `nixos-unstable` branch tips. The unstable source watch compares the locked stable source with the unstable pin, so its drift issue stays open while unstable carries a newer nftables. Each pin keeps one drift issue, which the workflow edits in place with the current report: both nixpkgs revisions, nftables versions, and patched-source hashes, the changed files, and a command for the full diff. It comments only when the pinned source changes. The workflow drops its canary job: the policy lists this repository, so its Pin-bump tests run every check, VM tests included, with proposed pins on both Linux systems before their release. The workflow also drops its optional AI triage and `tooling/drift-triage.sh`: the `ANTHROPIC_API_KEY` secret is no longer read. The `parser.diff` artifact of selected files is gone too.

### Added

- Model the named `ct count` object from nftables 1.1.7: `add`, `create`, `delete`, `destroy`, and `list` commands, `dsl.table` `ctCounts`, `dsl.create.ctCount` and the other command builders, and text rendering as `ct count NAME { over|until N; }`. `ct count` statements also accept a reference to the object, through `dsl.ctCount.ref`. nftables 1.1.6 and earlier reject both.
- Accept a map expression as the named-object reference of the `counter`, `quota`, `limit`, `synproxy`, and `ct count` statements (`quota name tcp dport map { … }`), and render it as text. The corpus baseline drops its four `stmt-map` categories.

### Changed

- Prefix error messages with the project name, `nix-nftypes:`.
