# Run live tests in a NixOS VM

Live tests create private user and network namespaces so that `nft` can parse and load rulesets without touching the host. Hosted CI runners deny those namespaces inside the build sandbox, and the shared project policy's jobs cannot install the AppArmor profile the old workflow used, so the probes run as root in one NixOS VM. Those tests are checks that declare `requiredSystemFeatures = [ "kvm" "nixos-test" ]`, so the project policy builds them in its VM jobs and skips them on a runner without KVM.

## Considered options

- An AppArmor profile that allows `unshare` on the CI runner (`685daf2`): the policy's jobs cannot install it, and `5026ae0` removed it from CI.

## Evidence

- `5026ae0` (#11), "ci!: Run the live parser tests in a NixOS VM", and the matching `CHANGELOG.md` entry.
- `tests/helpers/probes/vm.nix` and the "Test matrix" section of `docs/upstream-sync.md`.
