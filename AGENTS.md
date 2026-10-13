## Required checks

The development shell, loaded by `nix develop` or by direnv through `.envrc`, supplies Nix, nix-unit, the linters, and the parser tools.

```sh
nix fmt                     # fix a failing `formatting` check
nix-unit --flake .#tests    # evaluation-only suites, for a fast loop
nix flake check -L          # every check, with the locked nixpkgs
nix build -L .#legacyPackages.x86_64-linux.vmTests.<name>  # one live test in a NixOS VM; needs KVM
```

Run each system on a native builder: the tests run that system's `nft`, so `nix flake check --all-systems` from one architecture does not verify the other.

CI calls the shared [project policy](https://github.com/petohorvath/nixos-project-policy/blob/v0.5/POLICY.md) from [`.github/workflows/check.yml`](.github/workflows/check.yml). It runs `nix flake check` on `x86_64-linux` and `aarch64-linux` with the locked nixpkgs and with the policy's stable and unstable pins, and builds the VM tests on `x86_64-linux`. A pull request merges only after the policy statuses pass. To run the same checks locally:

```sh
nix run github:petohorvath/nixos-project-policy/v0.5 -- check .
nix run github:petohorvath/nixos-project-policy/v0.5 -- test . --nixpkgs locked
nix run github:petohorvath/nixos-project-policy/v0.5 -- vm .
```

`test` also accepts `--nixpkgs stable` and `--nixpkgs unstable`. `docs/upstream-sync.md` describes the test matrix and the weekly canary. For ad-hoc parser checks, `nix develop .#review` supplies just nftables and util-linux; review sandboxes run commands through `tooling/review-env.sh`, described in `.greptile/rules.md`.

## Agent skills

### Issue tracker

Issues live in GitHub Issues (`petohorvath/nix-nftypes`), managed with `gh`. See `docs/agents/issue-tracker.md`.

### Triage labels

The five default triage labels, each named after its role. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: one root `GLOSSARY.md` plus `docs/adr/`. See `docs/agents/domain.md`.
