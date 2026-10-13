# Upstream compatibility checks

The project tracks the nftables packages that Nix users install, not an
independent checkout of Netfilter `master`.

## Authorities

The `nixpkgs` flake input provides three related authorities:

1. `pkgs.nftables`: the live parser and serializer binary;
2. `pkgs.nftables.src` plus `pkgs.nftables.patches`: the exact patched source
   used to build that binary;
3. `pkgs.lib`: the Nix module/type implementation used by schema validation.

`nixpkgs` locks the stable NixOS branch. The project policy reruns the checks
with its stable and unstable pins overriding `nixpkgs`, so the same tests cover
the newer nftables that lands on unstable first. The source tree exposed as
`nftables-source` is produced with `pkgs.applyPatches`; there are no separate
nftables or libnftnl flake inputs.

## Test matrix

`tests/default.nix` creates every package-set-dependent test once, from
`nixpkgs`. Every test runs nix-unit against the package set's `lib` and
`nix-unit`. `unit-tests` runs the evaluation-only suites registered in `tests/unit.nix`;
its source-policy suite statically guards the single-authority design. Each
other test runs one suite from `tests/live.nix`, which asserts on the JSON
record of a probe (`tests/probes/`): a script that runs the package set's
`nft` or the source tooling and records each run's exit status and output.

All tests are checks in `checks.<system>`:

- `unit-tests`, the source-side tests, and `formatting` run their probes in
  the build sandbox.
- The live parser and renderer tests are VM tests. Their probes create
  private user and network namespaces, which hosted CI runners deny inside
  the build sandbox, so `tests/vm.nix` runs them in one NixOS VM. They
  declare `requiredSystemFeatures = [ "kvm" "nixos-test" ]`, so building
  them requires KVM.

Evaluate the exact current list rather than relying on a copied count:

```console
nix eval --json '.#checks.x86_64-linux' --apply builtins.attrNames | jq .
```

Checks and source packages are exposed for `x86_64-linux` and
`aarch64-linux`. CI runs the shared project policy on both systems with the
locked `nixpkgs` and with the policy's stable and unstable pins: the VM tests
in the `VM tests` jobs, and the other checks in the `Tests` jobs. A runner
without KVM reports the VM tests as skipped. The tests evaluate without
import-from-derivation, but building them runs the target architecture's
`nft` and tooling, so build each architecture on a matching native builder;
`--all-systems` from one architecture is not a cross-build path.

### Test groups

| Group | Tests |
| --- | --- |
| Nix/schema/DSL | `unit-tests`: schema, DSL parity, restricted types, DSL validation and its error messages |
| Renderer behavior | `unit-tests`: text and table-block parity; VM: JSON integration, text integration, table-block integration, selected JSON/text equivalence |
| Safety regressions | `unit-tests`: comments, interface names, verdict targets, scalar/token/reference names, datatypes, units, CT timeout keys, priorities; VM: comment and interface-name round trips |
| Source policy and drift | `unit-tests`: nixpkgs source policy; source checks: provenance, upstream corpus, enum/tag extraction, tooling self-tests; VM: read-back round trip |

The exact attribute names remain the machine-readable source of truth.

## Source-side checks

### Source provenance

`nftables-source-provenance-tests` verifies that source analysis receives the
tree the selected package set builds `pkgs.nftables` from. Other source
results are not trustworthy if this check fails.

It compares these attributes of the `nftables-source` package with those of
`pkgs.nftables`:

- `src`, the release archive;
- `patches`, the full patch list;
- `patchFlags`;
- `prePatch` and `postPatch`, with a `null` or missing hook equal to `""`.

`nftables-source` does not pass the unpack-phase and patch-phase attributes
`sourceRoot`, `setSourceRoot`, `preUnpack`, `postUnpack`, `unpackPhase`, and
`patchPhase`. The check fails, naming the attribute, when `pkgs.nftables`
sets one of them. Then either pass it in
`packages/nftables-source/package.nix` or record why it leaves the tree
unchanged.

### Upstream statement corpus

`nftables-corpus-tests` normalizes `tests/py/**/*.t.json` from the patched source
and validates each statement against `nftlib.types.statement`.

The check fails on any rejection that does not match a named pattern in
`tests/helpers/corpus-drift.nix`. The current 11 categories are documented in
[`spec-coverage.md`](spec-coverage.md). A pattern that stops matching also
fails the check, which names it so it can be pruned. Because the corpus only
changes with `flake.lock`, both failures appear in the lock-update change.

This detects schema-too-restrictive drift in upstream's exercised statements.
It does not prove that every parser branch appears in the corpus.

### Enum and dispatch extraction

`nftables-enum-extraction-tests` extracts selected enum tables and
statement/expression dispatch tags from the patched C source, then compares
them with `nftlib.enums` and schema tag registries. Plausibility floors prevent
an empty or badly parsed source file from passing.

Conditional string branches and constructs outside the extractor still require
manual review or corpus/live coverage.

### Read-back round trip

`nftables-roundtrip-tests`, a VM test, real-loads eleven selected integration
cases in private network namespaces, captures `nft -j list ruleset`, and
validates every emitted command with `nftlib.types.ruleset`.

One case is excluded before execution with its exact reason: flowtable offload
on dummy devices in an unprivileged namespace.

Every remaining selected case must load. An unexpected load failure now fails
the check instead of reducing coverage. The minimum-loaded floor remains as an
additional vacuous-pass guard. The current read-back divergence baseline is
empty.

This is sampled serializer evidence, not proof that every possible kernel state
or listed object shape has been observed.

### Tooling self-tests

`nftables-tooling-selftests` supplies synthetic source/corpus defects and checks
that enum extraction and corpus classification turn red. It also runs the
provenance assertions against doctored `pkgs.nftables` copies, one with a
`postPatch` the source tree lacks and one with a `postUnpack`, and checks that
each turns red. The schema suite in
`unit-tests` checks that read-back validation rejects junk. Both validate the
drift net's chosen fault classes, not nftables semantics themselves.

## Live parser and renderer tests

These are VM tests. Each runs its probe in a private network namespace inside
the package set's NixOS VM.

- `integration-tests` sends selected JSON to `nft -c -j -f` and confirms
  that a raw `create rule` case is rejected by the live parser.
- `text-integration-tests` sends native text to `nft -c -f` for the cases
  that render equivalence cannot load. A real load runs every check-mode
  validation, so render equivalence covers the rest.
- `text-block-integration-tests` wraps selected block output in a table and
  sends it to the text parser.
- `render-equivalence-tests` real-loads eight selected cases through JSON and
  text in separate namespaces and compares `nft list ruleset` output. A load
  failure or difference fails.

Named exclusions and text-only limits are documented in
[`text-coverage.md`](text-coverage.md).

## Daily policy-pin workflow

[`.github/workflows/upstream-sync.yml`](../.github/workflows/upstream-sync.yml)
runs daily at 09:00 UTC and on manual dispatch. It reads the stable and
unstable pins from the `validate` report of the checker in the policy series
that `check.yml` calls (`v0.6`), and runs once per pin, overriding `nixpkgs`
with that pin. It resolves no nixpkgs branch itself, so the source watch and
the policy's test runs see the same revisions. A pin release shows up in a
drift issue within a day.

### Patched-source watch

For each pin, the job:

1. reads the locked `nixpkgs` revision from `flake.lock`;
2. reads the pin's nixpkgs revision from the policy checker;
3. builds the locked patched source and, with `nixpkgs` overridden by the pin,
   the pinned patched source;
4. compares their NAR content hashes;
5. when they match, closes the pin's open drift issue;
6. when they differ, lists the changed files with `diff -rq` and writes the
   report into the pin's drift issue.

Each pin has at most one open drift issue, titled
`nixpkgs nftables drift (<pin>)` and labelled `nixpkgs-nftables-drift`. The
job opens the issue when none is open, and otherwise edits that issue in place,
replacing its body with the current report. The report gives both nixpkgs
revisions, both nftables versions, both hashes, the changed files, and a
command for the full diff:

```console
diff -ru $(nix build --no-link --print-out-paths .#nftables-source) \
         $(nix build --no-link --print-out-paths .#nftables-source --override-input nixpkgs github:NixOS/nixpkgs/<pin-revision>)
```

An edit sends no notification, so the job also comments on the issue when the
pinned source differs from the one the issue last reported. The issue body
records that hash in an HTML comment.

The stable pin's issue signals that the lock is behind the stable pin. The
unstable pin usually carries a newer nftables than the stable lock, so its
issue stays open until a lock update brings the same source, and a pin bump
that changes the source updates it with a comment.

A hash difference is a review signal, not proof of incompatibility. The full
patched-source NAR hashes are authoritative for whether drift exists. The
changed-file list names files only; the full-diff command shows their
contents.

### Tests with new pins

The workflow runs no tests. The policy lists this repository in its
`data/repos.json`, so its Pin-bump tests workflow runs `test` and `test --vm`
with each proposed stable and unstable pin on both Linux systems before the
pins are released. A failure there holds the pin bump until this repository
is fixed. After the release, the `Policy / Tests` and `Policy / VM tests` jobs
run every check with the new pins on each pull request.

## Interpreting failures

| Signal | Meaning | Response |
| --- | --- | --- |
| source provenance red | source checks are not tied to the selected package | fix provenance before trusting source-derived results |
| enum extraction red | extracted parser token/tag drift or extractor failure | inspect the patched source and plausibility output |
| corpus red | a packaged upstream statement no longer fits the known schema/baseline | extend the model or justify a named baseline |
| round trip red | a selected case failed to load or emitted an unmodelled command | inspect load logs and serializer output; do not reduce coverage silently |
| JSON integration red | selected rendered JSON is rejected by the packaged parser | fix schema/DSL/renderer or narrow the claim with evidence |
| text/equivalence red | selected native syntax is rejected or differs semantically | fix text rendering or add a narrowly justified named exclusion |
| unstable-only red | the policy's unstable pin failed while stable passed: likely future stable incompatibility | fix before updating the stable floor |
| pin-bump red | the policy's Pin-bump tests failed for this repository with a proposed pin | reproduce with the proposed revision, fix here, then re-run the failed policy jobs |
| drift issue | patched source at a policy pin differs from the lock | review the changed files and the full diff before updating; an unstable issue tracks the next nftables |

## Updating inputs

Update `nixpkgs`, then rerun the checks with the locked input and the policy's
pins:

```console
nix flake update nixpkgs
nix flake check -L
nix run github:petohorvath/nixos-project-policy/v0.6 -- test . --nixpkgs stable
nix run github:petohorvath/nixos-project-policy/v0.6 -- test . --nixpkgs stable --vm
nix run github:petohorvath/nixos-project-policy/v0.6 -- test . --nixpkgs unstable
nix run github:petohorvath/nixos-project-policy/v0.6 -- test . --nixpkgs unstable --vm
```

`nix flake check` builds the VM tests too, so it needs KVM. The policy's
`test --vm` builds the VM tests and skips them on a host without KVM.

When a new NixOS release becomes stable, point `inputs.nixpkgs.url` in
`flake.nix` at its branch before updating. The policy moves its stable pin to
that release, so the stable drift issue stays open until the lock follows.

When `check.yml` moves to a new policy series, change `POLICY` in
`upstream-sync.yml` to the same series; `unit-tests` fails until they agree.

The `flake-parts` input only assembles the flake outputs; its `nixpkgs-lib`
input follows `nixpkgs`. Update it separately with
`nix flake update flake-parts`.

Before merging an input update:

1. inspect the lock diff and package/source revision;
2. run the complete matrix for each supported Linux architecture through a
   matching native or remote builder; do not treat `--all-systems` evaluation
   from one architecture as cross-architecture verification;
3. review any corpus baseline or read-back change against the patched source;
4. keep known differences in code and coverage docs synchronized;
5. confirm that the policy's required statuses pass on the PR.

To reproduce a Pin-bump tests failure, override `nixpkgs` with the proposed
revision from the pin-bump pull request, replacing
`FULL_REVISION_FROM_PULL_REQUEST` with its 40-character revision:

```console
revision=FULL_REVISION_FROM_PULL_REQUEST

nix flake check -L --override-input nixpkgs "github:NixOS/nixpkgs/$revision"
```
