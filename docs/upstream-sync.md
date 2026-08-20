# Upstream compatibility checks

The project tracks the nftables packages that Nix users install, not an
independent checkout of Netfilter `master`.

## Authorities

Each flake input provides three related authorities:

1. `pkgs.nftables`: the live parser and serializer binary;
2. `pkgs.nftables.src` plus `pkgs.nftables.patches`: the exact patched source
   used to build that binary;
3. `pkgs.lib`: the Nix module/type implementation used by schema validation.

Stable uses the locked `nixpkgs` input. Unstable uses the locked
`nixpkgs-unstable` input. The source trees exposed as `nftables-source` and
`nftables-source-unstable` are produced with `pkgs.applyPatches`; there are no
separate nftables or libnftnl flake inputs.

## Locked-input matrix

`flake.nix` creates every channel-dependent check twice:

- plain name: stable package set;
- `-unstable` suffix: unstable package set.

One additional `channel-source-policy-tests` check statically guards the
single-authority design. Evaluate the exact current list rather than relying on
a copied count:

```console
nix eval --json '.#checks.x86_64-linux' --apply builtins.attrNames | jq .
```

Checks and source packages are exposed for `x86_64-linux` and
`aarch64-linux`. GitHub CI runs the complete matrix on `x86_64-linux`.
Source-derived checks use import-from-derivation, so evaluate each architecture
on a matching native builder; `--all-systems` from one architecture is not a
cross-build path.

### Test groups

| Group | Checks |
| --- | --- |
| Nix/schema/DSL | schema, restricted types, DSL validation, validation messages |
| Renderer behavior | JSON integration, text parity/integration, table-block parity/integration, selected JSON/text equivalence |
| Safety regressions | comments, interface names, verdict targets, scalar/token/reference names, datatypes, units, CT timeout keys, priorities |
| Source drift | provenance, upstream corpus, enum/tag extraction, read-back round trip, tooling self-tests |

The exact attribute names remain the machine-readable source of truth.

## Source-side checks

### Source provenance

`nftables-source-provenance-tests` verifies that source analysis receives the
selected channel's release source and full patch list. Other source results are
not trustworthy if this check fails.

### Upstream statement corpus

`nftables-corpus-tests` normalizes `tests/py/**/*.t.json` from the patched source
and validates each statement against `nftlib.types.statement`.

The check fails on any rejection that does not match a named pattern in
`tests/upstream-corpus.nix`. The current 11 categories are documented in
[`spec-coverage.md`](spec-coverage.md). A pattern that stops matching is
reported as stale.

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

`nftables-roundtrip-tests` real-loads nine selected integration cases in
private network namespaces, captures `nft -j list ruleset`, and validates every
emitted command with `nftlib.types.ruleset`.

Two cases are excluded before execution with exact reasons:

- a standalone rule using nonexistent `handle 42`;
- flowtable offload on dummy devices in an unprivileged namespace.

Every remaining selected case must load. An unexpected load failure now fails
the check instead of reducing coverage. The minimum-loaded floor remains as an
additional vacuous-pass guard. The current read-back divergence baseline is
empty.

This is sampled serializer evidence, not proof that every possible kernel state
or listed object shape has been observed.

### Tooling self-tests

`nftables-tooling-selftests` supplies synthetic source/corpus defects and checks
that enum extraction, corpus classification, and ruleset validation turn red.
It validates the drift net's chosen fault classes, not nftables semantics
themselves.

## Live parser and renderer checks

- `integration-tests` sends selected JSON to `nft -c -j -f` and confirms
  that a raw `create rule` case is rejected by the live parser.
- `text-integration-tests` sends selected native text to `nft -c -f`.
- `text-block-integration-tests` wraps selected block output in a table and
  sends it to the text parser.
- `render-equivalence-tests` real-loads six selected cases through JSON and
  text in separate namespaces and compares `nft list ruleset` output. A load
  failure or difference fails.

Named exclusions and text-only limits are documented in
[`text-coverage.md`](text-coverage.md).

## Weekly channel-tip workflow

[`.github/workflows/upstream-sync.yml`](../.github/workflows/upstream-sync.yml)
runs Mondays at 06:00 UTC and on manual dispatch. Stable and unstable run
independently.

### Patched-source watch

For each channel, the job:

1. reads the channel branch and locked revision from `flake.lock`;
2. resolves the branch tip once to an immutable nixpkgs revision;
3. builds locked and tip patched-source outputs;
4. compares their NAR content hashes;
5. when different, diffs parser/serializer/grammar/reference files and uploads
   `parser.diff`;
6. files or updates a labelled GitHub issue;
7. closes matching open drift issues when locked and tip sources match again.

A hash difference is a review signal, not proof of incompatibility. The full
patched-source NAR hashes are authoritative for whether drift exists.
`parser.diff` is a selected-file diagnostic: it can be incomplete or empty when
the changed source lies outside the fixed review list.

If `ANTHROPIC_API_KEY` is configured, `tooling/drift-triage.sh` can add a prose
summary. Missing or failed AI triage falls back to a basic report and never
changes the deterministic result.

### Canary checks

A separate job overrides one input with the immutable tip revision and runs
nine nftables-facing checks:

1. JSON integration;
2. text integration;
3. table-block integration;
4. JSON/text equivalence;
5. source provenance;
6. upstream corpus;
7. enum/tag extraction;
8. read-back round trip;
9. tooling self-tests.

The job is `continue-on-error: true`: it is an early-warning signal, not a merge
gate. It does not update `flake.lock`.

The source-watch and canary jobs each resolve their own immutable tip. A channel
can move between those resolutions, so compare the revisions shown in the job
summaries when correlating results.

## Interpreting failures

| Signal | Meaning | Response |
| --- | --- | --- |
| source provenance red | source checks are not tied to the selected package | fix provenance before trusting source-derived results |
| enum extraction red | extracted parser token/tag drift or extractor failure | inspect the patched source and plausibility output |
| corpus red | a packaged upstream statement no longer fits the known schema/baseline | extend the model or justify a named baseline |
| round trip red | a selected case failed to load or emitted an unmodelled command | inspect load logs and serializer output; do not reduce coverage silently |
| JSON integration red | selected rendered JSON is rejected by the channel parser | fix schema/DSL/renderer or narrow the claim with evidence |
| text/equivalence red | selected native syntax is rejected or differs semantically | fix text rendering or add a narrowly justified named exclusion |
| unstable-only red | likely future stable incompatibility | fix before updating the stable floor |
| canary-only red | one of the nine selected tip-revision checks failed, or its job environment/tooling failed, while the locked checks remained green | reproduce at the reported immutable revision and inspect the failing check |
| drift issue | patched source at the channel tip differs from the lock | review the artifact and canary before updating |

## Updating inputs

Update one input at a time so failures retain a clear authority:

```console
nix flake update nixpkgs
nix flake check -L

nix flake update nixpkgs-unstable
nix flake check -L
```

Before merging an input update:

1. inspect the lock diff and package/source revision;
2. run the complete matrix for each supported Linux architecture through a
   matching native or remote builder; do not treat `--all-systems` evaluation
   from one architecture as cross-architecture verification;
3. review any corpus baseline or read-back change against the patched source;
4. keep known differences in code and coverage docs synchronized;
5. confirm GitHub CI on `x86_64-linux`.

To reproduce the complete canary at the exact revision from its summary, choose
the matching input and suffix:

- stable: `input=nixpkgs`, `suffix=`;
- unstable: `input=nixpkgs-unstable`, `suffix=-unstable`.

Then run all nine canary targets, replacing `FULL_REVISION_FROM_SUMMARY` with
the 40-character revision printed by the workflow:

```console
input=nixpkgs
suffix=
revision=FULL_REVISION_FROM_SUMMARY

nix build -L \
    --override-input "$input" "github:NixOS/nixpkgs/$revision" \
    ".#checks.x86_64-linux.integration-tests${suffix}" \
    ".#checks.x86_64-linux.text-integration-tests${suffix}" \
    ".#checks.x86_64-linux.text-block-integration-tests${suffix}" \
    ".#checks.x86_64-linux.render-equivalence-tests${suffix}" \
    ".#checks.x86_64-linux.nftables-source-provenance-tests${suffix}" \
    ".#checks.x86_64-linux.nftables-corpus-tests${suffix}" \
    ".#checks.x86_64-linux.nftables-enum-extraction-tests${suffix}" \
    ".#checks.x86_64-linux.nftables-roundtrip-tests${suffix}" \
    ".#checks.x86_64-linux.nftables-tooling-selftests${suffix}"
```
