# Staying in sync with nftables

The schema in `lib/schema/` is hand-derived from nftables' JSON parser and
serializer. nftables evolves over time, while this project must remain usable
with the versions that Nix consumers actually install. The compatibility
authorities are therefore the nftables packages carried by the two flake
inputs—not a separate checkout of nftables upstream `master`.

## Compatibility authorities

There are four package-set snapshots:

| Snapshot | Purpose | How it moves |
|---|---|---|
| Locked `nixpkgs` | Stable compatibility floor; plain check names | `nix flake update nixpkgs` or a deliberate stable-branch change |
| Locked `nixpkgs-unstable` | Early-warning compatibility target; `-unstable` check suffix | `nix flake update nixpkgs-unstable` |
| Current stable branch tip | Preview of the next stable input update | Resolved by the weekly/manual workflow |
| Current unstable branch tip | Preview of the next unstable input update | Resolved by the weekly/manual workflow |

Each snapshot is an oracle on three related surfaces:

1. `pkgs.nftables`, the exact `nft` binary consumers run;
2. `pkgs.nftables.src` plus `pkgs.nftables.patches`, the parser, serializer,
   grammar, documentation, and test corpus from which that binary is built;
3. the snapshot's nixpkgs `lib`, whose module-system behavior is used by the
   schema.

`flake.nix` materializes the source surface with `pkgs.applyPatches`. Using
`pkgs.nftables.src` directly would be subtly wrong because it is the raw
release archive and omits nixpkgs' downstream patches. The resulting trees are
exposed as:

```console
nix build .#nftables-source
nix build .#nftables-source-unstable
```

There are intentionally no `nftables-src` or `libnftnl-src` flake inputs. This
avoids a second version authority and avoids direct Git access to
`git.netfilter.org`. Fixed-output sources and patches are normally served by
the Nix binary cache; the matching binaries remain ordinary nixpkgs packages.
`channel-source-policy-tests` runs once—not per channel—and statically guards
this design in both `flake.nix` and the scheduled workflow.

### What this design does not cover

Changes present only on nftables upstream `master`, but not yet packaged by
either nixpkgs channel, are out of scope. That is deliberate: this is a
consumer-compatibility net, not an upstream-development early-warning service.
Unstable becomes the leading signal once nixpkgs packages a change.

## Drift directions

Drift has two directions:

- **D1 — schema or renderer too permissive.** The library emits a shape that a
  channel's real parser rejects. Live-parser checks catch this when a case
  exercises the path.
- **D2 — schema too restrictive or incomplete.** A channel parser accepts or
  emits a field, enum, tag, or object shape that the schema does not model.
  Hand-written tests cannot reliably discover unknown constructs, so source,
  corpus, extraction, and read-back checks cover this direction.

## Locked-input checks

`flake.nix` instantiates the full channel-dependent check set twice. Stable
owns the plain names; unstable uses the `-unstable` suffix. Thus both the
channel's `nft` and its `lib` behavior are gated on every `nix flake check`.

The nftables-facing checks are:

| Check | Surface | Direction |
|---|---|---|
| `integration-tests` | JSON rendered by the DSL, checked by the real channel `nft` | D1 |
| `text-integration-tests` | Text rendered by the library, checked by the real channel `nft` | D1 |
| `text-block-integration-tests` | Single-table block rendering | D1 |
| `render-equivalence-tests` | JSON and text loaded separately, then listed and compared | D1 / semantics |
| `nftables-source-provenance-tests` | Source and patch derivation identity vs `pkgs.nftables` | meta |
| `nftables-corpus-tests` | nftables' own `tests/py` statement corpus vs the schema | D2 |
| `nftables-enum-extraction-tests` | Parser enum and dispatch tables vs schema tokens | D2 |
| `nftables-roundtrip-tests` | Real `nft -j list ruleset` output vs the schema | D2 / serializer |
| `nftables-tooling-selftests` | Injected defects must turn the drift checks red | meta |

Every source-side check has a stable and unstable instance. If both channels
package identical nftables source, Nix can reuse the fixed-output inputs and
the checks should report the same parser surface; they remain separate so a
future channel divergence is visible immediately.

### Corpus check

nftables ships `tests/py/**/*.t.json`, containing the statement arrays its own
tests expect. `tests/upstream-corpus.nix` validates those statements against
`nftlib.types.statement`. Known intentional or not-yet-fixed gaps are
classified in `knownDivergences`; an unclassified offender fails the check.
Patterns that stop matching are reported as stale so the baseline can shrink.

### Deterministic token extraction

`tests/upstream-enums.nix` and `tooling/check-upstream-enums.py` inspect enum
tables (`family_tbl`, `rt_key_tbl`, `fib_result_tbl`, `meta_templates`) and JSON
dispatch tables (`stmt_parser_tbl`, `cb_tbl`). Every parser token must be
represented by the corresponding schema enum or tagged union. Plausibility
floors make a broken extraction regex fail loudly rather than pass vacuously.

Tokens parsed through free-form `strcmp` ladders are outside this extractor and
remain covered by the corpus, live-parser, source-diff, and review paths.

### Read-back round trip

`tests/upstream-roundtrip.nix` really loads selected cases into an unprivileged
network namespace with the selected channel's `nft`, captures
`nft -j list ruleset`, and validates every emitted command. This covers
`src/json.c` and object bodies, which the statement-only corpus does not.

The runner provides `/etc/protocols` in the namespace. Without it, nftables may
serialize protocol names as numbers, producing forms that its own JSON parser
rejects on re-input. A load-count floor prevents environment failures from
turning the check vacuously green.

### Tooling self-tests

`tests/upstream-selftest.nix` injects missing schema tokens, malformed source
tables, an unbaselined corpus statement, and invalid read-back shapes. The
tests prove that the drift machinery itself still fails in the intended ways.

## Scheduled channel-tip workflow

`.github/workflows/upstream-sync.yml` runs Mondays at 06:00 UTC and supports
manual dispatch. It has two matrix jobs, one per channel.

### `channel-source-watch`

For each input, the job:

1. reads the locked branch and revision from `flake.lock`;
2. resolves the branch tip once and pins the rest of the job to that immutable
   nixpkgs revision;
3. builds the locked and tip `nftables-source` packages;
4. compares NAR content hashes of the fully patched source trees;
5. if they differ, diffs the schema-relevant parser, serializer, grammar, and
   documentation files and uploads `parser.diff`;
6. if they differ, files or updates an issue labelled
   `nixpkgs-nftables-drift`;
7. if they match, closes any open drift issues for that channel as resolved.

The comparison is content-based rather than version-string-based. Nixpkgs can
backport patches without changing `pname`/`version`, and a newer nixpkgs commit
does not necessarily carry newer nftables source.

If `ANTHROPIC_API_KEY` exists, `tooling/drift-triage.sh` drafts a semantic
report from the diff. If the secret is absent—or triage fails—the workflow
still produces a deterministic basic report and files the issue. AI output is
review assistance only; the real parser and deterministic checks are the gate.

### `canary`

For each input, the job resolves the channel tip to an immutable revision and
temporarily applies `--override-input`. It runs these nine checks against the
tip without changing `flake.lock`:

```text
integration-tests
text-integration-tests
text-block-integration-tests
render-equivalence-tests
nftables-source-provenance-tests
nftables-corpus-tests
nftables-enum-extraction-tests
nftables-roundtrip-tests
nftables-tooling-selftests
```

The canary runs even when the nftables source hash is unchanged. A channel can
change `lib`, dependencies, build flags, or the resulting package while still
reporting the same nftables version and source. Nix caching keeps unchanged
work cheap. The job is non-gating (`continue-on-error`) so it reports upcoming
breakage without blocking unrelated work.

## Responding to signals

| Signal | Meaning | Action |
|---|---|---|
| `nftables-source-provenance-tests` red | A source check no longer uses exactly the selected package's source and patch set | Fix the source derivation before trusting other source checks |
| `nftables-enum-extraction-tests` red | The parser accepts a token/tag missing from the schema, or extraction broke | Add the confirmed token and tests, or repair the extractor |
| `nftables-corpus-tests` red | The packaged corpus contains an unmodelled statement shape | Extend the schema/renderer/tests, or document and baseline an intentional gap |
| `nftables-roundtrip-tests` red | The channel serializer emits a shape the schema rejects | Extend the schema, or explicitly baseline a justified divergence |
| `nftables-tooling-selftests` red | The drift net itself is no longer trustworthy | Repair it before relying on any green source result |
| `*-unstable` red while stable is green | Unstable packaged a relevant parser, serializer, dependency, or `lib` change first | Fix before it reaches the next stable channel |
| Stable red while unstable is green | The deployment floor regressed or code relies on unstable-only behavior | Treat as a release blocker |
| `canary` red while locked checks are green | The next update of that channel will break a compatibility check | Reproduce with the exact tip revision shown in the summary; fix before updating |
| `nixpkgs-nftables-drift` issue | A channel tip carries different fully patched nftables source than its lock | Review the deterministic diff and canary results, then update/fix deliberately |

## Updating inputs

Routine update:

```console
nix flake update nixpkgs nixpkgs-unstable
nix flake check
```

The weekly canary previews these moves. When a channel-source issue exists,
review its source diff and canary result before updating. After a successful
update, source hashes should converge and the watcher stops reporting drift.

When a new NixOS release becomes stable:

1. change `inputs.nixpkgs.url` in `flake.nix` to the new `nixos-YY.MM` branch;
2. run `nix flake lock`;
3. run the complete check set;
4. update any documented compatibility exceptions with exact parser evidence.

The workflow reads branch refs from `flake.lock`, so it follows the new stable
branch automatically.

## Known corpus divergences

The authoritative baseline is `knownDivergences` in
`tests/upstream-corpus.nix`. At the current packaged nftables source it covers:

- **`null`-body statement forms** — `{reject:null}`, `{redirect:null}`,
  `{masquerade:null}`, `{log:null}`, and `{queue:null}`;
- **`op:"!"`** — negation accepted by the parser but absent from the schema's
  operator enum;
- **stateful-object-via-map** — `counter`/`quota`/`limit`/`synproxy` with a
  `{map:{…}}` body;
- **`synproxy` flags-only** — a `synproxy` body with `flags` but no
  `mss`/`wscale`.

Each is a real gap that can be removed by extending the schema, renderer, and
tests. The baseline exists only so the checks gate on newly introduced drift.
