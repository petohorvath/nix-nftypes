# Staying in sync with nftables

The schema in `lib/schema/` is hand-derived to be 1:1 with the nftables JSON
parser. nftables keeps evolving — new statements, expressions, fields, enum
values, and meta/ct/rt keys land in `src/parser_json.c` and its lookup tables
every release. This document describes the mechanism that keeps the library in
step with that moving target, and what to do when it fires.

## The problem, precisely

The library has **three version surfaces** that can drift independently:

| | What it pins | How it moves |
|---|---|---|
| **The derivation pin** | `nftables-src` in `flake.lock` — the exact `parser_json.c` the *types* encode | only by `nix flake update nftables-src` |
| **The stable oracle** | `nft` (and `lib`) from the `nixpkgs` input — the current NixOS stable release, the floor consumers deploy on | by `nix flake update nixpkgs`, and deliberately repointed at each NixOS release |
| **The unstable oracle** | `nft` (and `lib`) from the `nixpkgs-unstable` input — where a newer nftables lands first | by `nix flake update nixpkgs-unstable` |

These are decoupled on purpose: the schema is a careful transcription of one
known revision (recorded in the README and `docs/spec-coverage.md`), while the
live-parser tests want to run against every `nft` a consumer is likely to
have — which for a Nix library means **both channels**. The job of this
mechanism is to make any disagreement between these surfaces — and between any
of them and current upstream — **visible and actionable**.

Each channel is an oracle on two axes, not one: its `nft` binary (what the
rendered output must be accepted by) and its nixpkgs `lib` (the module system
the schema types are built on — error-message shapes and `types.*` behavior
can shift between nixpkgs releases). The per-channel check duplication below
covers both.

Drift has **two directions**, and one of them is invisible to the project's own
tests:

- **D1 — schema too permissive.** The schema accepts something a newer parser
  rejects. The integration suite catches this *if* a test case exercises that
  path.
- **D2 — schema too restrictive / incomplete.** A newer parser accepts a field
  or enum value the schema doesn't model. **No hand-written test can catch
  this** — you cannot write a test for a construct you don't know exists. Every
  confirmed gap in `docs/spec-coverage.md` (G1 `rt key ipsec`, G3
  `fib result check`, …) is a D2 gap that was found by manual audit. The layers
  below find the next one automatically.

## The pipeline

Five layers, ordered by how much they're trusted. **Deterministic oracles
decide; AI only drafts** — which preserves the project's core invariant that
the parser, not anyone's reading of it, is the source of truth.

| Layer | Check | Direction | Trust |
|---|---|---|---|
| 0 | `nftables-src` flake input — the pin, machine-readable | — | foundational |
| 1 | `integration-tests-pinned` — DSL cases vs `nft` built from the pin | D1 | live parser |
| 1 | full check set ×2 — every suite against stable `nixpkgs` (plain names) **and** `nixpkgs-unstable` (`-unstable` suffix) | D1 | live parser + module system |
| 1 | `canary` CI job — integration suites vs the floating tip of **each** channel | D1 | live parser |
| 2 | `upstream-corpus-tests` — nftables' own `tests/py` corpus vs the schema | **D2** | upstream's own truth |
| 4 | `upstream-enum-extraction-tests` — C enum **and dispatch-tag** tables vs `nftlib.enums` + the statement/expression unions | **D2** | deterministic extraction |
| 5 | `upstream-roundtrip-tests` — everything `nft -j list ruleset` emits vs the schema | **D2** (serializer side) | live serializer |
| 3 | `drift-watch` workflow + AI triage — diff upstream parser, draft a report | both | AI (gated by 1/2/4/5) |
| — | `upstream-tooling-selftests` — injected drift must turn each check red | meta | self-test |

(The numbering follows the order the layers were designed in, not CI order.)

### Layer 0 — the pin (`flake.nix` / `flake.lock`)

`nftables-src` is a non-flake git input pinned to the exact revision the schema
was derived from. Bumping it (`nix flake update nftables-src`) is the
deliberate, reviewable act of adopting a newer parser. Every other layer reads
its source files from this input, so the pin and the checks can never silently
disagree. A second input, `libnftnl-src`, exists only to build the pinned `nft`
in Layer 1 (a post-1.1.6 nft needs libnftnl symbols newer than nixpkgs ships).

The **library itself never depends on `nftables-src`** — only the checks do.
`nftlib` stays usable standalone; the source tree is a test-time dependency.

### Layer 1 — live-parser conformance, two channels, canary

`nix build .#packages.<system>.nftables-pinned` builds `nft` from the pinned
source. `integration-tests-pinned` runs the full DSL integration case set
against it — "the types are accepted by the exact parser they claim to match."

The channel contract sits next to it: `flake.nix` instantiates the **entire
channel-dependent check set twice**, once against stable `nixpkgs` (plain
check names) and once against `nixpkgs-unstable` (`-unstable` suffix, e.g.
`integration-tests-unstable`). Both run on every `nix flake check`, so "the
library works on stable AND unstable" is PR-gated, not aspirational. The three
pin-anchored checks (`upstream-corpus-tests`, `upstream-enum-extraction-tests`,
`integration-tests-pinned`) are channel-independent and instantiated once, on
stable.

The `canary` job in `.github/workflows/upstream-sync.yml` goes one step
further: a matrix floats each channel input to its branch tip (ref read from
`flake.lock`) and re-runs the integration suites — catching a channel moving
past the locked revs between `nix flake update` runs. A green-pinned /
red-canary split is D1 drift in parser acceptance, surfaced without failing
the build.

A handful of DSL cases depend on pre-existing kernel state (`add rule … handle
N`) that `nft -c` in a fresh netns can't supply. The 1.1.6 release tolerates
these in check mode; the stricter pinned dev parser rejects them. They're
listed in `pinnedConformanceSkip` in `tests/dsl-integration.nix` and skipped
for the pinned run only — a check-mode limitation, not a schema defect.

### Layer 2 — upstream corpus (covers D2)

nftables ships `tests/py/**/*.t.json`: for every rule it tests, the exact
libnftables-JSON `expr` array it expects. `upstream-corpus-tests`
(`tests/upstream-corpus.nix`) validates every one of those statements against
`nftlib.types.statement`. This is upstream telling the library what valid input
looks like, revision by revision — including constructs nobody here thought to
test. `tooling/normalize-corpus.py` flattens the corpus; the check runs the
validation.

The corpus already exercises shapes the schema rejects. They are **not**
silently ignored — each is classified into a named pattern in
`knownDivergences` (with the reason and parser evidence), and the check fails
only on an offending statement matching **no** known pattern, i.e. *new* drift
from a future bump. See [Known corpus divergences](#known-corpus-divergences).

### Layer 4 — deterministic token extraction (covers D2)

`upstream-enum-extraction-tests` (`tests/upstream-enums.nix` →
`tooling/check-upstream-enums.py`) reads the cleanly-structured C lookup tables
in the pinned source and asserts every token they accept is in the schema.
Zero AI, zero false positives. Two table families:

- **enum tables** — `family_tbl`, `rt_key_tbl`, `fib_result_tbl` in
  `parser_json.c` and `meta_templates` in `meta.c`, diffed against
  `nftlib.enums`. Catches the exact historical drift class (G1 `rt key
  ipsec`, G3 `fib result check`) and the highest-churn enum, `metaKey`.
- **dispatch tables** — `stmt_parser_tbl` and `cb_tbl` in `parser_json.c`,
  diffed against the `statement` / `taggedExpression` attrTag unions. This
  makes "upstream added a whole new statement or expression kind" a
  deterministic red instead of something only the corpus (if it happens to
  use it) or the AI would notice. Schema-only leftovers are informational
  (`vmap` dispatches outside the table; `xt` is modelled but
  parser-rejected — both in spec-coverage.md).

Every table also carries a **plausibility floor**: if extraction yields fewer
tokens than the floor (an upstream reformat the regex no longer matches), the
check fails loudly instead of passing vacuously.

Enums parsed via `strcmp` ladders (`operator`, `socketKey`, `osfKey`) are out
of reach and are listed as "not source-checked" in the check's output —
they're the corpus check's and the AI watcher's job. The corpus check already
demonstrated the split by catching the missing `!` (negation) operator, which
`operator` being strcmp-parsed kept out of Layer 4.

### Layer 5 — read-back round-trip (covers the serializer)

`upstream-roundtrip-tests` (`tests/upstream-roundtrip.nix`) tests the
direction every other suite ignores: the **output** side. Each integration
case is really loaded (no `-c`) into a private netns with the pinned `nft`,
`nft -j list ruleset` is captured, and every emitted command is validated
against `nftlib.types.ruleset`. This is the README's "round-trip safe" claim
as a test, and the only deterministic net for two surfaces nothing else
covers: `src/json.c` (the serializer, which evolves independently of
`parser_json.c`) and **object bodies** (the `tests/py` corpus carries only
per-rule statement arrays). Divergences are baselined in
`knownReadbackDivergences` — empty at the current pin — and a load-count
floor refuses a vacuous pass if environment rot stops cases loading.

Building this check surfaced a real upstream asymmetry worth knowing:
`json.c` resolves l4 protocol numbers to names via glibc's
`getprotobynumber`, i.e. `/etc/protocols`. On systems without that file
(minimal containers), `ct helper`/`ct timeout`/`ct expectation` list back
with `"protocol": 6` instead of `"tcp"` — a form `parser_json.c` **rejects**
on input, so on such systems nftables' own listing does not round-trip
through its own parser. The check provides `/etc/protocols` inside the
namespace so the captured listing matches normal systems and stays
deterministic.

### Tooling self-tests

The worst failure mode for a drift net is rotting silently *green* — a dead
extraction regex, an over-broad baseline, a validator that accepts anything.
`upstream-tooling-selftests` (`tests/upstream-selftest.nix`) injects defects
and asserts red: a schema stripped of `rt key ipsec` (G1 reintroduced) and of
the `tproxy` statement tag must produce DRIFT; a renamed C table and a table
the regex can no longer read must fail extraction (not report "no drift"); a
fake corpus statement matching no baseline pattern must land in `newDrift`;
and the `ruleset` validator must reject unknown top tags, fields, and
statements while accepting bare listed objects with handles.

### Layer 3 — scheduled watcher + AI triage (the early warning)

`.github/workflows/upstream-sync.yml` runs weekly. `drift-watch` compares
upstream nftables HEAD against the pinned rev; on a difference it diffs every
mirrored surface — `parser_json.c` and its lookup-table sources (`meta.c`,
`rt.c`), the serializer (`json.c`), the text grammar the text renderer
targets (`parser_bison.y`, `scanner.l`), and the adoc — and hands the diff to
`tooling/drift-triage.sh`, which asks Claude (`claude-opus-4-8`) to classify
each hunk and map it onto the schema, then files (or updates) a GitHub issue
labelled `upstream-drift`.

**Why AI fits here and nowhere else.** The mapping from a C `strcmp` ladder or
`json_unpack` call to a Nix `attrTag` branch or `types.enum` entry is
*semantic*, not syntactic — a plain text diff is too noisy (line shifts,
refactors), and the deterministic checks only cover the structured cases. The
schema files cite exact parser line numbers, which ground the model. But the
output is a **draft for a human**, gated by Layers 1/2/4: an AI-hallucinated
enum value dies at the conformance test against real `nft`. The watcher needs an
`ANTHROPIC_API_KEY` repository secret; without it, `drift-watch` files a bare
drift notice and skips triage.

## Responding to the signals

| Signal | Means | Action |
|---|---|---|
| `upstream-enum-extraction-tests` red | parser accepts an enum token or statement/expression tag the schema lacks — or extraction fell below a plausibility floor | add the token where the report points (`primitives.nix` / `statements.nix` / `expressions.nix`); record a G-N entry in `docs/spec-coverage.md`. On EXTRACTION FAILURE, fix the extractor's registry |
| `upstream-corpus-tests` red (new offender) | parser's own corpus uses a shape the schema rejects | extend the schema to accept it (and add a renderer + test), or, if intentionally unsupported, add a pattern to `knownDivergences` with the reason |
| `upstream-roundtrip-tests` red | the pinned `nft -j list ruleset` emits a shape the schema rejects — serializer or object drift; read-back consumers break | extend the schema (preferred) or baseline in `knownReadbackDivergences` with the reason |
| `upstream-tooling-selftests` red | the drift tooling itself regressed — a check would no longer go red on real drift | fix the tooling first; no other green can be trusted until this passes |
| `integration-tests-pinned` red | the schema emits JSON the pinned `nft` rejects | the schema is too permissive — tighten it |
| a `*-unstable` check red, stable twin green | the unstable channel moved — a newer `nft` rejects something stable accepts, or unstable's `lib` changed module-system behavior/messages | fix ahead of the next stable release, or add a per-oracle skip (the `pinnedConformanceSkip` pattern) with the reason |
| a stable check red, `-unstable` twin green | regression against the deployment floor (rare: a stable-channel backport, or a library change that leans on unstable-only behavior) | treat as a release blocker — stable is the compatibility floor |
| `canary` red for a channel, locked checks green | that channel's tip moved past the locked rev with a behavior change | `nix flake update <input>` and re-run; fix or skip-list what turns red |
| `upstream-drift` issue filed | upstream moved past the pin | read the AI report, apply the confirmed schema changes, then bump the pin |

## Bumping the pin

When adopting a newer nftables:

1. `nix flake update nftables-src` (and `libnftnl-src` if the pinned `nft` no
   longer builds — a stale libnftnl pin is the first thing to check on a build
   failure).
2. `nix flake check` — Layers 2 and 4 will fail loudly on every new D2 gap, and
   `integration-tests-pinned` on every new D1 gap.
3. Apply the schema changes each red check points at (the AI report from
   Layer 3, if one was filed, is a starting draft — verify it against the
   checks, don't trust it).
4. Re-run `nix flake check` until green; prune any now-stale entries the corpus
   check reports.
5. Update the README's "authoritative reference" line and `docs/spec-coverage.md`'s
   "version audited" line to the new rev.

## Bumping the channels

Routine (`nix flake update nixpkgs nixpkgs-unstable`) — moves both channels to
their current tips; the duplicated check set makes any regression visible.
The `canary` job previews exactly this move weekly, so a red canary tells you
what the next update will break before you run it.

When a new NixOS release becomes stable (May / November):

1. Repoint `inputs.nixpkgs.url` in `flake.nix` to the new `nixos-YY.MM` branch
   and `nix flake lock`. The canary matrix follows automatically — it reads
   each input's branch ref from `flake.lock`.
2. `nix flake check`. The old stable's `nft` is no longer tested; if the new
   stable's `nft` is older than something the suite exercises, the failing
   case gets a per-oracle skip (the `pinnedConformanceSkip` pattern in
   `tests/dsl-integration.nix`) with the reason — that skip list *is* the
   stable-compatibility contract, kept explicit.

Note the naming asymmetry is deliberate: stable owns the plain check names
because it is the floor consumers deploy on; unstable is the early-warning
variant. Today both channels ship the same nftables (1.1.6), so the two sets
are near-identical — the value shows the day they diverge.

## Known corpus divergences

Shapes the pinned parser accepts that the schema rejects, confirmed against
`nft -c -j -f`. Baselined so Layer 2 gates on *new* drift; each is a real gap
the schema could close (schema + renderer + tests) as follow-up work. The
authoritative list with reasons is `knownDivergences` in
`tests/upstream-corpus.nix`; as of the current pin:

- **`null`-body statement forms** — `{reject:null}`, `{redirect:null}`,
  `{masquerade:null}`, `{log:null}`, `{queue:null}`. The schema requires an
  object body where the parser allows the bare form.
- **`op:"!"` (negation)** — the `match` operator `!`, missing from the
  `operator` enum. (Caught by Layer 2 because `operator` is strcmp-parsed and so
  invisible to Layer 4.)
- **stateful-object-via-map** — `counter`/`quota`/`limit`/`synproxy` with a
  `{map:{…}}` body (the `<stmt> map { … }` form). The schema bodies have no
  `map` key.
- **`synproxy` flags-only** — a `synproxy` body with only `flags` (no
  `mss`/`wscale`), which the schema over-requires.
