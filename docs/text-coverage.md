# Text renderer coverage

`lib/text/` converts schema-shaped values to nftables' native text grammar. It
is a pure Nix renderer; it does not invoke `nft`.

The JSON renderer is the compatibility target. Text support is tested
separately because JSON and text have different grammars, quoting rules, and
runtime behavior.

## Render modes

| Function | Form |
| --- | --- |
| `toText` | compact imperative commands |
| `toTextPretty` | readable imperative commands |
| `toTextBlock` | compact contents of one table block |
| `toTextBlockPretty` | readable contents of one table block |

Imperative output contains commands such as `add table`, `add chain`, and
`add rule`. Block output accepts one `dsl.table` node, omits the table wrapper,
and emits named objects and chains in block syntax with rules folded into their
parent chains. It rejects top-level `elements.<name>` entries because the
standalone `element` command has no representation inside table-block grammar;
initial elements remain supported inside their set/map definitions.

## Executable evidence

| Check | Current scope | Failure policy |
| --- | --- | --- |
| `text-parity-tests` | expected strings for statements, expressions, objects, and commands | any mismatch fails |
| schema/text drift assertions in `schema-tests` | every schema statement/expression/object tag has a renderer registration | missing registration fails |
| `text-integration-tests` | 9 of the 11 JSON integration cases through `nft -c -f` | any selected-case parse failure fails; 2 named exclusions |
| `text-block-parity-tests` | 24 exact-output, structure, no-op, and rejection assertions | any mismatch fails |
| `text-block-integration-tests` | 4 table cases in compact and pretty form through `nft -c -f` | any parse failure fails |
| `render-equivalence-tests` | 6 selected cases loaded through JSON and text in separate network namespaces, then compared using `nft list ruleset` | a load failure or output difference fails; 5 cases are excluded before execution |

Stable and unstable checks use the corresponding channel's `nft` binary.

The equivalence suite is strong evidence for its six selected cases. It is not
a universal 1:1 guarantee for every schema value.

## Explicit integration exclusions

`tests/text-integration.nix` excludes:

1. `example-home-router-dsl`: its flowtable is named `offload` and a rule uses
   `flow add @offload`. JSON accepts both, but the text grammar treats `offload`
   as reserved in the flowtable-name and flowtable-reference positions.
2. `add-rule-via-tree-and-standalone`: the text check resolves `handle 42`
   against live kernel state and fails because that rule does not exist in the
   isolated namespace. JSON check mode tolerates the dangling handle.

`tests/render-equivalence.nix` additionally excludes:

- `list-table`, because a query cannot be loaded as persistent ruleset state;
- `create-supported-kinds` and `delete-supported-kinds`, because selected
  stateful object commands depend on kernel features unavailable in the test
  namespace.

These exclusions are named in code rather than silently skipped at runtime.
After filtering, every selected equivalence case must load successfully.

## Coverage limits

### JSON-only names and values

The JSON API can represent strings without relying on the text lexer's keyword
and identifier rules. A JSON-valid object name may therefore lack a safe text
spelling. The `offload` flowtable example is the current live-test case.

### Rare or kernel-dependent constructs

Expected-string tests cover more syntax than the isolated live-parser suite can
materialize. Tunnel objects and less common statements may require kernel
modules, device state, or object support unavailable in an unprivileged network
namespace. Their formatting is tested, but not every variant is real-loaded.

### Command state

Commands using handles, indexes, reset/list output, or referenced objects can
be syntactically valid while requiring state that a check-only or empty
namespace does not contain. Those cases need a purpose-built fixture rather
than being treated as generic renderer coverage.

### Raw input

The text renderer accepts raw attrsets for escape-hatch use, but it is not a
schema validator. Defensive token and string assertions block known injection
classes, yet callers should still validate raw configuration with
`nftlib.types.ruleset`.

### Quoting and safety

Several text positions have no general escape syntax. The schema and renderer
therefore reject unsafe quoted strings, interface names, bare scalar tokens,
references, unit names, and priorities instead of emitting ambiguous text.
JSON may be able to carry a value that the text path intentionally refuses.

## Support policy

Use `toJson` when:

- parser compatibility is more important than human-readable output;
- names or values interact with text keywords;
- the construct is listed as a text limitation;
- exact text-path evidence does not exist.

Use `toText*` for cases covered by the parity/live suites or after adding a
focused parser fixture for the required construct.

When extending the renderer:

1. add the expected text to the parity suite;
2. add or update a live-parser case where the environment can support it;
3. add an equivalence case when both paths can be real-loaded;
4. record any necessary named exclusion and its exact external-state reason.
