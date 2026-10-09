# Build rulesets as a declarative table tree over the schema

The DSL describes each table as a declarative table tree (options, named objects, and chains with ordered rules) and expands it into the same schema-shaped commands a hand-written ruleset would contain. It replaced an earlier layer of context-threading builders: plain attrset paths take the place of their closures, and expansion orders the commands (table, chains, named objects, then rules) so that references to chains and named sets resolve within one transaction.

## Considered options

- Context-threading builders (`mkRuleset`, `mkTable`, `mkChain`, `mkRule`, `declareChain`, `inChain`): shipped in `d44234d` and removed by `d858e2c`.

## Consequences

Nesting owns scope: an explicit `family`, `table`, `chain`, or `name` that disagrees with the tree position is an error, and callers who need a different scope use explicit commands or raw commands instead.

## Evidence

- `d44234d` adds the builder layer as "strictly additive, no schema changes" with byte-identical parity tests; `d858e2c` rewrites it as the declarative tree and fixes the expansion order.
- `f956a35` makes the tree own scope and keeps rules with their chains through preparation.
- `docs/dsl-coverage.md` "Construction path" and "Declarative objects and rules"; the parity suite in `tests/suites/dsl-parity.nix`.
