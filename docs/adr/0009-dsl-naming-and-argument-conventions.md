# Give every DSL builder the same naming and argument conventions

The 0.1.0 DSL mixed `flush*` builders with `verb.kind` namespaces, `snake_case` with camelCase field names, and positional with attrset arguments for the same fields. 0.2.0 applies one set of rules everywhere, so callers can predict a builder's shape from its kind:

- Each command verb is a `<verb>.<kind>` namespace generated from the object-kind registry, and each builder takes one object body: `add`, `create`, `delete`, `destroy`, `flush`, `list`, `reset`, and `rename`. `replace` and `insert` stay single functions because their only kind is `rule`.
- Every DSL field name is camelCase. The DSL renames it to the JSON key, whether that key uses a hyphen (`queue-threshold`) or an underscore (`rate_unit`).
- A builder takes positional arguments only when every argument is required and there are at most two, as in `eq left right`, `vmap key data`, and `counter.ref name`. Every other builder takes one attrset. `dsl.table family name body` is the one exception, because it mirrors nftables' `table inet filter { … }`.
- A statement whose fields are all optional takes `{ }` for its empty form. Named variants cover forms an attrset cannot express: `.ref name` for a named object and `.auto` for the JSON null body.

## Considered options

- Deprecated aliases with warnings, removed in a later release. 0.1.0 had been out for a day and had almost no users, so one clean break cost less than a deprecation cycle.
- Attrset arguments everywhere except operators. It would have changed `vmap`, `mangle`, and `xt`, which read like their nftables syntax when positional.

## Consequences

- A bare `flush` value cannot also carry `flush.<kind>` builders, because the value is emitted as JSON. Flushing everything is therefore `flush.ruleset { }`, whose empty body stands for the JSON `null`.
- Object bodies, in a table tree or a command builder, still accept the JSON spelling of a key (`rate_unit`, `gc-interval`) because the rename passes unknown keys through. Statement builders reject the JSON spelling as an unexpected argument.

## Evidence

- `lib/dsl/structure/commands.nix` builds every verb namespace with `mkNamespace`; `lib/dsl/internal/rename.nix` holds every rename.
- `testNoPlainVariants`, the `flush.<kind>` and `add.<kind>` cases, and the camelCase cases in `tests/suites/dsl-parity.nix`.
