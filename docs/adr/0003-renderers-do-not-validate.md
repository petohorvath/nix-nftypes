# Keep validation explicit: renderers do not validate

Validation is a separate step from rendering. `validate` checks a value against a schema type, and the DSL validates the bodies it assembles, but the renderers only clean and serialize, and raw attrsets mixed into `dsl.ruleset` pass through unchanged. This keeps raw attrsets usable as the escape hatch for parser-valid shapes the model does not cover, at the cost that a caller who renders unvalidated input gets no schema check.

## Consequences

Because a raw attrset can reach the text renderer unvalidated, the text renderer carries its own safety checks (see ADR-0004).

Checks of a value's shape or position are not validation, so they don't conflict with this decision: the imperative renderers throw for anything but a ruleset, pointing a table tree to `dsl.ruleset`, and `dsl.ruleset` throws for a reset that nft would ignore, raw commands included, without checking any command's contents.

Filling in a field is not validation either: when they clean their input, the imperative renderers give a rule without `expr` the empty list. nft's JSON parser requires the key on a rule even where it ignores it, as for `destroy`, so a raw `destroy` rule loads as JSON as it does as text, while `validate` still returns its input unchanged.

## Evidence

- `README.md` "Validate hand-written rulesets": "The renderers do not validate: they clean and render whatever ruleset or table tree they receive."
- `docs/api.md` "Validation model" names three distinct operations (validation, DSL construction, rendering).
- `validate` in `lib/validate.nix` replaced the `lib.evalModules` pattern the docs showed.
- `docs/dsl-coverage.md` "Validation boundaries": "A raw attrset remains the escape hatch for parser-valid shapes outside the model."
- The comment above `toJson` in `lib/default.nix`; the wording was settled in `a2fd1fd`.
