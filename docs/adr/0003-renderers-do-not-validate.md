# Keep validation explicit: renderers do not validate

Validation is a separate step from rendering. The schema validates values passed through `lib.evalModules`, and the DSL validates the bodies it assembles, but the renderers only clean and serialize, and raw attrsets mixed into `dsl.ruleset` pass through unchanged. This keeps raw attrsets usable as the escape hatch for parser-valid shapes the model does not cover, at the cost that a caller who renders unvalidated input gets no schema check.

## Consequences

Because a raw attrset can reach the text renderer unvalidated, the text renderer carries its own safety checks (see ADR-0004).

## Evidence

- `README.md` "How it is structured": "The renderers are serializers; they do **not** automatically type-check arbitrary raw values."
- `docs/api.md` "Validation model" names three distinct operations (schema validation, DSL construction, rendering) and ends "Cleaning is not validation."
- `docs/dsl-coverage.md` "Validation boundaries": "A raw attrset remains the escape hatch for parser-valid shapes outside the model."
- The comment above `toJson` in `lib/default.nix`; the wording was settled in `a2fd1fd`.
