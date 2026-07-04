{
  pkgs,
  nftlib,
  nftablesSrc,
}:

# Layer 4 of the upstream-sync pipeline (docs/upstream-sync.md): deterministic
# token drift detection. Runs `tooling/check-upstream-enums.py` against the
# pinned nftables source and this library's accepted-token lists.
#
# This is the zero-AI, zero-false-positive complement to the corpus check and
# the AI watcher. Two families of C tables are read:
#
#   - enum tables (family_tbl, rt_key_tbl, fib_result_tbl, meta_templates)
#     vs `nftlib.enums` — the exact historical drift class in
#     docs/spec-coverage.md (G1 `rt key ipsec`, G3 `fib result check`) and
#     the highest-churn enum, `metaKey`;
#   - the JSON dispatch tables (stmt_parser_tbl, cb_tbl) vs the schema's
#     statement / taggedExpression attrTag unions — so "upstream added a
#     whole new statement/expression kind" is a deterministic red, not
#     something only the corpus (if it happens to use it) or the AI would
#     notice. Schema-only leftovers are informational: `vmap` dispatches
#     outside the table and `xt` is modelled but parser-rejected, both
#     documented in spec-coverage.md.
#
# Enums parsed via strcmp ladders (e.g. the `operator` enum, where the
# corpus check found the missing `!`) are out of this check's reach and are
# listed as "not source-checked" in its output.
#
# The script exits non-zero iff a parser token is missing from the schema
# (or extraction collapses below a plausibility floor — see the script), so
# the derivation build fails on drift and the report lands in the build log.

let
  schemaJson = pkgs.writeText "schema-tokens.json" (
    builtins.toJSON {
      enums = nftlib.enums;
      statementTags = builtins.attrNames nftlib.types.statement.functor.payload.tags;
      expressionTags = builtins.attrNames nftlib.types.taggedExpression.functor.payload.tags;
    }
  );
in
{
  runTests =
    _pkgs:
    pkgs.runCommandLocal "upstream-enum-extraction-tests"
      {
        nativeBuildInputs = [ pkgs.python3 ];
      }
      ''
        python3 ${../tooling/check-upstream-enums.py} ${nftablesSrc} ${schemaJson}
        touch $out
      '';
}
