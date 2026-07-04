{
  pkgs,
  nftlib,
  nftablesSrc,
}:

# Layer 4 of the upstream-sync pipeline (docs/upstream-sync.md): deterministic
# enum drift detection. Runs `tooling/check-upstream-enums.py` against the
# pinned nftables source and this library's `nftlib.enums`.
#
# This is the zero-AI, zero-false-positive complement to the corpus check and
# the AI watcher: it reads the cleanly-structured C tables (family_tbl,
# rt_key_tbl, fib_result_tbl, meta_templates) and asserts every token they
# accept is in the schema. It catches the exact historical drift class in
# docs/spec-coverage.md (G1 `rt key ipsec`, G3 `fib result check`) and the
# highest-churn enum, `metaKey`. Enums parsed via strcmp ladders (e.g. the
# `operator` enum, where the corpus check found the missing `!`) are out of
# this check's reach and are listed as "not source-checked" in its output.
#
# The script exits non-zero iff a parser token is missing from the schema, so
# the derivation build fails on drift and the report lands in the build log.

let
  schemaJson = pkgs.writeText "schema-enums.json" (builtins.toJSON nftlib.enums);
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
