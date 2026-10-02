/*
  Token drift (docs/upstream-sync.md): tooling/check-upstream-enums.py
  reads the package set's patched nftables source and compares its
  enum tables (family_tbl, rt_key_tbl, fib_result_tbl, meta_templates)
  and JSON dispatch tables (stmt_parser_tbl, cb_tbl) with the schema's
  accepted tokens and statement / expression tags.

  The checker exits non-zero iff a parser token is missing from the schema
  or extraction collapses below its plausibility floor. Enums parsed via
  strcmp ladders (e.g. `operator`) are out of its reach and listed as "not
  source-checked" in its output.
*/
{
  helpers,
  observations,
  ...
}:
{
  testSchemaCoversParserTokens = helpers.probeSucceeds observations.nftablesEnumExtraction.check;
}
