/*
  Token drift (docs/upstream-sync.md): tooling/extract-upstream-tokens.py
  reads the package set's patched nftables source and extracts its enum
  tables (family_tbl, rt_key_tbl, fib_result_tbl, meta_templates,
  ct_templates, and data_unit, the byte units), the ct keys
  json_parse_ct_expr takes a direction for (ct_dir_keys, by their
  ct_templates tokens), JSON dispatch tables (stmt_parser_tbl,
  cb_tbl), and the payload protocols and their fields (proto_lookup_byname's
  proto_tbl, by each protocol's templates). Each `testEnumDrift_*` test
  compares one model list with its table (tests/helpers/token-drift.nix;
  the byte units and a limit's rate units both check data_unit) and fails
  on a token only one side has. A token the parser accepts but the model
  lacks goes in lib/schema/primitives.nix, for a payload field in
  lib/schema/payload-fields.nix, or for a tag in the schema's statement or
  expression union with a renderer in lib/text.

  The extractor fails when a table is missing or yields fewer tokens than
  its floor, the count at the locked nixpkgs. Enums parsed via strcmp
  ladders (`matchOperator`, `socketKey`, `osfKey`) are out of its reach.
*/
{
  helpers,
  lib,
  observations,
  ...
}:
let
  run = observations.nftablesEnumExtraction.extract;
  extracted = if run.status == 0 then builtins.fromJSON run.output else { };
  inherit (helpers.tokenDrift) models tables;
  drift = helpers.tokenDrift.drift models extracted;
  agreed = {
    missingFromModel = [ ];
    missingFromSource = [ ];
    staleModelOnly = [ ];
    staleSourceOnly = [ ];
  };
in
lib.mapAttrs' (
  name: tableDrift:
  lib.nameValuePair "testEnumDrift_${name}" {
    expr = tableDrift;
    expected = agreed;
  }
) drift
// {
  testExtractionSucceeds = helpers.runSucceeds run;

  # The extractor reads each table a model list is compared with, and no
  # other.
  testEveryExtractedTableHasAModel = {
    expr = builtins.attrNames extracted;
    expected = tables;
  };

  testCaseNames = {
    expr = builtins.attrNames observations.nftablesEnumExtraction;
    expected = [ "extract" ];
  };
}
