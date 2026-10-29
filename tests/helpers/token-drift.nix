/*
  Compares the tokens tooling/extract-upstream-tokens.py reads from the
  patched nftables source with the model's token lists: the enums, the
  ct keys that take a direction, and the statement and expression tags. Takes the model lists and the extracted
  tables, `{ <table> = [ <token> … ]; }`, and returns per model list the
  tokens only one side has, beyond the documented `modelOnly` extras.
  Every list is empty when the model and the source agree.
*/
{ lib, nftlib }:
let
  tagsOf = union: builtins.attrNames union.functor.payload.tags;

  # The ct keys the ct body takes a direction for, as the schema decides.
  ctDirKeys = builtins.filter (
    key:
    (builtins.tryEval (
      nftlib.validate nftlib.types.expressionBodies.ctBody {
        inherit key;
        dir = "original";
      }
    )).success
  ) nftlib.enums.ctKey;

  # The model's token list for each source-checked table.
  models = {
    inherit (nftlib.enums)
      byteUnit
      ctKey
      family
      fibResult
      limitRateUnit
      metaKey
      rtKey
      ;
    ctDirKey = ctDirKeys;
    expressionTag = tagsOf nftlib.types.taggedExpression;
    statementTag = tagsOf nftlib.types.statement;
  };

  # The source table a model list is compared with, where it has another
  # name: a limit's rate units are `packets` and data_unit's byte units, so
  # both lists check the one table.
  sourceTables = {
    limitRateUnit = "byteUnit";
  };

  # The tables the extractor must read, one per model list without a
  # `sourceTables` entry.
  tables = builtins.attrNames (removeAttrs models (builtins.attrNames sourceTables));

  # Tokens the model accepts that the source table lacks, because the
  # parser accepts them outside the table. A token that shows up in the
  # table fails as stale.
  modelOnly = {
    # json_parse_limit_stmt and the limit object parser test for `packets`
    # before they read the rate in a byte unit.
    limitRateUnit = [ "packets" ];
    # meta_key_parse's backwards-compatibility aliases after the table.
    metaKey = [
      "ibriport"
      "obriport"
      "secpath"
    ];
    # json_parse_stmt handles `vmap` before the table and rejects `xt` as
    # input; the model keeps `xt` for Read-back.
    statementTag = [
      "vmap"
      "xt"
    ];
  };

  drift =
    models: extracted:
    lib.mapAttrs (
      name: model:
      let
        table = sourceTables.${name} or name;
        source = extracted.${table} or null;
        extras = modelOnly.${name} or [ ];
      in
      if source == null then
        { notExtracted = table; }
      else
        {
          missingFromModel = lib.subtractLists model source;
          missingFromSource = lib.subtractLists (source ++ extras) model;
          staleModelOnly = lib.intersectLists extras source;
        }
    ) models;
in
{
  inherit
    drift
    models
    modelOnly
    tables
    ;
}
