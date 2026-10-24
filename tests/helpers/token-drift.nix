/*
  Compares the tokens tooling/extract-upstream-tokens.py reads from the
  patched nftables source with the model's token lists: the enums and the
  statement and expression tags. Takes the model lists and the extracted
  tables, `{ <table> = [ <token> … ]; }`, and returns per table the tokens
  only one side has, beyond the documented `modelOnly` extras. Every list
  is empty when the model and the source agree.
*/
{ lib, nftlib }:
let
  tagsOf = union: builtins.attrNames union.functor.payload.tags;

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
    expressionTag = tagsOf nftlib.types.taggedExpression;
    statementTag = tagsOf nftlib.types.statement;
  };

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
        source = extracted.${name} or null;
        extras = modelOnly.${name} or [ ];
      in
      if source == null then
        { notExtracted = name; }
      else
        {
          missingFromModel = lib.subtractLists model source;
          missingFromSource = lib.subtractLists (source ++ extras) model;
          staleModelOnly = lib.intersectLists extras source;
        }
    ) models;
in
{
  inherit drift models modelOnly;
}
