/*
  Compares the tokens tooling/extract-upstream-tokens.py reads from the
  patched nftables source with the model's token lists: the enums, the
  ct keys that take a direction, the statement and expression tags, and
  the payload fields, each as `<protocol> <field>`. Takes the model lists
  and the extracted tables, `{ <table> = [ <token> … ]; }`, and returns
  per model list the tokens only one side has, beyond the documented
  `modelOnly` and `sourceOnly` extras. Every list is empty when the model
  and the source agree.
*/
{ lib, nftlib }:
let
  tagsOf = import ./tags-of.nix;

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
    expressionTag = tagsOf nftlib.types.expression;
    payloadField = lib.concatLists (
      lib.mapAttrsToList (
        protocol: map (field: "${protocol} ${field}")
      ) nftlib.enums.payloadFieldsByProtocol
    );
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

  # Tokens the source table holds that the model lacks, because nft does
  # not load them as written. A token that leaves the table fails as
  # stale.
  sourceOnly = {
    # The `meta l4proto` dependency's template, which the payload parser
    # takes as a field and nft loads as a header field at offset 0; and
    # the tunnel headers, whose fields load only in the tunnel form.
    payloadField = [
      "ip l4proto"
      "ip6 l4proto"
      "gre l4proto"
      "gretap l4proto"
      "vxlan flags"
      "vxlan vni"
      "geneve type"
      "geneve vni"
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
        omitted = sourceOnly.${name} or [ ];
      in
      if source == null then
        { notExtracted = table; }
      else
        {
          missingFromModel = lib.subtractLists (model ++ omitted) source;
          missingFromSource = lib.subtractLists (source ++ extras) model;
          staleModelOnly = lib.intersectLists extras source;
          staleSourceOnly = lib.subtractLists source omitted;
        }
    ) models;
in
{
  inherit
    drift
    models
    modelOnly
    sourceOnly
    tables
    ;
}
