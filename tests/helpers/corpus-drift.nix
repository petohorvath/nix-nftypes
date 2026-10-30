/*
  Classifies nftables corpus statements the schema rejects. Each offending
  statement maps to a named pattern; baselined patterns (`knownDivergences`)
  are known gaps with their reason, and anything else is new drift.

  Takes the normalized corpus, `[ { file, title, expr }, … ]`.
*/
{ lib, validatesStatement }:
corpus:
let

  # Every corpus statement the schema rejects, deduped by JSON form.
  offending = lib.pipe corpus [
    (map (entry: builtins.filter (s: !(validatesStatement s)) entry.expr))
    lib.flatten
    lib.unique
  ];

  # Classify an offending statement into a stable pattern name. Coarser than
  # exact JSON so corpus value-churn (a renamed counter, a different port)
  # doesn't read as new drift. A statement that fits no pattern returns
  # `"UNCLASSIFIED"`, which is never in the baseline, so it counts as
  # new drift.
  classify =
    s:
    let
      tag = builtins.head (builtins.attrNames s);
      body = s.${tag};
    in
    if body == null then
      "null-body:${tag}"
    else if tag == "match" && (body.op or null) == "!" then
      "op-negation"
    else if builtins.isAttrs body && body ? map then
      "stmt-map:${tag}"
    else
      "UNCLASSIFIED";

  # Baselined divergence patterns: parser accepts, schema rejects, confirmed
  # against the packaged `nft -c -j -f`. Value is the reason + fix pointer.
  # Keep in sync with docs/spec-coverage.md, "Parser input accepted but
  # schema rejected".
  knownDivergences = {
    "op-negation" =
      "match `op:\"!\"` (unary negation); missing from the `matchOperator` enum (strcmp-parsed, so the table extractor cannot see it)";
  };
  knownCategories = builtins.attrNames knownDivergences;

  newDrift = builtins.filter (s: !(builtins.elem (classify s) knownCategories)) offending;
  # Baselined patterns no offending statement matches any more.
  staleCategories = lib.subtractLists (lib.unique (map classify offending)) knownCategories;
in
{
  inherit
    knownDivergences
    newDrift
    offending
    staleCategories
    ;
}
