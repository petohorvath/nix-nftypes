/*
  Classifies nftables corpus statements the schema rejects. Each offending
  statement maps to a named pattern; baselined patterns (`knownDivergences`)
  are known gaps with their reason, and anything else is new drift.

  Takes the normalized corpus, `[ { file, title, expr }, … ]`.
*/
{ helpers, lib }:
corpus:
let
  validates = helpers.validates helpers.nftlib.types.statement;

  # Every corpus statement the schema rejects, deduped by JSON form.
  offending = lib.pipe corpus [
    (map (entry: builtins.filter (s: !(validates s)) entry.expr))
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
    else if tag == "synproxy" && body ? flags && !(body ? mss) then
      "synproxy-flags-only"
    else
      "UNCLASSIFIED";

  # Baselined divergence patterns: parser accepts, schema rejects, confirmed
  # against the packaged `nft -c -j -f`. Value is the reason + fix pointer.
  # Keep in sync with docs/upstream-sync.md's "Known corpus divergences".
  knownDivergences = {
    "null-body:reject" =
      "bare `{reject:null}` (default icmp/icmpx reject); schema requires an object body";
    "null-body:redirect" = "bare `{redirect:null}`; schema requires an object body";
    "null-body:masquerade" = "bare `{masquerade:null}`; schema requires an object body";
    "null-body:log" = "bare `{log:null}` (log with no options); schema requires an object body";
    "null-body:queue" = "bare `{queue:null}`; schema requires an object body";
    "op-negation" =
      "match `op:\"!\"` (unary negation); missing from the `operator` enum (strcmp-parsed, so the table extractor cannot see it)";
    "stmt-map:counter" =
      "`counter map { … }` (stateful object selected by map); counter body has no `map` key";
    "stmt-map:quota" = "`quota map { … }`; quota body has no `map` key";
    "stmt-map:limit" = "`limit map { … }`; limit body has no `map` key";
    "stmt-map:synproxy" = "`synproxy map { … }`; synproxy body has no `map` key";
    "synproxy-flags-only" =
      "`synproxy` with only `flags` (no mss/wscale); schema over-requires mss/wscale";
  };
  knownCategories = builtins.attrNames knownDivergences;

  newDrift = builtins.filter (s: !(builtins.elem (classify s) knownCategories)) offending;
in
{
  inherit
    knownDivergences
    newDrift
    offending
    ;
}
