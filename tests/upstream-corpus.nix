{
  pkgs,
  nftlib,
  nftablesSrc,
}:

# Corpus check in the channel-source pipeline (docs/upstream-sync.md):
# validate nftables' *own* regression corpus against this library's schema.
#
# nftables ships `tests/py/**/*.t.json` — for every rule the project tests,
# the exact libnftables-JSON `expr` array it expects. That is upstream
# telling us, revision by revision, what valid input looks like, including
# constructs we never thought to test. Feeding it through `nftlib.types.
# statement` catches the "schema too restrictive" drift direction (D2) that
# the project's own tests structurally cannot — you cannot write a test for
# a field you do not know exists. Every confirmed gap in docs/spec-coverage.md
# (G1 `rt key ipsec`, G3 `fib result check`, …) is exactly this class, and
# was found by hand audit; this check finds the next one automatically.
#
# `tooling/normalize-corpus.py` flattens the corpus to one JSON document at
# eval time (import-from-derivation); each entry's `expr` is then validated
# statement-by-statement.
#
# # Baseline
#
# The corpus already exercises shapes the schema rejects. They are NOT
# silently ignored: each is classified into a named pattern in
# `knownDivergences` (with the reason and the parser evidence). The check
# fails only on an offending statement that matches NO known pattern — i.e.
# *new* drift introduced by a future channel package update. Patterns that
# stop firing (schema fixed, or corpus changed) are reported as stale so the
# baseline can be pruned. Fixing a baselined gap (schema + renderer + tests)
# is tracked separately in docs/upstream-sync.md; this check's job is to
# stop the set from growing unnoticed.

let
  inherit (pkgs) lib;

  # Normalize the corpus to `[ { file, title, expr }, … ]` (IFD).
  corpusJson = pkgs.runCommandLocal "nft-corpus.json" { nativeBuildInputs = [ pkgs.python3 ]; } ''
    python3 ${../tooling/normalize-corpus.py} ${nftablesSrc}/tests/py > $out
  '';
  corpus = builtins.fromJSON (builtins.readFile corpusJson);

  # True iff `s` type-checks as a `statement`. deepSeq forces the lazy
  # submodule validation; tryEval converts a type error into `false`.
  validates =
    s:
    (builtins.tryEval (
      builtins.deepSeq
        (lib.evalModules {
          modules = [
            { options.v = lib.mkOption { type = nftlib.types.statement; }; }
            { v = s; }
          ];
        }).config.v
        true
    )).success;

  # Every corpus statement the schema rejects, deduped by JSON form.
  offending = lib.unique (
    lib.flatten (map (entry: builtins.filter (s: !(validates s)) entry.expr) corpus)
  );

  # Classify an offending statement into a stable pattern name. Coarser than
  # exact JSON so corpus value-churn (a renamed counter, a different port)
  # doesn't read as new drift. A statement that fits no pattern returns
  # `"UNCLASSIFIED"`, which is never in the baseline → it fails the check.
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

  /*
    Baselined divergence patterns: parser accepts, schema rejects, confirmed
    against the channel `nft -c -j -f`. Value is the reason + fix pointer.
    Keep in sync with docs/upstream-sync.md's "Known corpus divergences".
  */
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

  categoriesSeen = lib.unique (map classify offending);
  newDrift = builtins.filter (s: !(builtins.elem (classify s) knownCategories)) offending;
  staleCategories = lib.subtractLists categoriesSeen knownCategories;

  entryCount = builtins.length corpus;
  fmtList = items: lib.concatMapStringsSep "\n" (x: "    ${x}") items;
  staleNote =
    if staleCategories == [ ] then
      ""
    else
      "\nStale baseline patterns (no longer in corpus — prune from knownDivergences):\n"
      + fmtList staleCategories;

  runTests =
    _pkgs:
    if newDrift == [ ] then
      pkgs.runCommandLocal "nftables-corpus-tests-pass" { } ''
        cat <<'EOF'
        nftables-corpus: ${toString entryCount} corpus rules validated against `statement`.
        ${toString (builtins.length offending)} offending statements, all matching ${toString (builtins.length knownCategories)} baselined divergence patterns.
        ${staleNote}
        EOF
        touch $out
      ''
    else
      pkgs.runCommandLocal "nftables-corpus-tests-fail" { } ''
        cat <<'EOF'
        nftables-corpus: NEW drift — the channel parser's own corpus contains
        ${toString (builtins.length newDrift)} statement shape(s) the schema rejects and that match
        no baselined pattern. This is the test-invisible "schema too
        restrictive" direction (D2). Either extend the schema to accept them
        (preferred) or, if intentionally unsupported, add a pattern to
        `knownDivergences` with the reason.

        New offending statements:
        ${fmtList (map builtins.toJSON newDrift)}
        EOF
        exit 1
      '';
in
{
  inherit
    runTests
    corpus
    offending
    newDrift
    knownDivergences
    ;
}
