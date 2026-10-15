/*
  Shared test helpers. Loads the library under test (and the internal
  modules the suites pin directly) and provides the evaluation and
  assertion helpers the suites share.
*/
{ lib }:
let
  nftlib = import ../../lib { inherit lib; };

  nftSafeIfname = import ../../lib/nft-safe-ifname.nix { };
  nftSafeScalar = import ../../lib/nft-safe-scalar.nix { };
  nftSafeString = import ../../lib/nft-safe-string.nix { };
  nftSafeLogPrefix = import ../../lib/nft-safe-log-prefix.nix { inherit nftSafeString; };

  # The text module itself, so drift checks read the exact dispatch tables
  # the production renderers use.
  text = import ../../lib/text {
    inherit
      lib
      nftSafeIfname
      nftSafeLogPrefix
      nftSafeScalar
      nftSafeString
      ;
    clean = import ../../lib/clean.nix { inherit lib; };
  };

  evalSucceeds = expr: (builtins.tryEval expr).success;

  inherit (nftlib) validate;

  # False on any type error; `validate` already forces every check.
  validates = valueType: value: evalSucceeds (validate valueType value);

in
{
  inherit
    nftlib
    validate
    validates
    ;

  examples = {
    basicFirewall = import ../../examples/basic-firewall.nix { inherit nftlib; };
    basicFirewallDsl = import ../../examples/basic-firewall-dsl.nix { inherit nftlib; };
    homeRouterDsl = import ../../examples/home-router-dsl.nix { inherit nftlib; };
  };

  # The children each table-tree example passes to `dsl.ruleset`, which an
  # Integration case needs for its block form: the example gets a
  # `dsl.ruleset` that returns them as they are.
  exampleChildren =
    let
      childrenOf =
        path:
        import path {
          nftlib = nftlib // {
            dsl = nftlib.dsl // {
              ruleset = lib.id;
            };
          };
        };
    in
    {
      basicFirewallDsl = childrenOf ../../examples/basic-firewall-dsl.nix;
      homeRouterDsl = childrenOf ../../examples/home-router-dsl.nix;
    };

  # Internal modules, exercised directly so defence-in-depth checks are
  # pinned independently of the public API. Production callers should
  # not import these paths.
  internals = {
    inherit nftSafeIfname nftSafeScalar;
    dslMergeDisjoint = import ../../lib/dsl/internal/merge-disjoint.nix { inherit lib; };
    textDispatch = text.dispatch;
    textPrimitives = text.primitives;
  };

  /*
    `expectedError.msg` patterns for the text renderer's safety refusals.
    Each takes the field label the refusing call site passes and matches
    the refusal from its `nix-nftypes: text:` prefix to its closing
    `Field: <label>.`, so a refusal of a different field fails the test.
    The opening phrase may wrap at any space.
  */
  refusals =
    let
      refusal =
        phrase: field:
        "nix-nftypes: text: ${lib.replaceStrings [ " " ] [ "\\s+" ] phrase}[\\s\\S]*Field: ${field}\\.";
    in
    {
      bareToken = refusal "refusing to render a bare nft token";
      ifname = refusal "refusing to render an interface name";
      quotedString = refusal "refusing to render a string containing a character unsafe";
      logPrefix = refusal "refusing to render a log prefix that nft's text would not";
      jsonIgnored = refusal "refusing to render a field that nft's JSON parser ignores";
      namedReference = refusal "refusing to render a named reference without its `@`";
      barePrefix = refusal "refusing to render a bare string containing `/`[\\s\\S]*exprs\\.prefix";
      unidentified = refusal "refusing to render a string that nft's text would misread";
      noTextSpelling = refusal "refusing to render a value that nft's text has no spelling for";
      typeofMapValue = refusal "refusing to render a map with a datatype key and a typeof value" "map type";
      tunnel = refusal "refusing to render a tunnel object" "tunnel";
      scalar = refusal "refusing to render a scalar string" "expression";
      datatype = refusal "refusing to render a set/map datatype";
      priority = refusal "refusing to render a non-integer chain/flowtable priority";
      setExpression = refusal "refusing to render a `\\{ set = …; \\}` body" "set expression";
    };

  roundtrip = valueType: value: nftlib.toJson (validate valueType value);

  # Classifies corpus statements the schema rejects; see corpus-drift.nix.
  corpusDrift = import ./corpus-drift.nix {
    inherit lib;
    validatesStatement = validates nftlib.types.statement;
  };

  # The model's source-checked token lists and their Drift; see
  # token-drift.nix.
  tokenDrift = import ./token-drift.nix { inherit lib nftlib; };

  # The source-provenance tests for one provenance record.
  sourceProvenanceTests = import ./source-provenance.nix { inherit lib; };

  /*
    nix-unit test asserting that a recorded probe run
    (`{ status, output }`) exited zero. On failure the diff shows the
    run's output.
  */
  runSucceeds = run: {
    expr = {
      inherit (run) status;
    }
    // lib.optionalAttrs (run.status != 0) { inherit (run) output; };
    expected.status = 0;
  };

  /*
    nix-unit test asserting that a recorded probe run exited zero with
    exactly `output`.
  */
  runOutputIs = output: run: {
    expr = {
      inherit (run) output status;
    };
    expected = {
      inherit output;
      status = 0;
    };
  };

  /*
    nix-unit test for a Known difference where `nft` misbehaves: asserts
    that the recorded run still exits zero with exactly `misbehaviour`, the
    output nft gives today. It fails once nft stops misbehaving, which is
    the cue to revisit the Known difference (ADR 0010).
  */
  runStillMisbehaves = misbehaviour: run: {
    expr = {
      inherit (run) output status;
    };
    expected = {
      output = misbehaviour;
      status = 0;
    };
  };

  # The package set's nft version, such as "1.1.6", from the `nftVersion`
  # run that every nft probe records (tests/probes/nft.nix). Throws when
  # the run's output is not `nft --version` output.
  nftVersion =
    record:
    let
      matched = builtins.match "nftables v([0-9.]+)[[:space:]].*" record.nftVersion.output;
    in
    if matched == null then
      throw "nftVersion: unrecognised `nft --version` output ${builtins.toJSON record.nftVersion.output}"
    else
      builtins.head matched;

  # A record's case runs, without the `nftVersion` run.
  caseRuns = record: removeAttrs record [ "nftVersion" ];

  # Whether `case` expects nft `version` to reject it: true when the case
  # sets `rejectedBefore` to a newer version, for a form that only a newer
  # tested nft accepts (ADR 0010).
  rejectedOn = version: case: case ? rejectedBefore && lib.versionOlder version case.rejectedBefore;

  # nix-unit test asserting that a recorded probe run failed and that its
  # output contains every string in `messages`. On failure the diff shows
  # the run's output.
  runFailsWith =
    messages: run:
    let
      failed = run.status != 0;
      reported = builtins.all (message: lib.hasInfix message run.output) messages;
    in
    {
      expr = {
        inherit failed reported;
      }
      // lib.optionalAttrs (!(failed && reported)) { inherit (run) output; };
      expected = {
        failed = true;
        reported = true;
      };
    };

  # The schema test generator's walk over the option tree; see
  # option-tree.nix.
  optionTree = import ./option-tree.nix { inherit lib validates; };

  # The reach check's walk over Integration cases and its verdicts.
  reach = import ./reach.nix { inherit lib; };

  # Reads a project file relative to the repository root.
  readProjectFile = path: builtins.readFile (../.. + "/${path}");
}
