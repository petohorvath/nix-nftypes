# Shared test helpers. Takes the library under test, `nftlib`, and
# provides the evaluation and assertion helpers the suites share.
{ lib, nftlib }:
let
  evalSucceeds = expr: (builtins.tryEval expr).success;

  inherit (nftlib) validate;
  clean = import ../../lib/clean.nix { inherit lib; };

  # False on any type error; `validate` already forces every check.
  validates = valueType: value: evalSucceeds (validate valueType value);

in
{
  inherit validate validates;

  /*
    `expectedError.msg` patterns for the text renderer's safety refusals.
    Each takes the field label the refusing call site passes and matches
    the whole refusal, from its `nix-nftypes: <renderer>:` prefix to its
    closing `Field: <label>.`, so a refusal of a different field fails the
    test. A Refusal is never hard-wrapped: its explanation is one line,
    followed by an `Offending value:` line when it has a value, and the
    `Field:` line.
  */
  refusals =
    let
      refusal =
        phrase: field:
        "^nix-nftypes: toText(Pretty|Block|BlockPretty)?: ${phrase}[^\n]*(\nOffending value: [^\n]*)?\nField: ${field}\\.$";
    in
    {
      bareToken = refusal "refusing to render a bare nft token";
      ifname = refusal "refusing to render an interface name";
      quotedString = refusal "refusing to render a string containing a character unsafe";
      logPrefix = refusal "refusing to render a log prefix that nft's text would not";
      jsonIgnored = refusal "refusing to render a field that nft's JSON parser ignores";
      namedReference = refusal "refusing to render a named reference without its `@`";
      barePrefix = refusal "refusing to render a bare string containing `/`[^\n]*which `dsl\\.expr\\.prefix` builds";
      unidentified = refusal "refusing to render a string that nft's text would misread";
      noTextSpelling = refusal "refusing to render a value that nft's text has no spelling for";
      typeofMapValue = refusal "refusing to render a map with a datatype key and a typeof value" "map type";
      tunnel = refusal "refusing to render a tunnel object" "tunnel";
      scalar = refusal "refusing to render a scalar string" "expression";
      datatype = refusal "refusing to render a set/map datatype";
      priority = refusal "refusing to render a non-integer chain/flowtable priority";
      setExpression = refusal "refusing to render a `\\{ set = …; \\}` body" "set expression";
      ruleWithoutStatements = refusal "refusing to render a rule without statements" "rule expr";
    };

  # The JSON of `value` once it validates as `valueType`, cleaned as the
  # renderers clean it: the parity suites compare expressions, statements,
  # and commands, and `toJson` takes only a ruleset.
  roundtrip = valueType: value: builtins.toJSON (clean (validate valueType value));

  # The JSON of a ruleset holding just `command`; `toJson` takes only a
  # ruleset.
  commandJson = command: nftlib.toJson (nftlib.dsl.ruleset [ command ]);

  # `word` with its first letter upper-cased, to build a camelCase test
  # name from an attribute name.
  capitalise = word: lib.toUpper (builtins.substring 0 1 word) + builtins.substring 1 (-1) word;

  # Classifies corpus statements the schema rejects; see corpus-drift.nix.
  corpusDrift = import ./corpus-drift.nix {
    inherit lib;
    validatesStatement = validates nftlib.types.statement;
  };

  # The model's source-checked token lists and their Drift; see
  # token-drift.nix.
  tokenDrift = import ./token-drift.nix { inherit lib nftlib; };

  # The tags of a tagged union, or of the tagged unions among a `oneOf`'s
  # branches.
  tagsOf = import ./tags-of.nix;

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
  # run that every nft probe records (tests/helpers/probes/nft.nix). Throws when
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
}
