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

  # The text module itself, so drift checks read the exact dispatch tables
  # the production renderers use.
  text = import ../../lib/text {
    inherit
      lib
      nftSafeIfname
      nftSafeScalar
      nftSafeString
      ;
    clean = import ../../lib/clean.nix { inherit lib; };
  };

  evalSucceeds = expr: (builtins.tryEval expr).success;

  # Type-check a value through a one-option module; throws on mismatch.
  validate =
    valueType: value:
    (lib.evalModules {
      modules = [
        { options.v = lib.mkOption { type = valueType; }; }
        { v = value; }
      ];
    }).config.v;

  # Deep-forces the validated value so lazy submodule checks run; false
  # on any type error.
  validates = valueType: value: evalSucceeds (builtins.deepSeq (validate valueType value) true);

in
{
  inherit
    nftlib
    validate
    validates
    ;

  examples = {
    basicFirewallDsl = import ../../examples/basic-firewall-dsl.nix { inherit nftlib; };
    homeRouterDsl = import ../../examples/home-router-dsl.nix { inherit nftlib; };
  };

  # Internal modules, exercised directly so defence-in-depth checks are
  # pinned independently of the public API. Production callers should
  # not import these paths.
  internals = {
    inherit nftSafeIfname nftSafeScalar;
    textDispatch = text.dispatch;
    textPrimitives = import ../../lib/text/primitives.nix {
      inherit lib nftSafeScalar nftSafeString;
    };
  };

  roundtrip = valueType: value: nftlib.toJson (validate valueType value);

  # Classifies corpus statements the schema rejects; see corpus-drift.nix.
  corpusDrift = import ./corpus-drift.nix {
    inherit lib;
    validatesStatement = validates nftlib.types.statement;
  };

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
    nix-unit test asserting that a recorded probe run failed and that its
    output contains every string in `messages`. On failure the diff shows
    the run's output.
  */
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

  # Reads a project file relative to the repository root.
  readProjectFile = path: builtins.readFile (../.. + "/${path}");
}
