/*
  Shared test helpers. Loads the library under test (and the internal
  modules the suites pin directly) and provides the evaluation probes the
  unit suites and source-side checks share.
*/
{ lib }:
let
  nftlib = import ../../lib { inherit lib; };

  nftSafeIfname = import ../../lib/nft-safe-ifname.nix { };
  nftSafeScalar = import ../../lib/nft-safe-scalar.nix { };
  nftSafeString = import ../../lib/nft-safe-string.nix { };

  # Same wiring as lib/text/default.nix, so drift checks read the exact
  # dispatch tables the production renderers use.
  context = import ../../lib/text/context.nix { inherit lib; };
  primitives = import ../../lib/text/primitives.nix {
    inherit lib nftSafeScalar nftSafeString;
  };
  limit = import ../../lib/text/limit.nix { inherit lib primitives; };
  # Mutual reference between statements and expressions, resolved lazily
  # by the recursive `let`.
  expressions = import ../../lib/text/expressions.nix {
    inherit
      context
      lib
      nftSafeScalar
      primitives
      statements
      ;
  };
  statements = import ../../lib/text/statements.nix {
    inherit
      context
      expressions
      lib
      limit
      nftSafeIfname
      primitives
      ;
  };
  objects = import ../../lib/text/objects.nix {
    inherit
      context
      expressions
      lib
      limit
      nftSafeIfname
      nftSafeScalar
      primitives
      statements
      ;
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

  rejects = render: value: !(evalSucceeds (render value));
in
{
  inherit
    evalSucceeds
    nftlib
    validate
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
    textPrimitives = primitives;
    textRenderers = { inherit expressions objects statements; };
  };

  roundtrip = valueType: value: nftlib.toJson (validate valueType value);

  # Deep-forces the validated value so lazy submodule checks run; false
  # on any type error.
  validates = valueType: value: evalSucceeds (builtins.deepSeq (validate valueType value) true);

  rejectsJson = rejects nftlib.toJson;
  rejectsText = rejects nftlib.toText;
  rejectsTextPretty = rejects nftlib.toTextPretty;

  # Reads a project file relative to the repository root.
  readProjectFile = path: builtins.readFile (../.. + "/${path}");
}
