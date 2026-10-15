/*
  Imperative nftables-text rendering and internal object spelling.

  Imperative entries consume a schema-shaped ruleset attrset
  (`{ nftables = [ <command>, ... ]; }`). The table module (../table.nix)
  owns toTextBlock* and uses the object renderers directly, preserving the
  tree's chain/rule ownership throughout validation and block emission.

  Internally we run `clean` (from lib/clean.nix) once at the entry,
  mirroring `toJson`'s contract: nested renderers trust their input is
  already cleaned.
*/
{
  lib,
  clean,
  nftSafeIfname,
  nftSafeLogPrefix,
  nftSafeScalar,
  nftSafeString,
}:

let
  context = import ./context.nix { inherit lib; };
  inherit (import ../table-tree-marker.nix { }) requireNoTableTree;
  primitives = import ./primitives.nix {
    inherit
      lib
      nftSafeIfname
      nftSafeLogPrefix
      nftSafeScalar
      nftSafeString
      ;
  };
  limit = import ./limit.nix { inherit lib primitives; };
  expressions = import ./expressions.nix {
    inherit
      context
      lib
      nftSafeScalar
      primitives
      ;
  };
  statements = import ./statements.nix {
    inherit
      context
      expressions
      lib
      limit
      primitives
      ;
  };
  objects = import ./objects.nix {
    inherit
      context
      expressions
      lib
      limit
      nftSafeScalar
      primitives
      statements
      ;
  };
  commands = import ./commands.nix {
    inherit
      lib
      limit
      objects
      primitives
      ;
  };

  renderRuleset =
    ctx: ruleset:
    let
      cleaned = clean (requireNoTableTree "text" ruleset);
      rulesetCommands =
        if cleaned ? nftables then
          cleaned.nftables
        else
          throw "nix-nftypes: text: ruleset must have a `nftables` key";
    in
    lib.concatStringsSep "\n" (
      # A dropped command, such as a listing's metainfo, renders as null.
      builtins.filter (line: line != null) (map (commands.renderCommand ctx) rulesetCommands)
    );
in
{
  /*
    Render a ruleset to compact imperative nftables text: one command per
    line, with statements separated by `; ` inside braces.

    The argument is a schema-shaped ruleset (`{ nftables = [ … ]; }`). It is
    cleaned first but not fully type-checked; a missing `nftables` key
    throws, and so does a table tree, alone or among the commands.

    Returns the `.nft` text as a string.
  */
  toText = renderRuleset (context.mkCtx { pretty = false; });

  /*
    Render a ruleset to multi-line imperative nftables text with indented
    brace blocks.

    The argument is a schema-shaped ruleset (`{ nftables = [ … ]; }`),
    handled as in `toText`.

    Returns the `.nft` text as a string.
  */
  toTextPretty = renderRuleset (context.mkCtx { pretty = true; });

  # Internal spelling helpers for lib/table.nix; not exposed by nftlib.
  inherit (objects) renderChainBlock renderObject renderTableBlockOptions;

  # Internals for the test suites, not exposed by nftlib: the dispatch
  # tables read by the schema↔text drift tests, and the primitives the
  # renderer-level safety tests call directly.
  dispatch = {
    expressionTags = expressions.tags;
    objectKinds = objects.renderableKinds;
    statementTags = statements.tags;
  };
  inherit primitives;
}
