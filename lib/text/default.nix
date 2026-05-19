{
  lib,
  clean,
  nftSafeString,
  nftSafeIfname,
  nftSafeScalar,
}:

# Public entry for the nftables-text renderer.
#
#   toText             — compact imperative form: one command per line,
#                        statements separated by `; ` inside braces.
#   toTextPretty       — multi-line imperative form with indented brace
#                        blocks.
#   toTextBlock        — compact block form for the contents of one
#                        table block (no `add` keyword, no
#                        `<family> <table>` prefix; rules become inline
#                        statements inside their parent chain). Suitable
#                        for embedding inside a `table <fam> <name> {
#                        ... }` wrapper provided by a host module
#                        (e.g. nixpkgs' `networking.nftables.tables.<n>.content`).
#   toTextBlockPretty  — multi-line block form.
#
# Imperative entries consume a validated `ruleset` attrset
# (`{ nftables = [ <command>, ... ]; }`). Block entries consume the same
# envelope but expect every command to be `add <kind>`, with exactly one
# `add table` whose contents become the rendered output.
#
# Internally we run `clean` (from lib/clean.nix) once at the entry, mirroring
# `toJson`'s contract: nested renderers trust their input is already cleaned.

let
  context = import ./context.nix { inherit lib; };
  primitives = import ./primitives.nix { inherit lib nftSafeString; };
  # Mutual reference: `statements` consumes `expressions.renderExpression`,
  # while `renderElem` (in expressions) calls back into
  # `statements.renderStatement` to render element-attached `stmt` lists.
  # Recursive `let` resolves the cycle lazily.
  expressions = import ./expressions.nix {
    inherit
      lib
      context
      primitives
      statements
      nftSafeScalar
      ;
  };
  statements = import ./statements.nix {
    inherit
      lib
      context
      primitives
      expressions
      nftSafeIfname
      ;
  };
  objects = import ./objects.nix {
    inherit
      lib
      context
      primitives
      expressions
      statements
      nftSafeIfname
      nftSafeScalar
      ;
  };
  commands = import ./commands.nix {
    inherit
      lib
      primitives
      objects
      ;
  };

  renderRuleset =
    ctx: ruleset:
    let
      cleaned = clean ruleset;
      cmds =
        if cleaned ? nftables then cleaned.nftables else throw "text: ruleset must have a `nftables` key";
    in
    lib.concatMapStringsSep "\n" (commands.renderCommand ctx) cmds;

  toText = renderRuleset (context.mkCtx { pretty = false; });
  toTextPretty = renderRuleset (context.mkCtx { pretty = true; });

  # Block-form: render the contents of a single `add table … { … }`. The
  # ruleset must come from `dsl.ruleset [ <single dsl.table> ]` (or an
  # equivalent envelope built by hand) — the `add table` self-command is
  # dropped, and the remaining `add <kind>` children become the block
  # body. Verbs other than `add` are rejected (delete/flush/list/etc.
  # don't belong inside a `table { … }` block).
  renderTableBlock =
    ctx: ruleset:
    let
      cleaned = clean ruleset;
      cmds =
        if cleaned ? nftables then
          cleaned.nftables
        else
          throw "text.toTextBlock: input must have an `nftables` key";

      unwrapAdd =
        cmd:
        if cmd ? add then
          cmd.add
        else
          let
            verbs = lib.concatStringsSep ", " (builtins.attrNames cmd);
          in
          throw "text.toTextBlock: only `add` commands belong inside a table block; got [${verbs}]";

      # Drop the `add table` self — the wrapper is the consumer's job —
      # and partition the rest into rules (folded into their parent
      # chain) and everything-else (rendered as top-level block decls).
      bodyCmds = builtins.filter (c: !(c ? table)) (map unwrapAdd cmds);
      parted = lib.partition (c: c ? rule) bodyCmds;
      rulesByChain = lib.groupBy (r: r.chain) (map (c: c.rule) parted.right);
      nonRuleCmds = parted.wrong;

      blockCtx = ctx // {
        block = true;
        inherit rulesByChain;
      };

      renderTopLevel =
        c:
        let
          kind = builtins.head (builtins.attrNames c);
        in
        objects.renderObject blockCtx kind c.${kind};

      # Sanity check for hand-built envelopes — `dsl.ruleset` already
      # guarantees every rule's chain is declared.
      chainNames = lib.concatMap (c: lib.optional (c ? chain) c.chain.name) nonRuleCmds;
      orphanChains = lib.subtractLists chainNames (builtins.attrNames rulesByChain);
    in
    if orphanChains != [ ] then
      throw "text.toTextBlock: rules reference undeclared chains [${lib.concatStringsSep ", " orphanChains}]"
    else
      lib.concatMapStringsSep "\n" renderTopLevel nonRuleCmds;

  toTextBlock = renderTableBlock (context.mkCtx { pretty = false; });
  toTextBlockPretty = renderTableBlock (context.mkCtx { pretty = true; });
in
{
  inherit
    toText
    toTextPretty
    toTextBlock
    toTextBlockPretty
    ;
}
