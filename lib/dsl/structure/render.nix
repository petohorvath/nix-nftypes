{
  lib,
  validate,
  objects,
}:

# Declarative-tree → `[command]` expansion. Consumes table nodes produced by
# ./table.nix and emits the list of `{ add.* = …; }` commands the schema
# accepts. Context (family/table/chain) is injected during the walk; users
# never thread it manually.
#
# Each emit site validates the assembled body against the matching schema
# submodule before wrapping it in a command tag, so a type-mismatched field
# throws at eval time naming the user's tree path (e.g. `chains.c.prio:
# not of type 'null or signed integer'`) — not silently flowing into JSON
# where `nft -j -f` would drop the section.

let
  compact = import ../internal/compact.nix { inherit lib; };
  markers = import ../internal/markers.nix { inherit lib; };

  # Re-key the shared registry by `plural` for table-tree lookup. Each
  # entry carries the singular JSON `tag`, the schema `body` submodule,
  # and the DSL-key → JSON-key `renameBody` function the kind needs.
  objectKindRegistry = import ./object-kinds.nix { inherit lib objects; };
  objectKinds = lib.mapAttrs' (
    _: cfg: lib.nameValuePair cfg.plural (removeAttrs cfg [ "plural" ])
  ) objectKindRegistry;

  # Alphabetical attribute-name listing. `builtins.attrNames` is already
  # sorted; this wrapper documents intent at call sites.
  sortedNames = builtins.attrNames;

  # Emit one `add <kind>` command for a single named object.
  emitObject =
    ctx: pluralKey: name: userBody:
    let
      cfg = objectKinds.${pluralKey};
      full = compact (
        {
          inherit (ctx) family table;
          inherit name;
        }
        // (cfg.renameBody userBody)
      );
      validated = validate {
        type = cfg.body;
        value = full;
        prefix = [
          pluralKey
          name
        ];
      };
    in
    {
      add = {
        "${cfg.tag}" = compact validated;
      };
    };

  # All `add <kind>` commands for every object kind present in `body`.
  emitObjects =
    ctx: body:
    let
      presentKinds = builtins.filter (k: body ? ${k}) (sortedNames objectKinds);
      emitKind =
        pluralKey:
        let
          entries = body.${pluralKey};
        in
        map (name: emitObject ctx pluralKey name entries.${name}) (sortedNames entries);
    in
    lib.concatMap emitKind presentKinds;

  # Emit a single rule, injecting chain context. `entry` is either a bare
  # list of statements or an attrset `{ expr; handle?; index?; comment?; }`.
  # `idx` is the rule's position in the chain's `rules` list — included in
  # the validation prefix so errors say which rule failed.
  emitRule =
    ctx: idx: entry:
    let
      body = if builtins.isList entry then { expr = entry; } else entry;
      full = compact ({ inherit (ctx) family table chain; } // body);
      validated = validate {
        type = objects.ruleBody;
        value = full;
        prefix = [
          "chains"
          ctx.chain
          "rules"
          (toString idx)
        ];
      };
    in
    {
      add = {
        rule = compact validated;
      };
    };

  # Emit `add chain` for a single chain (rules excluded — see emitChainRules).
  emitChainAdd =
    ctx: name: chainBodyValue:
    let
      full = compact (
        {
          inherit (ctx) family table;
          inherit name;
        }
        // (removeAttrs chainBodyValue [ "rules" ])
      );
      validated = validate {
        type = objects.chainBody;
        value = full;
        prefix = [
          "chains"
          name
        ];
      };
    in
    {
      add = {
        chain = compact validated;
      };
    };

  # Emit all `add rule` commands for one chain.
  emitChainRules =
    ctx: name: chainBodyValue:
    lib.imap0 (idx: entry: emitRule (ctx // { chain = name; }) idx entry) (chainBodyValue.rules or [ ]);

  # Full expansion of a single table node into a flat command list.
  # Emission order is chosen so cross-references within the atomic batch
  # always resolve:
  #   1. add table
  #   2. add chain (all chains, empty shells) — must precede (3) because
  #      verdict-map elements and other objects may reference chains by
  #      name, and nftables expects the target chain to already be declared
  #      in the transaction.
  #   3. add <object> (sets, maps, counters, …)
  #   4. add rule (grouped by chain) — must come last because rules
  #      reference both chains (jump/goto) and objects (@name).
  expandTable =
    node:
    let
      inherit (node) family name;
      body = removeAttrs node [
        markers.table
        "family"
        "name"
      ];
      tableOpts = builtins.intersectAttrs {
        handle = null;
        flags = null;
        comment = null;
      } body;
      tableFull = compact ({ inherit family name; } // tableOpts);
      tableValidated = validate {
        type = objects.tableBody;
        value = tableFull;
        prefix = [ ];
      };
      tableAdd = {
        add = {
          table = compact tableValidated;
        };
      };
      ctx = {
        inherit family;
        table = name;
      };

      chains = body.chains or { };
      chainNames = sortedNames chains;
      chainAdds = map (chainName: emitChainAdd ctx chainName chains.${chainName}) chainNames;
      ruleAdds = lib.concatMap (chainName: emitChainRules ctx chainName chains.${chainName}) chainNames;
    in
    [ tableAdd ] ++ chainAdds ++ emitObjects ctx body ++ ruleAdds;

  # Process one child of a ruleset or nested list.
  #   table node → expanded command list
  #   list       → flattened (recurse)
  #   attrset    → passed through as a single command
  flattenChild =
    c:
    if builtins.isAttrs c && (c.${markers.table} or false) then
      expandTable c
    else if builtins.isList c then
      flattenChildren c
    else if builtins.isAttrs c then
      [ c ]
    else
      throw "dsl.ruleset: invalid child — expected table node, command attrset, or list";

  flattenChildren = children: lib.concatMap flattenChild children;
in
{
  inherit flattenChildren expandTable;
}
