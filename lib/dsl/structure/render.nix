{ lib, validate, objects }:

# Declarative-tree → `[command]` expansion. Consumes table nodes produced by
# ./table.nix and emits the list of `{ add.* = …; }` commands the schema
# accepts. Context (family/table/chain) is injected during the walk; users
# never thread it manually.

let
  compact = import ../internal/compact.nix { inherit lib; };
  rename = import ../internal/rename.nix { inherit lib; };
  markers = import ../internal/markers.nix { inherit lib; };

  # Object-kind configuration: the plural key used in a table body → the
  # singular JSON tag emitted, plus the camelCase→hyphen rename applied to
  # each entry's body before emission.
  objectKinds = {
    sets = {
      tag = "set";
      renameBody = rename.set;
    };
    maps = {
      tag = "map";
      renameBody = rename.set;
    };
    elements = {
      tag = "element";
      renameBody = rename.element;
    };
    flowtables = {
      tag = "flowtable";
      renameBody = lib.id;
    };
    counters = {
      tag = "counter";
      renameBody = lib.id;
    };
    quotas = {
      tag = "quota";
      renameBody = lib.id;
    };
    limits = {
      tag = "limit";
      renameBody = lib.id;
    };
    ctHelpers = {
      tag = "ct helper";
      renameBody = lib.id;
    };
    ctTimeouts = {
      tag = "ct timeout";
      renameBody = lib.id;
    };
    ctExpectations = {
      tag = "ct expectation";
      renameBody = lib.id;
    };
    secmarks = {
      tag = "secmark";
      renameBody = lib.id;
    };
    synproxies = {
      tag = "synproxy";
      renameBody = lib.id;
    };
    # Tunnel bodies have hyphenated top-level keys (src-ipv4, …). The
    # nested `tunnel` attribute's shape depends on `type` and isn't renamed
    # here — users of geneve options write the hyphenated keys directly.
    tunnels = {
      tag = "tunnel";
      renameBody = rename.tunnel;
    };
  };

  # Alphabetical attribute-name listing. `builtins.attrNames` is already
  # sorted; this wrapper documents intent at call sites.
  sortedNames = builtins.attrNames;

  # Emit one `add <kind>` command for a single named object.
  emitObject =
    ctx: pluralKey: name: body:
    let
      cfg = objectKinds.${pluralKey};
      full = compact (
        {
          inherit (ctx) family table;
          inherit name;
        }
        // (cfg.renameBody body)
      );
    in
    {
      add = {
        "${cfg.tag}" = full;
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
  emitRule =
    ctx: entry:
    let
      body = if builtins.isList entry then { expr = entry; } else entry;
      full = compact ({ inherit (ctx) family table chain; } // body);
    in
    {
      add = {
        rule = full;
      };
    };

  # Emit `add chain` for a single chain (rules excluded — see emitChainRules).
  emitChainAdd =
    ctx: name: chainBody:
    let
      full = compact (
        {
          inherit (ctx) family table;
          inherit name;
        }
        // (removeAttrs chainBody [ "rules" ])
      );
    in
    {
      add = {
        chain = full;
      };
    };

  # Emit all `add rule` commands for one chain.
  emitChainRules =
    ctx: name: chainBody:
    map (emitRule (ctx // { chain = name; })) (chainBody.rules or [ ]);

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
      tableAdd = {
        add = {
          table = compact ({ inherit family name; } // tableOpts);
        };
      };
      ctx = {
        inherit family;
        table = name;
      };

      chains = body.chains or { };
      chainNames = sortedNames chains;
      chainAdds = map (name: emitChainAdd ctx name chains.${name}) chainNames;
      ruleAdds = lib.concatMap (name: emitChainRules ctx name chains.${name}) chainNames;
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
