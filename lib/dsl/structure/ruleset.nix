{
  lib,
  validate,
  objects,
  expandTable,
}:

# Ruleset envelope and flush-family commands. For other command kinds
# (create, delete, destroy, list, rename, reset, replace, insert) see
# ./commands.nix. The ruleset renderer passes any bare command attrset
# through unchanged, so users can always drop to raw JSON if needed.
#
# Each `flush*` helper and the standalone `rule` constructor runs the
# user body through the matching schema submodule before emitting; the
# table-tree path is validated leaf-by-leaf in lib/table.nix.

let
  markers = import ../internal/markers.nix { };
  compact = import ../internal/compact.nix { inherit lib; };
  rename = import ../internal/rename.nix { inherit lib; };

  # Table preparation belongs to the table module. The ruleset only knows
  # how to combine tables, nested lists, and the raw-command escape hatch.
  flattenChild =
    child:
    if builtins.isAttrs child && (child.${markers.table} or false) then
      expandTable child
    else if builtins.isList child then
      flattenChildren child
    else if builtins.isAttrs child then
      [ child ]
    else
      throw "dsl.ruleset: invalid child — expected table node, command attrset, or list";

  flattenChildren = children: lib.concatMap flattenChild children;

  # -- Flush commands -------------------------------------------------------
  # Schema (objects.nix `flushObject`) accepts: table, chain, set, map,
  # meter, ruleset (parser_json.c:4297-4304). `flush` bare is the
  # ubiquitous "flush everything" form. The sibling helpers take the
  # object body so callers can supply whatever fields the schema demands —
  # notably, `set`/`map` bodies still require `type` (and `map` for maps)
  # even for a flush-by-name, since the submodule is shared with add-object
  # commands.
  #
  # `flush flowtable` is intentionally absent from both schema and DSL —
  # the nftables parser rejects it ("Unknown object passed to flush
  # command").
  flushKinds = {
    flushRuleset = {
      tag = "ruleset";
      body = objects.rulesetBody;
    };
    flushTable = {
      tag = "table";
      body = objects.tableBody;
    };
    flushChain = {
      tag = "chain";
      body = objects.chainBody;
    };
    flushSet = {
      tag = "set";
      body = objects.setObjectBody;
      renameBody = rename.set;
    };
    flushMap = {
      tag = "map";
      body = objects.mapObjectBody;
      renameBody = rename.set;
    };
    flushMeter = {
      tag = "meter";
      body = objects.meterObjectBody;
    };
  };

  flushHelpers = lib.mapAttrs (name: cfg: body: {
    flush.${cfg.tag} = validate {
      type = cfg.body;
      value = (cfg.renameBody or lib.id) body;
      prefix = [ name ];
    };
  }) flushKinds;
in
{
  # Envelope: flat-maps children into { nftables = [ commands ]; }. Children
  # may be table nodes (expanded into multiple commands), bare command
  # attrsets, or lists of commands.
  ruleset = children: {
    nftables = flattenChildren children;
  };

  # Bare `flush ruleset` — the ubiquitous "flush everything" form.
  flush = {
    flush = {
      ruleset = null;
    };
  };

  # -- Standalone rule ------------------------------------------------------
  # For use outside a table tree — typically with an explicit handle or
  # index (e.g. to append a rule after a specific existing rule).
  rule =
    {
      family,
      table,
      chain,
      expr,
      handle ? null,
      index ? null,
      comment ? null,
    }:
    let
      body = compact {
        inherit
          family
          table
          chain
          expr
          handle
          index
          comment
          ;
      };
      validated = validate {
        type = objects.ruleBody;
        value = body;
        prefix = [ "rule" ];
      };
    in
    {
      add = {
        rule = compact validated;
      };
    };
}
// flushHelpers
