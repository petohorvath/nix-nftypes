{ lib }:

# Ruleset envelope and flush-family commands. For other command kinds
# (create, delete, destroy, list, rename, reset, replace, insert) see
# ./commands.nix. The ruleset renderer passes any bare command attrset
# through unchanged, so users can always drop to raw JSON if needed.

let
  render = import ./render.nix { inherit lib; };
  compact = import ../internal/compact.nix { inherit lib; };
  rename = import ../internal/rename.nix { inherit lib; };
in
{
  # Envelope: flat-maps children into { nftables = [ commands ]; }. Children
  # may be table nodes (expanded into multiple commands), bare command
  # attrsets, or lists of commands.
  ruleset = children: {
    nftables = render.flattenChildren children;
  };

  # -- Flush commands -------------------------------------------------------
  # Schema (objects.nix `flushObject`) accepts: table, chain, set, map,
  # flowtable, ruleset. `flush` bare is the ubiquitous "flush everything"
  # form. The sibling helpers take the object body so callers can supply
  # whatever fields the schema demands — notably, `set`/`map` bodies still
  # require `type` (and `map` for maps) even for a flush-by-name, since
  # the submodule is shared with add-object commands.

  flush = { flush = { ruleset = null; }; };

  # nftables only supports `flush` for table / chain / set / map / ruleset.
  # `flush flowtable` is rejected by the parser ("Unknown object passed to
  # flush command"), even though the library's schema accepts it — omit it
  # from the DSL to make the failure a DSL-level error.
  flushRuleset = body: { flush = { ruleset = body; }; };
  flushTable = body: { flush = { table = body; }; };
  flushChain = body: { flush = { chain = body; }; };
  flushSet = body: { flush = { set = rename.set body; }; };
  flushMap = body: { flush = { map = rename.set body; }; };

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
    {
      add = {
        rule = compact {
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
      };
    };
}
