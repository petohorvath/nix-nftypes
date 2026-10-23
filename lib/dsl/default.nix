/*
  Public entry point for the `dsl` layer — a declarative DSL emphasizing:
    - Path-based field access (`fields.tcp.dport` instead of
      `expr.payload "tcp" "dport"`)
    - Top-level operator functions (`eq`, `ne`, `inSet`, `notInSet`, …)
    - Variant namespaces via `__functor` (`counter {…}` vs `counter.auto`)
    - Declarative table structure (`chains.<name>.rules = [...]`) in place
      of context-threading builders
    - CamelCase aliases for hyphenated JSON keys (handled by
      internal/rename.nix)
*/
{
  lib,
  objects,
  expandTable,
  resetOrder,
}:

let
  validate = import ./internal/validate.nix { inherit lib; };

  fields = import ./fields { inherit lib; };
  ops = import ./ops.nix { inherit lib; };
  verdicts = import ./verdicts.nix { inherit lib; };
  exprs = import ./exprs.nix { inherit lib; };
  payload = import ./payload.nix { inherit lib; };
  actions = import ./actions { inherit lib; };
  ruleset = import ./structure/ruleset.nix { inherit expandTable lib resetOrder; };
  table = import ./structure/table.nix { inherit lib; };
  commands = import ./structure/commands.nix { inherit lib objects validate; };
  mergeDisjoint = import ./internal/merge-disjoint.nix { inherit lib; };
in
# One flat namespace plus a few nested ones. The layers must define
# disjoint names; the merge throws on any name two of them define.
mergeDisjoint {
  structure = {
    inherit fields table;
    inherit (ruleset) ruleset;
    # The payload escape hatches are expression constructors like the
    # rest of `expr`.
    expr = mergeDisjoint { inherit exprs payload; };
    inherit (commands)
      add
      create
      delete
      destroy
      flush
      insert
      list
      rename
      replace
      reset
      ;
  };
  inherit ops; # eq, ne, lt, gt, le, ge, inSet, notInSet, hasAnyFlag, match
  inherit verdicts; # accept, drop, continue, return, notrack, jump, goto
  inherit actions; # counter, log, limit, snat, resetStmt, …
}
