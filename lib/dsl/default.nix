/*
  Public entry point for the `dsl` layer — a declarative DSL emphasizing:
    - Path-based field access (`fields.tcp.dport` instead of
      `payload "tcp" "dport"`)
    - Top-level operator functions (`eq`, `ne`, `inSet`, `within`, …)
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
  resetsRunAsWritten,
}:

let
  validate = import ./internal/validate.nix { inherit lib; };

  fields = import ./fields { inherit lib; };
  ops = import ./ops.nix { inherit lib; };
  verdicts = import ./verdicts.nix { inherit lib; };
  exprs = import ./exprs.nix { inherit lib; };
  payload = import ./payload.nix { inherit lib; };
  actions = import ./actions { inherit lib; };
  ruleset = import ./structure/ruleset.nix { inherit expandTable lib resetsRunAsWritten; };
  table = import ./structure/table.nix { inherit lib; };
  commands = import ./structure/commands.nix { inherit lib objects validate; };
  variant = import ./internal/variant.nix { inherit lib; };
  mergeDisjoint = import ./internal/merge-disjoint.nix { inherit lib; };

  # `reset` exists as both a rule-body statement (e.g. `reset tcpOption`)
  # and a top-level command (e.g. `reset counters in table t`). Merge both
  # forms behind one name via __functor: bare call stays the statement
  # form, sub-attrs expose the per-object-kind command builders.
  reset = variant actions.reset commands.resetCommand;

  # `actions.reset` would otherwise collide with the merged form in the
  # merge below.
  actionsWithoutReset = removeAttrs actions [ "reset" ];
in
# One flat namespace plus a few nested ones. The layers must define
# disjoint names; the merge throws on any name two of them define.
mergeDisjoint {
  structure = {
    inherit fields reset table;
    inherit (ruleset) ruleset;
    expr = exprs;
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
      ;
  };
  inherit payload; # payload, payloadRaw, payloadTunnel
  inherit ops; # eq, ne, lt, gt, le, ge, inSet, notInSet, within, match
  inherit verdicts; # accept, drop, continue, return, notrack, jump, goto
  actions = actionsWithoutReset; # counter, log, limit, snat, … (not reset)
}
