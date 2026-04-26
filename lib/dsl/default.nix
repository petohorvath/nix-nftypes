{ lib, objects }:

# Public entry point for the `dsl` layer — a declarative DSL emphasizing:
#   - Path-based field access (`fields.tcp.dport` instead of `payload "tcp" "dport"`)
#   - Top-level operator functions (`eq`, `ne`, `inSet`, `within`, …)
#   - Variant namespaces via `__functor` (`counter {…}` vs `counter.auto`)
#   - Declarative table structure (`chains.<name>.rules = [...]`) in place
#     of context-threading builders
#   - CamelCase aliases for hyphenated JSON keys (handled by internal/rename.nix)

let
  validate = import ./internal/validate.nix { inherit lib; };

  fields = import ./fields { inherit lib; };
  ops = import ./ops.nix { inherit lib; };
  verdicts = import ./verdicts.nix { inherit lib; };
  exprs = import ./exprs.nix { inherit lib; };
  payload = import ./payload.nix { inherit lib; };
  actions = import ./actions { inherit lib; };
  ruleset = import ./structure/ruleset.nix { inherit lib validate objects; };
  table = import ./structure/table.nix { inherit lib; };
  commands = import ./structure/commands.nix { inherit lib validate objects; };
  variant = import ./internal/variant.nix { inherit lib; };

  # `reset` exists as both a rule-body statement (e.g. `reset tcpOption`)
  # and a top-level command (e.g. `reset counters in table t`). Merge both
  # forms behind one name via __functor: bare call stays the statement
  # form, sub-attrs expose the per-object-kind command builders.
  reset = variant actions.reset commands.resetCommand;

  # `actions.reset` would otherwise shadow the merged form below; drop it
  # so the `// actions` merge doesn't overwrite the combined value.
  actionsWithoutReset = removeAttrs actions [ "reset" ];
in
# Merge everything onto a single flat namespace plus a few nested ones.
# Conflicts would be compile-time errors (attribute collision), so the order
# of `//` is cosmetic — each layer is expected to define disjoint names.
{
  inherit fields table;
  expr = exprs;
  inherit (commands)
    create
    delete
    destroy
    list
    rename
    replace
    insert
    ;
  inherit reset;
}
// payload # payload, payloadRaw, payloadTunnel
// ops # eq, ne, lt, gt, le, ge, inSet, notInSet, within, match
// verdicts # accept, drop, continue, return, notrack, jump, goto
// actionsWithoutReset # counter, log, limit, snat, … (reset handled above)
// ruleset # ruleset, rule, flush, flushTable, flushChain, flushSet, flushMap, flushRuleset
# create / delete / destroy / list / rename / replace / insert / reset are
# exposed above via `inherit (commands) …` so they live at the top of the
# attrset (not lost among `//` layers).
