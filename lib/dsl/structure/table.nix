/*
  Declarative table builder. `dsl.table` returns a table node that ruleset
  expansion or block rendering turns into nftables commands.
*/
{ lib }:

let
  markers = import ../internal/markers.nix { };
  requireBody = import ../internal/require-body.nix { inherit lib; };
  location = import ../internal/location.nix { inherit lib; };
in
/*
  Declare a table and its contents as one tree, so callers do not thread
  family, table, and chain names through each command.

  `family` is the table family, `name` the table name, and `body` the tree.
  Recognized keys in `body`:
    Table-level options: handle, flags, comment
    Object kinds (each: name → body attrset):
      sets, maps, elements, flowtables, counters, quotas, limits,
      ctHelpers, ctTimeouts, ctExpectations, ctCounts, secmarks, synproxies
    Chains (name → chainBody), where chainBody may contain:
      type, hook, prio, dev, policy, handle, comment, rules
    rules is a list (order-preserving); each element is either a bare list
    of statements or an attrset `{ expr = [...]; index?; comment?; }`.

  Nesting owns family/table/name/chain. Explicit matching fields in child
  bodies, and in `body` itself, are accepted, but conflicting values fail
  during expansion. Use standalone commands to choose scope independently
  of the tree.

  Returns `body` tagged with the table marker, `family`, and `name`. Keys
  are checked lazily, when the node is expanded or rendered.
*/
family: name: body:
let
  tree = location.tableTree family name;
  # The positional value replaces the body's, so a conflict throws when
  # expansion reads it.
  scoped =
    key: positional:
    if body ? ${key} && body.${key} != positional then
      location.fail (location.within tree [ key ])
        "must match its table-tree scope ${builtins.toJSON positional}, got ${builtins.toJSON body.${key}}"
    else
      positional;
in
requireBody tree body
// {
  "${markers.table}" = true;
  family = scoped "family" family;
  name = scoped "name" name;
}
