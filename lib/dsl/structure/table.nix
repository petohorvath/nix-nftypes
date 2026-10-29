/*
  Declarative table builder. `dsl.table` returns a table node that ruleset
  expansion or block rendering turns into nftables commands.
*/
{ lib }:

let
  inherit (import ../../table-tree-marker.nix { }) marker;
  requireBody = import ../internal/require-body.nix { inherit lib; };
  location = import ../internal/location.nix { inherit lib; };
in
/*
  Declare a table and its contents as one tree, so callers do not thread
  family, table, and chain names through each command.

  `family` is the table family, `name` the table name, and `body` the tree.
  Recognized keys in `body`:
    Table-level options: flags, comment
    Object kinds (each: name → body attrset):
      sets, maps, flowtables, counters, quotas, limits, ctHelpers,
      ctTimeouts, ctExpectations, ctCounts, secmarks, synproxies
    A set or map takes its elements in its own body; `add.element` adds
    elements to one defined elsewhere.
    Chains (name → chainBody), where chainBody may contain:
      type, hook, prio, dev, policy, comment, rules
    prio is an int or a Symbolic priority such as "filter", which resolves
    to its int for the table's family and the chain's hook.
    rules is a list (order-preserving); each element is either a bare list
    of statements or an attrset `{ statements = [...]; index?; comment?; }`.
    No body in the tree takes a `handle`, which nft ignores on add.

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
  "${marker}" = true;
  family = scoped "family" family;
  name = scoped "name" name;
}
