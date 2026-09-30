/*
  Declarative table builder. `dsl.table` returns a table node that ruleset
  expansion or block rendering turns into nftables commands.
*/
{ lib }:

let
  markers = import ../internal/markers.nix { };
in
/*
  Declare a table and its contents as one tree, so callers do not thread
  family, table, and chain names through each command.

  `family` is the table family, `name` the table name, and `body` the tree.
  Recognized keys in `body`:
    Table-level options: handle, flags, comment
    Object kinds (each: name → body attrset):
      sets, maps, elements, flowtables, counters, quotas, limits,
      ctHelpers, ctTimeouts, ctExpectations, secmarks, synproxies, tunnels
    Chains (name → chainBody), where chainBody may contain:
      type, hook, prio, dev, policy, handle, comment, rules
    rules is a list (order-preserving); each element is either a bare list
    of statements or an attrset `{ expr = [...]; handle?; index?; comment?; }`.

  Nesting owns family/table/name/chain. Explicit matching fields in child
  bodies are accepted, but conflicting values fail during expansion. Use
  standalone commands to choose scope independently of the tree.

  Returns `body` tagged with the table marker, `family`, and `name`. Keys
  are checked lazily, when the node is expanded or rendered.
*/
family: name: body:
body
// {
  "${markers.table}" = true;
  inherit family name;
}
