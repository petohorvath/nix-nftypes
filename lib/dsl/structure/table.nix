{ lib }:

# Declarative table builder. `dsl.table family name body` returns a table
# node — a marker attrset the renderer later expands into `add table`,
# `add <object-kind>`, `add chain`, and `add rule` commands.
#
# Recognized keys in `body`:
#   Table-level options: handle, flags, comment
#   Object kinds (each: name → body attrset):
#     sets, maps, elements, flowtables, counters, quotas, limits,
#     ctHelpers, ctTimeouts, ctExpectations, secmarks, synproxies, tunnels
#   Chains (name → chainBody), where chainBody may contain:
#     type, hook, prio, dev, policy, handle, comment, rules
#   rules is a list (order-preserving); each element is either a bare list
#   of statements or an attrset `{ expr = [...]; handle?; index?; comment?; }`.

let
  markers = import ../internal/markers.nix { inherit lib; };
in
family: name: body:
body
// {
  "${markers.table}" = true;
  inherit family name;
}
