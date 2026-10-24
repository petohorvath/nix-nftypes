# Flow-offload, meter, and verdict-map statements.
{ lib, statement }:

let
  location = import ../internal/location.nix { inherit lib; };
  reference = import ../internal/reference.nix { inherit lib; };
in
{
  /*
    Offload the flow to a flowtable. `flowtable` is the flowtable name, with
    or without its leading `@`. Returns a flow statement that adds the flow
    to `"@<name>"`, nft's only flow operation. Throws for an attrset,
    pointing to `flow "ft"`, and when `flowtable` is not a string.
  */
  flow =
    flowtable:
    if builtins.isAttrs flowtable then
      location.fail (location.builder [ "flow" ]) "takes the flowtable name alone; write `flow \"ft\"`"
    else
      statement.tagged "flow" "flow" {
        op = "add";
        flowtable = reference.atReference "flow" flowtable;
      };

  /*
    Apply a statement per key through a meter.

    `meter { name; key; statement; size?; }` takes the meter name, the
    per-flow key expression, the statement to apply, and the optional
    maximum entry count. Returns a meter statement. Throws when the body
    doesn't validate, and for `stmt`, pointing to `statement`.
  */
  meter = statement.fromFields { name = "meter"; };

  /*
    Choose a verdict by looking up a key. `key` is the lookup expression and
    `data` the verdict map body, or a named map's name with or without its
    leading `@`. Returns a vmap statement whose named map is `"@<name>"`,
    and throws when its body doesn't validate.
  */
  vmap =
    key: data:
    statement.tagged "vmap" "vmap" {
      inherit key;
      data = if builtins.isString data then reference.atReference "vmap" data else data;
    };
}
