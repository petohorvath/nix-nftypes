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
    let
      flowLocation = location.builder [ "flow" ];
    in
    flowtable:
    if builtins.isAttrs flowtable then
      location.fail flowLocation "takes the flowtable name alone; write `flow \"ft\"`"
    else
      statement.tagged { name = "flow"; } {
        op = "add";
        flowtable = reference.atReference flowLocation flowtable;
      };

  /*
    Apply a statement per key through a meter.

    `meter { name; key; statement; size?; }` takes the meter name, the
    per-flow key expression, the statement to apply, and the optional
    maximum entry count. The name declares the meter's set, so it takes
    the bare name: a leading `@` is dropped. Returns a meter statement.
    Throws when the body doesn't validate, and for `stmt`, pointing to
    `statement`.
  */
  meter = statement.fromFields {
    name = "meter";
    prepare = reference.normaliseBareName;
  };

  /*
    Choose a verdict by looking up a key. `key` is the lookup expression and
    `data` a list of `[ key verdict ]` pairs, an anonymous map
    `{ set = [ … ]; }`, or a named map's name with or without its leading
    `@`. Returns a vmap statement whose data is the anonymous map
    `{ set = data; }` for a list and `"@<name>"` for a name, and throws
    when its body doesn't validate. A verdict written as a string, such as
    `"accept"`, which nft's JSON parser rejects, throws and points to the
    verdict's builder.
  */
  vmap =
    key: data:
    let
      stringVerdict = lib.findFirst (
        pair:
        builtins.isList pair && builtins.length pair == 2 && builtins.isString (builtins.elemAt pair 1)
      ) null (if builtins.isList data then data else [ ]);
    in
    if stringVerdict != null then
      location.fail (location.builder [ "vmap" ])
        "the value ${builtins.toJSON (builtins.elemAt stringVerdict 1)} for the key ${builtins.toJSON (builtins.head stringVerdict)} is a string, which nft's JSON parser rejects; write a verdict, such as `dsl.accept` or `dsl.jump \"chain\"`"
    else
      statement.tagged { name = "vmap"; } {
        inherit key;
        data = reference.mapData (location.builder [ "vmap" ]) data;
      };
}
