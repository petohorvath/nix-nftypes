/*
  Build a Variant namespace: a value called for its common form that also
  carries named variants as attributes.

    variant name base extras
      `name`   is the builder's name under `dsl`, for its errors
      `base`   is the function called when the result is invoked:
               `(variant name base …) args  ==  base args`, but for a
               string where `extras` has a `.ref`
      `extras` is a plain attrset of named variants reachable by attribute
               access: `.auto`, `.ref`, `.icmp`, …

  Returns `extras` plus a `__functor` that delegates to `base`. A string
  given to a namespace with a `.ref` names an object, and a map
  expression, `{ map = …; }`, selects one, so each throws and points to
  `.ref` instead of reaching `base`, which would take the map expression
  as a second spelling of `.ref`.

  Example:
    counter = variant "counter"
      ({ packets ? null, bytes ? null }: { counter = { … }; })
      {
        auto = { counter = null; };
        ref = name: { counter = name; };
      };

    counter { packets = 0; bytes = 0; }
                        ⇒ base { packets = 0; bytes = 0; }  (via __functor)
    counter.auto        ⇒ { counter = null; }
    counter.ref "pkts"  ⇒ { counter = "pkts"; }
    counter "pkts"      ⇒ throws, pointing to `counter.ref "pkts"`
*/
{ lib }:

let
  location = import ./location.nix { inherit lib; };
in
name: base: extras:
extras
// {
  __functor =
    _self: arg:
    if builtins.isString arg && extras ? ref then
      location.fail (location.builder [ name ])
        "a string names an object; reference it with `${name}.ref ${builtins.toJSON arg}`, or give the statement's fields as an attribute set"
    else if builtins.isAttrs arg && builtins.attrNames arg == [ "map" ] && extras ? ref then
      location.fail (location.builder [ name ])
        "a map expression selects an object by key; reference it with `${name}.ref (expr.map …)`, or give the statement's fields as an attribute set"
    else
      base arg;
}
