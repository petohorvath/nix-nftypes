/*
  Build a Variant namespace: a value called for its common form that also
  carries named variants as attributes.

    variant name base extras
      `name`   is the builder's name under `dsl`, for its errors
      `base`   is the function called when the result is invoked:
               `(variant base …) args  ==  base args`
      `extras` is a plain attrset of named variants reachable by attribute
               access: `.auto`, `.ref`, `.icmp`, …

  Returns `extras` plus a `__functor` that delegates to `base`. A string
  given to a namespace with a `.ref` names an object, so it throws and
  points to `.ref` instead of reaching `base`.

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
    else
      base arg;
}
