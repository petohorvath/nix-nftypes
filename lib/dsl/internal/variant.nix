/*
  Build a callable attrset that also carries named variants.

    variant base extras
      `base`   is the function called when the result is invoked:
               `(variant base …) args  ==  base args`
      `extras` is a plain attrset of named variants reachable by attribute
               access: `.auto`, `.ref`, `.plain`, …

  Returns `extras` plus a `__functor` that delegates to `base`.

  Example:
    counter = variant
      ({ packets ? null, bytes ? null }: { counter = { … }; })
      {
        auto = { counter = null; };
        ref = name: { counter = name; };
      };

    counter { packets = 0; }    ⇒ via __functor ⇒ base { packets = 0; }
    counter.auto                 ⇒ { counter = null; }
    counter.ref "pkts"           ⇒ { counter = "pkts"; }
*/
{ lib }:

base: extras: extras // { __functor = _self: base; }
