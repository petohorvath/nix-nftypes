/*
  Merge the DSL's layers onto one flat namespace. `layers` maps each
  layer's name to its attrset. Returns their union, and throws naming the
  name and the layers that define it if two layers define the same name,
  where `//` would let one silently shadow the other.
*/
{ lib }:

layers:
let
  # Each name → the layers that define it.
  definers = lib.zipAttrs (lib.mapAttrsToList (layer: lib.mapAttrs (_: _: layer)) layers);
  collisions = lib.filterAttrs (_: layerNames: builtins.length layerNames > 1) definers;
  describe =
    name: layerNames:
    "`${name}' is defined by more than one layer: ${lib.concatStringsSep ", " layerNames}";
in
if collisions == { } then
  lib.mergeAttrsList (builtins.attrValues layers)
else
  throw "nix-nftypes: dsl: ${lib.concatStringsSep "; " (lib.mapAttrsToList describe collisions)}"
