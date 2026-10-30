/*
  Check a DSL body before anything reads it: a body is data, never a
  module. `location` is the body's location (./location.nix) and `value`
  the body. Returns `value`. Throws, naming the location, when `value`
  isn't an attrset (a string such as `"/sp1"` would otherwise be imported
  as a module file) or when it has `_module`, which would reconfigure its
  validation (`_module.check = false` lets unknown fields through), or
  when it is a module property such as `lib.mkIf`, which only the module
  system resolves (../../module-property.nix).
*/
{ lib }:

let
  inherit (import ./location.nix { inherit lib; }) fail within;
  inherit (import ../../module-property.nix { inherit lib; })
    isModuleProperty
    modulePropertyMessage
    ;
in
location: value:
if !(builtins.isAttrs value) then
  fail location "expected an attribute set of fields, got a ${builtins.typeOf value}"
else if isModuleProperty value then
  fail location (modulePropertyMessage {
    inherit value;
  })
else if value ? _module then
  fail (within location [ "_module" ]) "a body takes the schema's fields only"
else
  value
