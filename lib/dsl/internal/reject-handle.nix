/*
  nft reads a `handle` only in Read-back, in a Selector, and in `insert`
  and `replace` rule (ADR 0009). It ignores one when it adds, creates, or
  renames an object, and a Table tree adds its objects, so their bodies
  take none. `location` is the body's location (./location.nix) and `body`
  the body. Returns `body`, or throws at its `handle` and points to
  Read-back.
*/
{ lib }:

let
  inherit (import ./location.nix { inherit lib; }) fail within;
in
location: body:
if builtins.isAttrs body && body ? handle then
  fail (within location [ "handle" ])
    "nft ignores a handle on add, create, and rename, and a Table tree adds its objects; a handle appears in Read-back, where nft lists it, and selects an object in a Selector or a rule in insert.rule and replace.rule"
else
  body
