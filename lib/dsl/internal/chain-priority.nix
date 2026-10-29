/*
  A chain's Symbolic priority, resolved to the int nft's JSON `prio` takes.

  `resolve location family body`: `body` with a string `prio` replaced by
  `compatibility.priorityValue family hook prio`, for the body's `hook`.
  `location` is the chain's location (./location.nix). A symbol nft rejects
  at the hook throws the helper's message at `<location>.prio`, which names
  the chain. A symbol without a `hook` or `family` throws too. Any other
  body passes through unchanged, for the schema to check.

  A flowtable keeps an integer `prio`: nft resolves a flowtable's symbol as
  netdev at `ingress`, whatever the table's family (ADR 0009).
*/
{ lib, compatibility }:

let
  inherit (import ./location.nix { inherit lib; }) fail within;
in
location: family: body:
if builtins.isAttrs body && builtins.isString (body.prio or null) then
  let
    at = within location [ "prio" ];
  in
  if builtins.isString family && builtins.isString (body.hook or null) then
    body // { prio = compatibility.resolvePriority (fail at) family body.hook body.prio; }
  else
    fail at "a Symbolic priority resolves for the chain's family and hook; give both, or an int priority"
else
  body
