/*
  Aggregator of pre-built expression field trees. Imports each protocol/group
  file and merges them under one namespace. Users write e.g.:
    inherit (nftlib.dsl.fields) ct ip meta tcp;
    eq tcp.dport 22
    eq ip.saddr "10.0.0.1"

  A leaf is an expression nft loads as written in some rule, though it can
  need a table family or hook there. A key nft loads only with a
  refinement has no leaf, such as a FIB result, which needs `saddr` or
  `daddr` among its flags, or an IPsec key, which needs a direction; its
  `dsl.expr` constructor builds it.
*/
{ lib }:

let
  payloadFields = import ./payload.nix { inherit lib; };
  meta = import ./meta.nix { inherit lib; };
  ct = import ./ct.nix { inherit lib; };
  rt = import ./rt.nix { inherit lib; };
  socket = import ./socket.nix { inherit lib; };
  osf = import ./osf.nix { inherit lib; };
  tunnel = import ./tunnel.nix { inherit lib; };
in
payloadFields
// {
  inherit
    ct
    meta
    osf
    rt
    socket
    tunnel
    ;
}
