/*
  Aggregator of pre-built expression field trees. Imports each protocol/group
  file and merges them under one namespace. Users write e.g.:
    inherit (nftlib.dsl.fields) ct ip meta tcp;
    eq tcp.dport 22
    eq ip.saddr "10.0.0.1"

  A leaf is an expression nft loads as written in some rule. A key nft
  loads only with a refinement, such as a fib result without flags or an
  ipsec key without a direction, has no leaf; its `dsl.expr` constructor
  builds it.
*/
{ lib }:

let
  payloadFields = import ./payload.nix { inherit lib; };
  meta = import ./meta.nix { inherit lib; };
  ct = import ./ct.nix { inherit lib; };
  rt = import ./rt.nix { inherit lib; };
  socket = import ./socket.nix { inherit lib; };
  osf = import ./osf.nix { inherit lib; };
  tunnelMeta = import ./tunnelMeta.nix { inherit lib; };
in
payloadFields
// {
  inherit
    ct
    meta
    osf
    rt
    socket
    tunnelMeta
    ;
}
