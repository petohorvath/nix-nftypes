/*
  Aggregator of pre-built expression field trees. Imports each protocol/group
  file and merges them under one namespace. Users write e.g.:
    inherit (nftlib.dsl.fields) ct fib ip meta tcp;
    eq tcp.dport 22
    eq ip.saddr "10.0.0.1"
*/
{ lib }:

let
  payloadFields = import ./payload.nix { inherit lib; };
  meta = import ./meta.nix { inherit lib; };
  ct = import ./ct.nix { inherit lib; };
  rt = import ./rt.nix { inherit lib; };
  socket = import ./socket.nix { inherit lib; };
  fib = import ./fib.nix { inherit lib; };
  osf = import ./osf.nix { inherit lib; };
  ipsec = import ./ipsec.nix { inherit lib; };
  tunnelMeta = import ./tunnelMeta.nix { inherit lib; };
in
payloadFields
// {
  inherit
    ct
    fib
    ipsec
    meta
    osf
    rt
    socket
    tunnelMeta
    ;
}
