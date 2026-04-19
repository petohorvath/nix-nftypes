{ lib }:

# Aggregator of pre-built expression field trees. Imports each protocol/group
# file and merges them under one namespace. Users write e.g.:
#   inherit (nftlib.dsl.fields) tcp ip ct meta fib;
#   eq tcp.dport 22
#   eq ip.saddr "10.0.0.1"

let
  payloadFields = import ./payload.nix { inherit lib; };
  meta = import ./meta.nix { inherit lib; };
  ct = import ./ct.nix { inherit lib; };
  rt = import ./rt.nix { inherit lib; };
  socket = import ./socket.nix { inherit lib; };
  fib = import ./fib.nix { inherit lib; };
  ipsec = import ./ipsec.nix { inherit lib; };
  tunnelMeta = import ./tunnelMeta.nix { inherit lib; };
in
payloadFields
// {
  inherit
    meta
    ct
    rt
    socket
    fib
    ipsec
    tunnelMeta
    ;
}
