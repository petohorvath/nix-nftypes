{ lib, statement }:

# Aggregator of action/statement combinators. Each module returns an
# attrset keyed by the statement name so the aggregate is a simple merge.

let
  load = path: import path { inherit lib statement; };
in
lib.foldl' (acc: m: acc // m) { } (
  map load [
    ./counter.nix
    ./last.nix
    ./reject.nix
    ./log.nix
    ./rate.nix
    ./nat.nix
    ./synproxy.nix
    ./queue.nix
    ./ct.nix
    ./flow.nix
    ./misc.nix
  ]
)
