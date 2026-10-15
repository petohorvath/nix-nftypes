/*
  The placement probe's inputs: one base chain per family × chain type ×
  hook in the schema's enums (6 × 3 × 7 = 126), each alone in table
  `<family> t` as chain `c`, at priority 0. An ingress or egress chain
  binds the probe's dummy `eth0`, since those hooks need a device and
  `validChainPlacement` doesn't model devices.
*/
{ lib, nftlib }:
let
  inherit (nftlib) enums;

  deviceHooks = [
    "ingress"
    "egress"
  ];

  placement = family: type: hook: {
    name = "${family}-${type}-${hook}";
    inherit family hook type;
    ruleset.nftables = [
      {
        add.table = {
          inherit family;
          name = "t";
        };
      }
      {
        add.chain = {
          inherit family hook type;
          table = "t";
          name = "c";
          prio = 0;
        }
        // lib.optionalAttrs (builtins.elem hook deviceHooks) { dev = "eth0"; };
      }
    ];
  };
in
{
  placements = lib.concatMap (
    family: lib.concatMap (type: map (placement family type) enums.hook) enums.chainType
  ) enums.family;
}
