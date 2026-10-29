/*
  The placement probe's inputs: one base chain per family × chain type ×
  hook in the schema's enums (6 × 3 × 7 = 126), each alone in table
  `<family> t` as chain `c`, at priority 0. An ingress or egress chain
  binds the probe's dummy `eth0`, since those hooks need a device and
  `validChainPlacement` doesn't model devices.

  The priority probe's inputs: one filter chain per hook each family
  exposes and symbol of nft's priority tables (25 × 7 = 175), as text,
  since JSON and the text renderer take only an int priority.
*/
{ lib, nftlib }:
let
  inherit (nftlib) compatibility enums;

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

  # The symbols of `std_prios` and `bridge_std_prios` in nftables
  # `src/rule.c`, written out so a symbol the tables miss is still probed.
  prioritySymbolNames = [
    "raw"
    "mangle"
    "dstnat"
    "filter"
    "security"
    "srcnat"
    "out"
  ];

  prioritySymbol = family: hook: symbol: {
    name = "${family}-${hook}-${symbol}";
    inherit family hook symbol;
    text = ''
      table ${family} t {
        chain c {
          type filter hook ${hook} priority ${symbol};
          ${lib.optionalString (builtins.elem hook deviceHooks) "devices = { eth0 };"}
        }
      }
    '';
  };
in
{
  placements = lib.concatMap (
    family: lib.concatMap (type: map (placement family type) enums.hook) enums.chainType
  ) enums.family;

  prioritySymbols = lib.concatLists (
    lib.mapAttrsToList (
      family: hooks: lib.concatMap (hook: map (prioritySymbol family hook) prioritySymbolNames) hooks
    ) compatibility.hooksByFamily
  );
}
