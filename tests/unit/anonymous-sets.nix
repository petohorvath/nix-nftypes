# An anonymous set or map, `{ set = [ … ]; }`, holds at least one element:
# nft rejects an empty one ("Invalid RHS of relational", "Illegal map
# expression data"), in JSON and text alike. A NixOS module that matches
# `cfg.allowedTCPPorts` built one whenever the list was empty.
{ nftlib, ... }:
let
  inherit (nftlib) dsl types validate;
  inherit (dsl.fields) tcp;

  rule = statement: {
    add.rule = {
      family = "inet";
      table = "t";
      chain = "c";
      expr = [ statement ];
    };
  };

  emptyListMessage =
    what:
    "${what} is an empty list, which nft rejects as an anonymous set or map; leave the rule out when the list is empty, as with `lib\\.optional \\(xs != \\[ \\]\\) rule`$";

  throws = msg: {
    expectedError = {
      type = "ThrownError";
      inherit msg;
    };
  };
in
{
  testInSetEmptyListThrows =
    throws "^nix-nftypes: dsl\\.inSet: ${emptyListMessage "the right side"}"
    // {
      expr = dsl.inSet tcp.dport [ ];
    };

  testNotInSetEmptyListThrows =
    throws "^nix-nftypes: dsl\\.notInSet: ${emptyListMessage "the right side"}"
    // {
      expr = dsl.notInSet tcp.dport [ ];
    };

  testVmapEmptyListThrows = throws "^nix-nftypes: dsl\\.vmap: ${emptyListMessage "the data"}" // {
    expr = dsl.vmap tcp.dport [ ];
  };

  testExprMapEmptyListThrows =
    throws "^nix-nftypes: dsl\\.expr\\.map: ${emptyListMessage "the data"}"
    // {
      expr = dsl.expr.map tcp.dport [ ];
    };

  testExprSetEmptyListThrows =
    throws "^nix-nftypes: dsl\\.expr\\.set: ${emptyListMessage "the set"}"
    // {
      expr = dsl.expr.set [ ];
    };

  testSchemaRejectsEmptySetInMatch = throws "is not of type `set body \\(a non-empty list" // {
    expr = validate types.command (rule {
      match = {
        op = "==";
        left.payload = {
          protocol = "tcp";
          field = "dport";
        };
        right.set = [ ];
      };
    });
  };

  testSchemaRejectsEmptyVmapData = throws "is not of type `set body \\(a non-empty list" // {
    expr = validate types.command (rule {
      vmap = {
        key.payload = {
          protocol = "tcp";
          field = "dport";
        };
        data.set = [ ];
      };
    });
  };

  # A named set may start empty.
  testNamedSetTakesNoElements = {
    expr =
      (validate types.command {
        add.set = {
          family = "inet";
          table = "t";
          name = "s";
          type = "ipv4_addr";
          elem = [ ];
        };
      }).add.set.elem;
    expected = [ ];
  };

  testNamedSetInTreeTakesNoElements = {
    expr = nftlib.toJson (
      dsl.ruleset [
        (dsl.table "inet" "t" {
          sets.s = {
            type = "ipv4_addr";
            elements = [ ];
          };
        })
      ]
    );
    expected = "{\"nftables\":[{\"add\":{\"table\":{\"family\":\"inet\",\"name\":\"t\"}}},{\"add\":{\"set\":{\"elem\":[],\"family\":\"inet\",\"name\":\"s\",\"table\":\"t\",\"type\":\"ipv4_addr\"}}}]}";
  };
}
