# An anonymous set or map, `{ set = [ … ]; }`, holds at least one element:
# nft rejects an empty one ("Invalid RHS of relational", "Illegal map
# expression data"), in JSON and text alike. A NixOS module that matches
# `cfg.allowedTCPPorts` built one whenever the list was empty.
#
# A verdict map's values are verdicts. nft's JSON parser rejects a string
# such as "accept" ("Could not parse netfilter verdict"), while text loads
# it as the verdict, so the two forms disagreed.
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

  testVmapStringVerdictThrows =
    throws "^nix-nftypes: dsl\\.vmap: the value \"accept\" for the key 22 is a string, which nft's JSON parser rejects; write a verdict, such as `dsl\\.accept` or `dsl\\.jump \"chain\"`$"
    // {
      expr = dsl.vmap tcp.dport [
        [
          22
          "accept"
        ]
      ];
    };

  testSchemaRejectsNonVerdictVmapData = throws "is not of type `verdict map data" // {
    expr = validate types.statement {
      vmap = {
        key.payload = {
          protocol = "tcp";
          field = "dport";
        };
        data.set = [
          [
            22
            1
          ]
        ];
      };
    };
  };

  testVmapTakesVerdicts = {
    expr =
      (dsl.vmap tcp.dport [
        [
          22
          dsl.accept
        ]
        [
          23
          (dsl.jump "c")
        ]
      ]).vmap.data;
    expected.set = [
      [
        22
        { accept = null; }
      ]
      [
        23
        { jump.target = "c"; }
      ]
    ];
  };

  # A named map's reference, bare or as a set, stays vmap data.
  testVmapTakesNamedMap = {
    expr =
      map
        (
          data:
          (validate types.statement {
            vmap = {
              key = tcp.dport;
              inherit data;
            };
          }).vmap.data
        )
        [
          "@m"
          { set = "@m"; }
        ];
    expected = [
      "@m"
      { set = "@m"; }
    ];
  };

  testVerdictMapElementsTakeVerdicts =
    throws "not of type `map body whose elements, for a verdict map, are \\[ key verdict \\] pairs"
    // {
      expr = nftlib.toJson (
        dsl.ruleset [
          (dsl.table "inet" "t" {
            maps.v = {
              type = "inet_service";
              dataType = "verdict";
              elements = [
                [
                  22
                  "accept"
                ]
              ];
            };
          })
        ]
      );
    };

  # A map of another data type takes any value.
  testDataMapTakesValues = {
    expr =
      (validate types.command {
        add.map = {
          family = "inet";
          table = "t";
          name = "m";
          type = "inet_service";
          map = "mark";
          elem = [
            [
              22
              1
            ]
          ];
        };
      }).add.map.map;
    expected = "mark";
  };
}
