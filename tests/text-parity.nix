{ pkgs, nftlib }:

# Schema-level parity tests for the text renderer (lib/text/).
#
# Each case renders a hand-built attrset through `toText` (compact form)
# and asserts the exact resulting string. Mirrors tests/default.nix's
# round-trip pattern for the JSON renderer: fast, deterministic, no
# shell-out. The live-parser checks live in tests/text-integration.nix.

let
  inherit (pkgs) lib;
  inherit (nftlib) toText;

  # Wrap a single command in a ruleset so toText's entry contract is met.
  one = cmd: toText { nftables = [ cmd ]; };

  tests = {
    # ---- expressions (rendered via the match statement) -----------------
    testMatchPayloadEq = {
      expr = one {
        add.rule = {
          family = "ip";
          table = "t";
          chain = "c";
          expr = [
            {
              match = {
                left = {
                  payload = {
                    protocol = "tcp";
                    field = "dport";
                  };
                };
                op = "==";
                right = 22;
              };
            }
          ];
        };
      };
      expected = "add rule ip t c tcp dport 22";
    };

    testMatchAnonymousSet = {
      expr = one {
        add.rule = {
          family = "ip";
          table = "t";
          chain = "c";
          expr = [
            {
              match = {
                left = {
                  ct = {
                    key = "state";
                  };
                };
                op = "in";
                right = {
                  set = [
                    "established"
                    "related"
                  ];
                };
              };
            }
            { accept = null; }
          ];
        };
      };
      expected = "add rule ip t c ct state { established, related } accept";
    };

    testPrefix = {
      expr = one {
        add.rule = {
          family = "ip";
          table = "t";
          chain = "c";
          expr = [
            {
              match = {
                left = {
                  payload = {
                    protocol = "ip";
                    field = "saddr";
                  };
                };
                op = "==";
                right = {
                  prefix = {
                    addr = "10.0.0.0";
                    len = 8;
                  };
                };
              };
            }
          ];
        };
      };
      expected = "add rule ip t c ip saddr 10.0.0.0/8";
    };

    testRange = {
      expr = one {
        add.rule = {
          family = "ip";
          table = "t";
          chain = "c";
          expr = [
            {
              match = {
                left = {
                  payload = {
                    protocol = "tcp";
                    field = "dport";
                  };
                };
                op = "==";
                right = {
                  range = [
                    1024
                    65535
                  ];
                };
              };
            }
          ];
        };
      };
      expected = "add rule ip t c tcp dport 1024-65535";
    };

    testBinopPrec = {
      expr = one {
        add.rule = {
          family = "ip";
          table = "t";
          chain = "c";
          expr = [
            {
              match = {
                left = {
                  "&" = [
                    {
                      "|" = [
                        "a"
                        "b"
                      ];
                    }
                    "c"
                  ];
                };
                op = "==";
                right = "1";
              };
            }
          ];
        };
      };
      expected = "add rule ip t c (a | b) & c 1";
    };

    testMapLookup = {
      expr = one {
        add.rule = {
          family = "ip";
          table = "t";
          chain = "c";
          expr = [
            {
              dnat = {
                addr = "10.0.0.10";
                family = "ip";
                port = {
                  map = {
                    key = {
                      payload = {
                        protocol = "tcp";
                        field = "dport";
                      };
                    };
                    data = "@port_forward";
                  };
                };
              };
            }
          ];
        };
      };
      expected = "add rule ip t c dnat ip to 10.0.0.10:tcp dport map @port_forward";
    };

    # ---- statements -----------------------------------------------------
    testCounterInline = {
      expr = one {
        add.rule = {
          family = "ip";
          table = "t";
          chain = "c";
          expr = [
            {
              counter = {
                packets = 10;
                bytes = 500;
              };
            }
            { accept = null; }
          ];
        };
      };
      expected = "add rule ip t c counter packets 10 bytes 500 accept";
    };

    testLimitDefaultBurst = {
      expr = one {
        add.rule = {
          family = "ip";
          table = "t";
          chain = "c";
          expr = [
            {
              limit = {
                rate = 10;
                per = "minute";
                burst = 5;
              };
            }
          ];
        };
      };
      expected = "add rule ip t c limit rate 10/minute burst 5 packets";
    };

    testRejectIcmp = {
      expr = one {
        add.rule = {
          family = "ip";
          table = "t";
          chain = "c";
          expr = [
            {
              reject = {
                type = "icmp";
                expr = "host-unreachable";
              };
            }
          ];
        };
      };
      expected = "add rule ip t c reject with icmp host-unreachable";
    };

    testLogPrefix = {
      expr = one {
        add.rule = {
          family = "ip";
          table = "t";
          chain = "c";
          expr = [
            {
              log = {
                prefix = "DROP ";
                level = "info";
              };
            }
          ];
        };
      };
      expected = ''add rule ip t c log prefix "DROP " level info'';
    };

    testCtAssignmentQuoted = {
      expr = one {
        add.rule = {
          family = "ip";
          table = "t";
          chain = "c";
          expr = [
            { "ct helper" = "ftp-helper"; }
          ];
        };
      };
      expected = ''add rule ip t c ct helper set "ftp-helper"'';
    };

    # ---- objects --------------------------------------------------------
    testTableMinimal = {
      expr = one {
        add.table = {
          family = "inet";
          name = "main";
        };
      };
      expected = "add table inet main";
    };

    testBaseChain = {
      expr = one {
        add.chain = {
          family = "inet";
          table = "main";
          name = "input";
          type = "filter";
          hook = "input";
          prio = 0;
          policy = "drop";
        };
      };
      expected = "add chain inet main input { type filter hook input priority 0; policy drop }";
    };

    testRegularChain = {
      expr = one {
        add.chain = {
          family = "inet";
          table = "main";
          name = "tcp_in";
        };
      };
      expected = "add chain inet main tcp_in";
    };

    testNetdevChain = {
      expr = one {
        add.chain = {
          family = "netdev";
          table = "filter";
          name = "ingress";
          type = "filter";
          hook = "ingress";
          prio = -100;
          dev = "eth0";
        };
      };
      expected = ''add chain netdev filter ingress { type filter hook ingress device "eth0" priority -100 }'';
    };

    testSetWithFlagsAndElems = {
      expr = one {
        add.set = {
          family = "inet";
          table = "main";
          name = "trusted";
          type = "ipv4_addr";
          flags = [ "interval" ];
          elem = [
            {
              prefix = {
                addr = "10.0.0.0";
                len = 8;
              };
            }
          ];
        };
      };
      expected = "add set inet main trusted { type ipv4_addr; flags interval; elements = { 10.0.0.0/8 } }";
    };

    testMapWithElems = {
      expr = one {
        add.map = {
          family = "inet";
          table = "main";
          name = "ports";
          type = "inet_service";
          map = "inet_service";
          elem = [
            [
              80
              8080
            ]
            [
              443
              8443
            ]
          ];
        };
      };
      expected = "add map inet main ports { type inet_service : inet_service; elements = { 80 : 8080, 443 : 8443 } }";
    };

    testElement = {
      expr = one {
        add.element = {
          family = "inet";
          table = "main";
          name = "trusted";
          elem = [
            "8.8.8.8"
            "1.1.1.1"
          ];
        };
      };
      expected = "add element inet main trusted { 8.8.8.8, 1.1.1.1 }";
    };

    testFlowtable = {
      expr = one {
        add.flowtable = {
          family = "inet";
          table = "main";
          name = "ft1";
          hook = "ingress";
          prio = 0;
          dev = [
            "eth0"
            "eth1"
          ];
        };
      };
      expected = "add flowtable inet main ft1 { hook ingress priority 0; devices = { eth0, eth1 } }";
    };

    testCounterObject = {
      expr = one {
        add.counter = {
          family = "ip";
          table = "filter";
          name = "ctr";
          packets = 100;
          bytes = 5000;
        };
      };
      expected = "add counter ip filter ctr { packets 100 bytes 5000 }";
    };

    testQuotaOver = {
      expr = one {
        add.quota = {
          family = "ip";
          table = "filter";
          name = "q";
          bytes = 1000000;
          inv = true;
        };
      };
      expected = "add quota ip filter q { over 1000000 bytes }";
    };

    testLimitObject = {
      expr = one {
        add.limit = {
          family = "ip";
          table = "filter";
          name = "lim";
          rate = 5;
          per = "second";
          burst = 10;
        };
      };
      expected = "add limit ip filter lim { rate 5/second burst 10 packets }";
    };

    testCtTimeoutPolicy = {
      expr = one {
        add."ct timeout" = {
          family = "ip";
          table = "t";
          name = "fast_tcp";
          protocol = "tcp";
          l3proto = "ip";
          policy = {
            established = 300;
            close = 5;
          };
        };
      };
      expected = "add ct timeout ip t fast_tcp { protocol tcp; l3proto ip; policy = { close: 5, established: 300 } }";
    };

    testSynproxyObject = {
      expr = one {
        add.synproxy = {
          family = "inet";
          table = "t";
          name = "sp";
          mss = 1460;
          wscale = 7;
          flags = [
            "timestamp"
            "sack-perm"
          ];
        };
      };
      expected = "add synproxy inet t sp { mss 1460 wscale 7; timestamp sack-perm }";
    };

    # ct timeout/expectation with only the required name fields — the
    # optional `l3proto` (and `protocol`/`policy`/etc.) is absent.
    # Regression: an earlier version did `body.l3proto != null` which
    # threw `attribute 'l3proto' missing` after `clean` stripped the
    # null defaults.
    testCtTimeoutMinimal = {
      expr = one {
        add."ct timeout" = {
          family = "ip";
          table = "t";
          name = "minimal";
        };
      };
      expected = "add ct timeout ip t minimal";
    };

    testCtExpectationMinimal = {
      expr = one {
        add."ct expectation" = {
          family = "ip";
          table = "t";
          name = "minimal";
        };
      };
      expected = "add ct expectation ip t minimal";
    };

    # Tunnel object with only id+type+nested encapsulation. Regression:
    # `mkAddr`/`mkInt` previously accessed body.${key} directly, which
    # threw for any field stripped by `clean`.
    testTunnelMinimalVxlan = {
      expr = one {
        add.tunnel = {
          family = "inet";
          table = "t";
          name = "v";
          id = 42;
          type = "vxlan";
          tunnel = {
            gbp = 100;
          };
        };
      };
      expected = "add tunnel inet t v { id 42; type vxlan; vxlan { gbp 100 } }";
    };

    # Hyphenated identifier — the bare-identifier regex must accept `-`
    # because `nft -c -f -` rejects double-quoted names in the
    # add/chain/set scope position.
    testHyphenatedNames = {
      expr = one {
        add.chain = {
          family = "inet";
          table = "my-table";
          name = "my-chain";
        };
      };
      expected = "add chain inet my-table my-chain";
    };

    # Match with `in` operator over a set: nft text elides the operator
    # (set membership is implicit). The earlier non-`in` test exercised
    # `op = "in"` but didn't distinguish the elision from `==`.
    testMatchInOperator = {
      expr = one {
        add.rule = {
          family = "ip";
          table = "t";
          chain = "c";
          expr = [
            {
              match = {
                left = {
                  meta = {
                    key = "iifname";
                  };
                };
                op = "in";
                right = {
                  set = [
                    "lo"
                    "eth0"
                  ];
                };
              };
            }
          ];
        };
      };
      expected = "add rule ip t c meta iifname { lo, eth0 }";
    };

    # Binop precedence where the child binds tighter than the parent —
    # no parens needed.
    testBinopNoParens = {
      expr = one {
        add.rule = {
          family = "ip";
          table = "t";
          chain = "c";
          expr = [
            {
              match = {
                left = {
                  "|" = [
                    {
                      "&" = [
                        "a"
                        "b"
                      ];
                    }
                    "c"
                  ];
                };
                op = "==";
                right = "1";
              };
            }
          ];
        };
      };
      expected = "add rule ip t c a & b | c 1";
    };

    # ---- commands -------------------------------------------------------
    testFlushRuleset = {
      expr = one { flush.ruleset = null; };
      expected = "flush ruleset";
    };

    testFlushRulesetByFamily = {
      expr = one {
        flush.ruleset = {
          family = "ip";
        };
      };
      expected = "flush ruleset ip";
    };

    testDeleteByHandle = {
      expr = one {
        delete.rule = {
          family = "ip";
          table = "t";
          chain = "c";
          handle = 42;
          expr = [ ];
        };
      };
      # Empty-statement-list rule renders as just the header with handle —
      # the trailing space from the empty `expr` join is stripped by
      # renderObject.
      expected = "delete rule ip t c handle 42";
    };

    testRename = {
      expr = one {
        rename.chain = {
          family = "ip";
          table = "t";
          name = "old";
          newname = "new";
        };
      };
      expected = "rename chain ip t old new";
    };

    testReplaceRule = {
      expr = one {
        replace.rule = {
          family = "ip";
          table = "t";
          chain = "c";
          handle = 7;
          expr = [ { drop = null; } ];
        };
      };
      expected = "replace rule ip t c handle 7 drop";
    };

    # ---- ruleset envelope (multi-command) -------------------------------
    testRulesetMultiCommand = {
      expr = toText {
        nftables = [
          { flush.ruleset = null; }
          {
            add.table = {
              family = "ip";
              name = "t";
            };
          }
          {
            add.chain = {
              family = "ip";
              table = "t";
              name = "c";
            };
          }
        ];
      };
      expected = "flush ruleset\nadd table ip t\nadd chain ip t c";
    };
  };

  runTests =
    pkgs':
    let
      results = lib.runTests tests;
      fmt = res: lib.generators.toPretty { } res;
    in
    if results == [ ] then
      pkgs'.runCommandLocal "nft-text-parity-tests-pass" { } ''
        echo "All ${toString (builtins.length (builtins.attrNames tests))} text-parity tests passed"
        touch $out
      ''
    else
      pkgs'.runCommandLocal "nft-text-parity-tests-fail" { } ''
        cat <<'EOF'
        Text-parity tests failed:
        ${fmt results}
        EOF
        exit 1
      '';
in
{
  inherit tests runTests;
}
