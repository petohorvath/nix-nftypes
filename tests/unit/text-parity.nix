{
  helpers,
  lib,
  nftlib,
  ...
}:

# Schema-level parity tests for the text renderer (lib/text/).
#
# Each case renders a hand-built attrset through `toText` (compact form)
# and asserts the exact resulting string. Mirrors tests/unit/schema.nix's
# round-trip pattern for the JSON renderer: fast, deterministic, no
# shell-out. Render equivalence (tests/integration/render-equivalence.nix)
# loads text through nft.

let
  inherit (nftlib) toText;

  # Wrap a single command in a ruleset so toText's entry contract is met.
  one = cmd: toText { nftables = [ cmd ]; };

  # Two ip tables, for output that spans tables.
  tableA = {
    family = "ip";
    name = "a";
  };
  tableB = {
    family = "ip";
    name = "b";
  };

  # A rule matching the ct expression `body` against an IPv4 address.
  ctMatch = body: {
    add.rule = {
      family = "ip";
      table = "t";
      chain = "c";
      expr = [
        {
          match = {
            left.ct = body;
            op = "==";
            right = "10.0.0.1";
          };
        }
      ];
    };
  };

  /*
    The ct keys whose name holds a space carry their family, so they load
    in an inet table, where nft refuses a ct `saddr` or `daddr`. Text
    writes each key as nft lists it, after the direction. The parse check
    loads each pin.
  */
  ctFamilyAddressKeyTests =
    lib.mapAttrs'
      (
        name: case:
        lib.nameValuePair "testCtFamilyAddressKey${name}" {
          expr = one {
            add.rule = {
              family = "inet";
              table = "t";
              chain = "c";
              expr = [
                {
                  match = {
                    left.ct = case.body;
                    op = "==";
                    inherit (case) right;
                  };
                }
              ];
            };
          };
          inherit (case) expected;
        }
      )
      {
        IpSaddr = {
          body = {
            key = "ip saddr";
            dir = "original";
          };
          right = "192.0.2.1";
          expected = "add rule inet t c ct original ip saddr == 192.0.2.1\n";
        };
        IpDaddr = {
          body = {
            key = "ip daddr";
            dir = "reply";
          };
          right = "192.0.2.2";
          expected = "add rule inet t c ct reply ip daddr == 192.0.2.2\n";
        };
        Ip6Saddr = {
          body = {
            key = "ip6 saddr";
            dir = "original";
          };
          right = "2001:db8::1";
          expected = "add rule inet t c ct original ip6 saddr == 2001:db8::1\n";
        };
        Ip6Daddr = {
          body = {
            key = "ip6 daddr";
            dir = "reply";
          };
          right = "2001:db8::2";
          expected = "add rule inet t c ct reply ip6 daddr == 2001:db8::2\n";
        };
      };

  # Statements that reference a named stateful object.
  statefulTags = [
    "counter"
    "quota"
    "limit"
    "ct count"
    "synproxy"
  ];

  # Exercise the same limit body through all three public command forms.
  limitForms =
    body:
    let
      named = body // {
        family = "ip";
        table = "t";
        name = "lim";
      };
    in
    {
      statement = one {
        add.rule = {
          family = "ip";
          table = "t";
          chain = "c";
          expr = [ { limit = body; } ];
        };
      };
      object = one { add.limit = named; };
      create = one { create.limit = named; };
    };

  # A positional `create <kind>` with a comment, which text refuses.
  createCommentRefused = kind: values: {
    expr = one {
      create.${kind} = {
        family = "ip";
        table = "t";
        name = "o";
        comment = "lost";
      }
      // values;
    };
    expectedError.msg = helpers.refusals.noTextSpelling "create ${kind} comment";
  };

  mark = {
    meta.key = "mark";
  };

  # `meta mark set <value>` in an inet rule.
  markSet =
    value:
    one {
      add.rule = {
        family = "inet";
        table = "t";
        chain = "c";
        expr = [
          {
            mangle = {
              key = mark;
              inherit value;
            };
          }
        ];
      };
    };

  # A rule in table `<family> t`, chain `c`, holding `statements`.
  ruleIn =
    family: statements:
    one {
      add.rule = {
        inherit family;
        table = "t";
        chain = "c";
        expr = statements;
      };
    };

  # nft requires a transport protocol match before a NAT or tproxy port.
  tcpMatch = {
    match = {
      left.meta.key = "l4proto";
      op = "==";
      right = "tcp";
    };
  };

  # A rule in table `ip6 t`, chain `c`, holding one statement.
  ip6Rule =
    statement:
    one {
      add.rule = {
        family = "ip6";
        table = "t";
        chain = "c";
        expr = [ statement ];
      };
    };

  # An ip6 rule that matches tcp first: nft requires a transport protocol
  # match before a NAT or tproxy port.
  ip6TcpRule =
    statement:
    one {
      add.rule = {
        family = "ip6";
        table = "t";
        chain = "c";
        expr = [
          {
            match = {
              left.meta.key = "l4proto";
              op = "==";
              right = "tcp";
            };
          }
          statement
        ];
      };
    };

  # nft lists a map of ct objects with a datatype key, as in
  # `type ipv4_addr : ct helper`, but parses one only with a typeof key.
  typeKeyCtObjectMapRefusals = builtins.listToAttrs (
    map
      (value: {
        name = "testTypeKeyMapRefuses_${builtins.replaceStrings [ " " ] [ "_" ] value}";
        value = {
          expr = one {
            add.map = {
              family = "inet";
              table = "t";
              name = "m";
              type = "ipv4_addr";
              map = value;
            };
          };
          expectedError.msg = helpers.refusals.noTextSpelling "map type";
        };
      })
      [
        "ct helper"
        "ct timeout"
        "ct expectation"
      ]
  );

  # nft's JSON parser ignores element statements, both the keys nft lists
  # and a `stmt` list, so text would load statements that JSON drops (a
  # Known difference).
  elementStatementRefusals =
    lib.mapAttrs'
      (
        key: value:
        lib.nameValuePair "testElementStatementRefused_${key}" {
          expr = one {
            add.element = {
              family = "ip";
              table = "t";
              name = "s";
              elem = [
                {
                  elem = {
                    val = "10.0.0.1";
                    ${key} = value;
                  };
                }
              ];
            };
          };
          expectedError.msg = helpers.refusals.jsonIgnored "element ${key}";
        }
      )
      {
        counter = {
          packets = 1;
          bytes = 2;
        };
        quota.val = 100;
        limit = {
          rate = 5;
          per = "second";
        };
        last.used = 1200;
        stmt = [ { counter = null; } ];
      };
in
{
  # ---- line endings ---------------------------------------------------
  # Every line ends with a newline, the last included, so two renders
  # concatenate into two commands, not one glued line.
  testConcatenatedRendersKeepCommandsApart = {
    expr = one { add.table = tableA; } + one { add.table = tableB; };
    expected = "add table ip a\nadd table ip b\n";
  };

  testPrettyEndsLastLineWithNewline = {
    expr = nftlib.toTextPretty { nftables = [ { add.table = tableA; } ]; };
    expected = "add table ip a\n";
  };

  # An empty ruleset adds nothing to the text it is appended to.
  testEmptyRulesetRendersEmpty = {
    expr = map (render: render { nftables = [ ]; }) [
      toText
      nftlib.toTextPretty
    ];
    expected = [
      ""
      ""
    ];
  };

  # Pretty form separates one table's commands from the next table's with
  # a blank line; a command outside any table, such as `flush ruleset`,
  # is separated from a table's commands too.
  testPrettySeparatesTables = {
    expr = nftlib.toTextPretty {
      nftables = [
        { flush.ruleset = null; }
        { add.table = tableA; }
        {
          add.chain = {
            family = "ip";
            table = "a";
            name = "c";
          };
        }
        { add.table = tableB; }
        {
          add.chain = {
            family = "ip";
            table = "a";
            name = "d";
          };
        }
      ];
    };
    expected = ''
      flush ruleset

      add table ip a
      add chain ip a c

      add table ip b

      add chain ip a d
    '';
  };

  # Compact form keeps one command per line, with no blank lines.
  testCompactKeepsTablesAdjacent = {
    expr = toText {
      nftables = [
        { add.table = tableA; }
        { add.table = tableB; }
      ];
    };
    expected = "add table ip a\nadd table ip b\n";
  };

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
    expected = "add rule ip t c tcp dport == 22\n";
  };

  # nft's JSON field `parameter-problem` is `param-problem` in text.
  testMatchPayloadIcmpv6ParamProblem = {
    expr = one {
      add.rule = {
        family = "ip6";
        table = "t";
        chain = "c";
        expr = [
          {
            match = {
              left = {
                payload = {
                  protocol = "icmpv6";
                  field = "parameter-problem";
                };
              };
              op = "==";
              right = 1;
            };
          }
        ];
      };
    };
    expected = "add rule ip6 t c icmpv6 param-problem == 1\n";
  };

  testMatchPayloadArpSaddrEther = {
    expr = one {
      add.rule = {
        family = "arp";
        table = "t";
        chain = "c";
        expr = [
          {
            match = {
              left = {
                payload = {
                  protocol = "arp";
                  field = "saddr ether";
                };
              };
              op = "==";
              right = "00:11:22:33:44:55";
            };
          }
        ];
      };
    };
    expected = "add rule arp t c arp saddr ether == 00:11:22:33:44:55\n";
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
    expected = "add rule ip t c ct state { established, related } accept\n";
  };

  # nft's JSON parser ignores a ct expression's `family`, while text would
  # load it as part of the key.
  testCtFamilyRefused = {
    expr = one (ctMatch {
      key = "saddr";
      dir = "original";
      family = "ip";
    });
    expectedError.msg = helpers.refusals.jsonIgnored "ct family";
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
    expected = "add rule ip t c ip saddr == 10.0.0.0/8\n";
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
    expected = "add rule ip t c tcp dport == 1024-65535\n";
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
                      { meta.key = "mark"; }
                      1
                    ];
                  }
                  2
                ];
              };
              op = "==";
              right = "1";
            };
          }
        ];
      };
    };
    expected = "add rule ip t c (meta mark | 1) & 2 == 1\n";
  };

  # A later operand of higher precedence needs no parens.
  testBinopLaterOperandOfHigherPrecedence = {
    expr = ruleIn "ip" [
      {
        match = {
          left."|" = [
            mark
            {
              "^" = [
                1
                3
              ];
            }
          ];
          op = "==";
          right = 1;
        };
      }
    ];
    expected = "add rule ip t c meta mark | 1 ^ 3 == 1\n";
  };

  # A concatenation matched against a named set, with an interface name
  # component.
  testConcatMatchesNamedSet = {
    expr = ruleIn "inet" [
      {
        match = {
          left.concat = [
            { meta.key = "iifname"; }
            {
              payload = {
                protocol = "ip";
                field = "saddr";
              };
            }
          ];
          op = "==";
          right = "@allowed";
        };
      }
    ];
    expected = "add rule inet t c meta iifname . ip saddr == @allowed\n";
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
    expected = "add rule ip t c dnat ip to 10.0.0.10:tcp dport map @port_forward\n";
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
    expected = "add rule ip t c counter packets 10 bytes 500 accept\n";
  };

  # The null body nft lists for a statement with no options.
  testNullStatementBodies = {
    expr =
      builtins.mapAttrs
        (
          tag: _:
          one {
            add.rule = {
              family = "ip";
              table = "t";
              chain = "c";
              expr = [ { ${tag} = null; } ];
            };
          }
        )
        {
          log = null;
          masquerade = null;
          queue = null;
          redirect = null;
          reject = null;
        };
    expected = {
      log = "add rule ip t c log\n";
      masquerade = "add rule ip t c masquerade\n";
      queue = "add rule ip t c queue\n";
      redirect = "add rule ip t c redirect\n";
      reject = "add rule ip t c reject\n";
    };
  };

  testLimitDefaultBurst = {
    expr = limitForms {
      rate = 10;
      per = "minute";
      burst = 5;
    };
    expected = {
      statement = "add rule ip t c limit rate 10/minute burst 5 packets\n";
      object = "add limit ip t lim { rate 10/minute burst 5 packets; }\n";
      create = "create limit ip t lim rate 10/minute burst 5 packets\n";
    };
  };

  testLimitRateOnly = {
    expr = limitForms {
      rate = 10;
      per = "minute";
    };
    expected = {
      statement = "add rule ip t c limit rate 10/minute\n";
      object = "add limit ip t lim { rate 10/minute; }\n";
      create = "create limit ip t lim rate 10/minute\n";
    };
  };

  testLimitNullOptions = {
    expr = limitForms {
      rate = 10;
      per = "minute";
      inv = null;
      rate_unit = null;
      burst = null;
      burst_unit = null;
    };
    expected = {
      statement = "add rule ip t c limit rate 10/minute\n";
      object = "add limit ip t lim { rate 10/minute; }\n";
      create = "create limit ip t lim rate 10/minute\n";
    };
  };

  testLimitExplicitUnitsOver = {
    expr = limitForms {
      rate = 10;
      per = "minute";
      inv = true;
      rate_unit = "kbytes";
      burst = 5;
      burst_unit = "bytes";
    };
    expected = {
      statement = "add rule ip t c limit rate over 10 kbytes/minute burst 5 bytes\n";
      object = "add limit ip t lim { rate over 10 kbytes/minute burst 5 bytes; }\n";
      create = "create limit ip t lim rate over 10 kbytes/minute burst 5 bytes\n";
    };
  };

  # A burst of 0 is the default: JSON makes a packet burst of 0 into 5,
  # as text does without one, and nft's text refuses `burst 0 packets`
  # inline.
  testLimitZeroBurst = {
    expr = limitForms {
      rate = 10;
      per = "minute";
      inv = false;
      burst = 0;
      burst_unit = "packets";
    };
    expected = {
      statement = "add rule ip t c limit rate 10/minute\n";
      object = "add limit ip t lim { rate 10/minute; }\n";
      create = "create limit ip t lim rate 10/minute\n";
    };
  };

  testLimitByteRateZeroBurst = {
    expr = limitForms {
      rate = 10;
      per = "minute";
      rate_unit = "mbytes";
      burst = 0;
      burst_unit = "kbytes";
    };
    expected = {
      statement = "add rule ip t c limit rate 10 mbytes/minute\n";
      object = "add limit ip t lim { rate 10 mbytes/minute; }\n";
      create = "create limit ip t lim rate 10 mbytes/minute\n";
    };
  };

  # `packets` is the packet rate text writes without a unit; JSON ignores
  # `burst_unit` on a packet rate.
  testLimitPacketRateUnit = {
    expr = limitForms {
      rate = 10;
      per = "minute";
      rate_unit = "packets";
      burst = 7;
      burst_unit = "bytes";
    };
    expected = {
      statement = "add rule ip t c limit rate 10/minute burst 7 packets\n";
      object = "add limit ip t lim { rate 10/minute burst 7 packets; }\n";
      create = "create limit ip t lim rate 10/minute burst 7 packets\n";
    };
  };

  # JSON's burst unit defaults to bytes for a byte rate.
  testLimitByteRateBurstDefaultsToBytes = {
    expr = limitForms {
      rate = 10;
      per = "second";
      rate_unit = "kbytes";
      burst = 5;
    };
    expected = {
      statement = "add rule ip t c limit rate 10 kbytes/second burst 5 bytes\n";
      object = "add limit ip t lim { rate 10 kbytes/second burst 5 bytes; }\n";
      create = "create limit ip t lim rate 10 kbytes/second burst 5 bytes\n";
    };
  };

  testLimitCommentAndReferencePretty = {
    expr = nftlib.toTextPretty {
      nftables = [
        {
          add.limit = {
            family = "ip";
            table = "t";
            name = "lim";
            rate = 10;
            per = "minute";
            burst = 5;
            comment = "packet budget";
          };
        }
        {
          add.rule = {
            family = "ip";
            table = "t";
            chain = "c";
            expr = [ { limit = "lim"; } ];
          };
        }
        {
          create.limit = {
            family = "ip";
            table = "t";
            name = "fast";
            rate = 20;
            per = "second";
            burst = 10;
          };
        }
      ];
    };
    expected = ''
      add limit ip t lim {
        rate 10/minute burst 5 packets;
        comment "packet budget";
      }
      add rule ip t c limit name "lim"
      create limit ip t fast rate 20/second burst 10 packets
    '';
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
    expected = "add rule ip t c reject with icmp host-unreachable\n";
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
    expected = "add rule ip t c log prefix \"DROP \" level info\n";
  };

  # nft loads a log prefix of 1 to 127 bytes.
  testLogPrefixBoundaryLengths =
    let
      maxLength = lib.concatStrings (lib.replicate 127 "a");
    in
    {
      expr = lib.mapAttrs (_: prefix: ruleIn "ip" [ { log.prefix = prefix; } ]) {
        oneByte = "a";
        inherit maxLength;
      };
      expected = {
        oneByte = "add rule ip t c log prefix \"a\"\n";
        maxLength = "add rule ip t c log prefix \"${maxLength}\"\n";
      };
    };

  # nft's text takes one log flag group per `flags`, its tcp flags
  # comma-joined.
  testLogFlags = {
    expr = ruleIn "ip" [
      {
        log.flags = [
          "tcp sequence"
          "ip options"
          "tcp options"
          "skuid"
          "ether"
        ];
      }
      { log.flags = "all"; }
    ];
    expected = "add rule ip t c log flags tcp sequence,options flags ip options flags skuid flags ether log flags all\n";
  };

  testLogFlagUnknown = {
    expr = ruleIn "ip" [ { log.flags = [ "bogus" ]; } ];
    expectedError.msg = helpers.refusals.noTextSpelling "log flags";
  };

  # An OS fingerprint is a string: nft's text can't parse `Linux:3.0`
  # bare, so the right side is quoted, in a set too.
  testOsfMatchQuotesString = {
    expr = ruleIn "ip" [
      {
        match = {
          left.osf = {
            key = "version";
            ttl = "loose";
          };
          op = "==";
          right = "Linux:3.0";
        };
      }
      {
        match = {
          left.osf.key = "name";
          op = "!=";
          right.set = [
            "Linux"
            "Windows"
          ];
        };
      }
    ];
    expected = "add rule ip t c osf ttl loose version == \"Linux:3.0\" osf name != { \"Linux\", \"Windows\" }\n";
  };

  testOsfMatchRefusesUnsafeString = {
    expr = ruleIn "ip" [
      {
        match = {
          left.osf.key = "name";
          op = "==";
          right = "Linux\"";
        };
      }
    ];
    expectedError.msg = helpers.refusals.quotedString "match right";
  };

  # `last used` takes a time; -1 is JSON's never.
  testLastUsed = {
    expr = ruleIn "ip" [
      { last = null; }
      { last.used = -1; }
      { last.used = 0; }
      { last.used = 86400000; }
    ];
    expected = "add rule ip t c last last used never last used 0ms last used 86400000ms\n";
  };

  # JSON loads any other negative time as a huge one.
  testLastUsedBelowNever = {
    expr = ruleIn "ip" [ { last.used = -2; } ];
    expectedError.msg = helpers.refusals.noTextSpelling "last used";
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
    expected = "add rule ip t c ct helper set \"ftp-helper\"\n";
  };

  # nft's text spells a tunnel assignment `tunnel name`, not `meta tunnel
  # set`, which it can't parse.
  testTunnelStatement = {
    expr = one {
      add.rule = {
        family = "netdev";
        table = "t";
        chain = "c";
        expr = [ { tunnel = "vxlan0"; } ];
      };
    };
    expected = "add rule netdev t c tunnel name \"vxlan0\"\n";
  };

  # ---- objects --------------------------------------------------------
  testTableMinimal = {
    expr = one {
      add.table = {
        family = "inet";
        name = "main";
      };
    };
    expected = "add table inet main\n";
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
    expected = "add chain inet main input { type filter hook input priority 0; policy drop; }\n";
  };

  testRegularChain = {
    expr = one {
      add.chain = {
        family = "inet";
        table = "main";
        name = "tcp_in";
      };
    };
    expected = "add chain inet main tcp_in\n";
  };

  # A raw chain without all of type, hook and prio is a regular chain, as
  # nft's JSON parser loads it.
  testChainWithoutEveryPlacementField = {
    expr =
      builtins.mapAttrs
        (
          _: placement:
          one {
            add.chain = {
              family = "ip";
              table = "t";
              name = "c";
            }
            // placement;
          }
        )
        {
          prio.prio = 0;
          type.type = "filter";
          typeAndHook = {
            type = "filter";
            hook = "input";
          };
        };
    expected = {
      prio = "add chain ip t c\n";
      type = "add chain ip t c\n";
      typeAndHook = "add chain ip t c\n";
    };
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
    expected = "add chain netdev filter ingress { type filter hook ingress device \"eth0\" priority -100; }\n";
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
    expected = "add set inet main trusted { type ipv4_addr; flags interval; elements = { 10.0.0.0/8 }; }\n";
  };

  # A typeof declaration replaces the `type` keyword.
  testTypeofSet = {
    expr = one {
      add.set = {
        family = "inet";
        table = "t";
        name = "s";
        type.typeof.meta.key = "iifname";
      };
    };
    expected = "add set inet t s { typeof meta iifname; }\n";
  };

  testTypeofConcatSet = {
    expr = one {
      add.set = {
        family = "inet";
        table = "t";
        name = "s";
        type.typeof.concat = [
          {
            payload = {
              protocol = "ip";
              field = "saddr";
            };
          }
          {
            payload = {
              protocol = "tcp";
              field = "dport";
            };
          }
        ];
      };
    };
    expected = "add set inet t s { typeof ip saddr . tcp dport; }\n";
  };

  # nft's text grammar declares both sides of a typeof map with one
  # `typeof`, and takes `verdict` or an object kind as a value type.
  testTypeofMap = {
    expr = one {
      add.map = {
        family = "inet";
        table = "t";
        name = "m";
        type.typeof.payload = {
          protocol = "ip";
          field = "saddr";
        };
        map.typeof.meta.key = "mark";
      };
    };
    expected = "add map inet t m { typeof ip saddr : meta mark; }\n";
  };

  testTypeofMapNamedValueType = {
    expr =
      map
        (
          value:
          one {
            add.map = {
              family = "inet";
              table = "t";
              name = "m";
              type.typeof.payload = {
                protocol = "ip";
                field = "saddr";
              };
              map = value;
            };
          }
        )
        [
          "verdict"
          "counter"
          "ct helper"
          "ct timeout"
          "ct expectation"
        ];
    expected = [
      "add map inet t m { typeof ip saddr : verdict; }\n"
      "add map inet t m { typeof ip saddr : counter; }\n"
      "add map inet t m { typeof ip saddr : ct helper; }\n"
      "add map inet t m { typeof ip saddr : ct timeout; }\n"
      "add map inet t m { typeof ip saddr : ct expectation; }\n"
    ];
  };

  # Text has no spelling for a datatype key with a typeof value.
  testTypeKeyTypeofValueRefuses = {
    expr = one {
      add.map = {
        family = "inet";
        table = "t";
        name = "m";
        type = "ipv4_addr";
        map.typeof.meta.key = "mark";
      };
    };
    expectedError.msg = helpers.refusals.typeofMapValue;
  };

  # A set, map or flow statement stores its reference with the `@`
  # nft's JSON requires, and text prints it as stored.
  testSetStatementNamedReference = {
    expr = one {
      add.rule = {
        family = "ip";
        table = "t";
        chain = "c";
        expr = [
          {
            set = {
              op = "add";
              elem.payload = {
                protocol = "ip";
                field = "saddr";
              };
              set = "@blocked";
            };
          }
        ];
      };
    };
    expected = "add rule ip t c add @blocked { ip saddr }\n";
  };

  testMapStatementNamedReference = {
    expr = one {
      add.rule = {
        family = "ip";
        table = "t";
        chain = "c";
        expr = [
          {
            map = {
              op = "update";
              elem.payload = {
                protocol = "ip";
                field = "saddr";
              };
              data = 1;
              map = "@cache";
            };
          }
        ];
      };
    };
    expected = "add rule ip t c update @cache { ip saddr : 1 }\n";
  };

  testFlowNamedReference = {
    expr = one {
      add.rule = {
        family = "inet";
        table = "t";
        chain = "c";
        expr = [
          {
            flow = {
              op = "add";
              flowtable = "@ft";
            };
          }
        ];
      };
    };
    expected = "add rule inet t c flow add @ft\n";
  };

  # Without its `@`, a reference is refused rather than printed bare.
  testStatementReferenceWithoutAtRefuses = {
    expr = one {
      add.rule = {
        family = "ip";
        table = "t";
        chain = "c";
        expr = [
          {
            set = {
              op = "add";
              elem.payload = {
                protocol = "ip";
                field = "saddr";
              };
              set = "blocked";
            };
          }
        ];
      };
    };
    expectedError.msg = helpers.refusals.namedReference "set reference";
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
    expected = "add map inet main ports { type inet_service : inet_service; elements = { 80 : 8080, 443 : 8443 }; }\n";
  };

  # nft's JSON parser ignores a set or map comment, so text would load a
  # comment that JSON drops (a Known difference).
  testSetComment = {
    expr = one {
      add.set = {
        family = "inet";
        table = "t";
        name = "s";
        type = "ipv4_addr";
        comment = "blocked hosts";
      };
    };
    expectedError.msg = helpers.refusals.jsonIgnored "set comment";
  };

  testMapComment = {
    expr = one {
      add.map = {
        family = "inet";
        table = "t";
        name = "m";
        type = "ipv4_addr";
        map = "verdict";
        comment = "per-host verdicts";
      };
    };
    expectedError.msg = helpers.refusals.jsonIgnored "map comment";
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
    expected = "add element inet main trusted { 8.8.8.8, 1.1.1.1 }\n";
  };

  testSetElementStatementRefused = {
    expr = one {
      add.set = {
        family = "ip";
        table = "t";
        name = "s";
        type = "ipv4_addr";
        stmt = [ { counter = null; } ];
        elem = [
          {
            elem = {
              val = "10.0.0.1";
              counter = {
                packets = 1;
                bytes = 2;
              };
            };
          }
        ];
      };
    };
    expectedError.msg = helpers.refusals.jsonIgnored "element counter";
  };

  # `nft -s` lists a stateless counter as null; like JSON, text drops it.
  testElementNullStatementOmitted = {
    expr = one {
      add.element = {
        family = "ip";
        table = "t";
        name = "s";
        elem = [
          {
            elem = {
              val = "10.0.0.1";
              counter = null;
            };
          }
        ];
      };
    };
    expected = "add element ip t s { 10.0.0.1 }\n";
  };

  # Set-level statements give every element its own instance.
  testSetStatement = {
    expr = one {
      add.set = {
        family = "ip";
        table = "t";
        name = "s";
        type = "ipv4_addr";
        stmt = [ { counter = null; } ];
        elem = [ "10.0.0.1" ];
      };
    };
    expected = "add set ip t s { type ipv4_addr; counter; elements = { 10.0.0.1 }; }\n";
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
    expected = "add flowtable inet main ft1 { hook ingress priority 0; devices = { \"eth0\", \"eth1\" }; }\n";
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
    expected = "add counter ip filter ctr { packets 100 bytes 5000; }\n";
  };

  # nft's text takes `packets N bytes N` only as a pair; JSON loads a
  # missing count as 0.
  testCounterObjectOneCount = {
    expr = map one [
      {
        add.counter = {
          family = "ip";
          table = "filter";
          name = "ctr";
          packets = 100;
        };
      }
      {
        add.counter = {
          family = "ip";
          table = "filter";
          name = "ctr";
          bytes = 5000;
          comment = "bytes only";
        };
      }
    ];
    expected = [
      "add counter ip filter ctr { packets 100 bytes 0; }\n"
      "add counter ip filter ctr { packets 0 bytes 5000; comment \"bytes only\"; }\n"
    ];
  };

  # `create counter` takes the counts positionally, as quota, limit and
  # synproxy do.
  testCounterCreate = {
    expr = map one [
      {
        create.counter = {
          family = "ip";
          table = "filter";
          name = "ctr";
          packets = 100;
        };
      }
      {
        create.counter = {
          family = "ip";
          table = "filter";
          name = "ctr";
        };
      }
    ];
    expected = [
      "create counter ip filter ctr packets 100 bytes 0\n"
      "create counter ip filter ctr\n"
    ];
  };

  # The positional `create` forms have no comment clause, while JSON's
  # create loads one.
  testCreateCounterCommentRefused = createCommentRefused "counter" { packets = 1; };

  testCreateQuotaCommentRefused = createCommentRefused "quota" { bytes = 1; };

  testCreateLimitCommentRefused = createCommentRefused "limit" {
    rate = 1;
    per = "second";
  };

  testCreateSynproxyCommentRefused = createCommentRefused "synproxy" {
    mss = 1460;
    wscale = 7;
  };

  # `create secmark` takes its context positionally, as `add secmark` may;
  # nft's grammar has no brace body for it.
  testCreateSecmarkIsPositional = {
    expr = one {
      create.secmark = {
        family = "inet";
        table = "t";
        name = "s";
        context = "system_u:object_r:ssh_server_packet_t:s0";
      };
    };
    expected = "create secmark inet t s \"system_u:object_r:ssh_server_packet_t:s0\"\n";
  };

  testCreateSecmarkCommentRefused = createCommentRefused "secmark" {
    context = "system_u:object_r:ssh_server_packet_t:s0";
  };

  # The positional context is required in text; JSON loads an empty one.
  testCreateSecmarkWithoutContextRefused = {
    expr = one {
      create.secmark = {
        family = "inet";
        table = "t";
        name = "s";
      };
    };
    expectedError.msg = helpers.refusals.noTextSpelling "create secmark context";
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
    expected = "add quota ip filter q { over 1000000 bytes; }\n";
  };

  # JSON's quota units default to bytes; text needs one written.
  testQuotaStatementUnitsDefaultToBytes = {
    expr = ruleIn "ip" [
      { quota.val = 100; }
      {
        quota = {
          val = 2;
          val_unit = "mbytes";
          used = 1;
          inv = true;
        };
      }
    ];
    expected = "add rule ip t c quota 100 bytes quota over 2 mbytes used 1 bytes\n";
  };

  # JSON's quota object `bytes` defaults to 0.
  testQuotaObjectWithoutBytes = {
    expr = map one [
      {
        add.quota = {
          family = "ip";
          table = "t";
          name = "q";
        };
      }
      {
        create.quota = {
          family = "ip";
          table = "t";
          name = "q";
          used = 0;
        };
      }
    ];
    expected = [
      "add quota ip t q { 0 bytes; }\n"
      "create quota ip t q 0 bytes used 0 bytes\n"
    ];
  };

  testCtCountObjectOver = {
    expr = one {
      add."ct count" = {
        family = "ip";
        table = "t";
        name = "c1";
        val = 5;
        inv = true;
        comment = "over five";
      };
    };
    expected = "add ct count ip t c1 { over 5; comment \"over five\"; }\n";
  };

  # Without `inv` the grammar still needs a keyword: `until`.
  testCtCountObjectUntil = {
    expr = one {
      create."ct count" = {
        family = "ip";
        table = "t";
        name = "c2";
        val = 4;
      };
    };
    expected = "create ct count ip t c2 { until 4; }\n";
  };

  testCtCountNamedReference = {
    expr = one {
      add.rule = {
        family = "ip";
        table = "t";
        chain = "c";
        expr = [ { "ct count" = "c1"; } ];
      };
    };
    expected = "add rule ip t c ct count name \"c1\"\n";
  };

  # Every stateful statement renders a map reference as
  # `<keyword> name <key> map { … }`.
  testStatefulMapReferences = {
    expr = map (
      tag:
      one {
        add.rule = {
          family = "ip";
          table = "t";
          chain = "c";
          expr = [
            {
              ${tag}.map = {
                key.payload = {
                  protocol = "tcp";
                  field = "dport";
                };
                data.set = [
                  [
                    22
                    "a"
                  ]
                  [
                    80
                    "b"
                  ]
                ];
              };
            }
          ];
        };
      }
    ) statefulTags;
    expected = map (tag: "add rule ip t c ${tag} name tcp dport map { 22 : a, 80 : b }\n") statefulTags;
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
    expected = "add ct timeout ip t fast_tcp { protocol tcp; l3proto ip; policy = { close: 5, established: 300 }; }\n";
  };

  testCtHelperInetL3proto = {
    expr = one {
      add."ct helper" = {
        family = "inet";
        table = "t";
        name = "h";
        type = "ftp";
        protocol = "tcp";
        l3proto = "inet";
      };
    };
    expected = "add ct helper inet t h { type \"ftp\" protocol tcp; l3proto inet; }\n";
  };

  /*
    nft 1.1.7 reads `mss N wscale N` on one line with the wrong token:
    `wscale` loads as 0, or as 8 when `timestamp` follows. Separating the
    three with `;` takes the grammar's other branch, which every tested nft
    reads correctly. The flags must follow `wscale N;` directly.
  */
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
    expected = "add synproxy inet t sp { mss 1460; wscale 7; timestamp sack-perm; }\n";
  };

  testSynproxyObjectWithoutFlags = {
    expr = one {
      add.synproxy = {
        family = "inet";
        table = "t";
        name = "sp";
        mss = 1460;
        wscale = 7;
        comment = "no flags";
      };
    };
    expected = "add synproxy inet t sp { mss 1460; wscale 7; comment \"no flags\"; }\n";
  };

  # `create synproxy` takes the values positionally, separated the same way.
  testSynproxyCreate = {
    expr = map one [
      {
        create.synproxy = {
          family = "inet";
          table = "t";
          name = "sp";
          mss = 1460;
          wscale = 7;
          flags = [ "sack-perm" ];
        };
      }
      {
        create.synproxy = {
          family = "inet";
          table = "t";
          name = "sp";
          mss = 1460;
          wscale = 7;
        };
      }
    ];
    expected = [
      "create synproxy inet t sp mss 1460; wscale 7; sack-perm;\n"
      "create synproxy inet t sp mss 1460; wscale 7;\n"
    ];
  };

  # ct timeout/expectation with only the fields nft requires: a timeout
  # needs `protocol`; an expectation `protocol`, `dport`, `timeout` and
  # `size`. Regression: an earlier version did `body.l3proto != null`
  # which threw `attribute 'l3proto' missing` after `clean` stripped the
  # null defaults.
  testCtTimeoutMinimal = {
    expr = one {
      add."ct timeout" = {
        family = "ip";
        table = "t";
        name = "minimal";
        protocol = "tcp";
      };
    };
    expected = "add ct timeout ip t minimal { protocol tcp; }\n";
  };

  testCtExpectationMinimal = {
    expr = one {
      add."ct expectation" = {
        family = "ip";
        table = "t";
        name = "minimal";
        protocol = "tcp";
        dport = 21;
        timeout = 1000;
        size = 1;
      };
    };
    expected = "add ct expectation ip t minimal { protocol tcp; dport 21; timeout 1000ms; size 1; }\n";
  };

  # JSON's ct expectation timeout is milliseconds, so text must say so;
  # a bare number in seconds would load 1000 times longer.
  testCtExpectationTimeoutIsMilliseconds = {
    expr = one {
      add."ct expectation" = {
        family = "ip";
        table = "t";
        name = "e";
        protocol = "udp";
        dport = 69;
        timeout = 60;
        size = 2;
        l3proto = "ip";
        comment = "tftp";
      };
    };
    expected = "add ct expectation ip t e { protocol udp; dport 69; timeout 60ms; size 2; l3proto ip; comment \"tftp\"; }\n";
  };

  # nft's JSON parser loads a tunnel's ports wrongly, so text refuses a
  # tunnel object in every command and in a listed ruleset.
  testTunnelObjectRefused = {
    expr = one {
      add.tunnel = {
        family = "netdev";
        table = "t";
        name = "v";
        id = 42;
        type = "vxlan";
        tunnel = {
          gbp = 100;
        };
      };
    };
    expectedError.msg = helpers.refusals.tunnel;
  };

  testTunnelCommandRefused = {
    expr = one {
      delete.tunnel = {
        family = "netdev";
        table = "t";
        name = "v";
      };
    };
    expectedError.msg = helpers.refusals.tunnel;
  };

  testListedTunnelRefused = {
    expr = one {
      tunnel = {
        family = "netdev";
        table = "t";
        name = "v";
        handle = 1;
        id = 42;
        "src-ipv4" = "192.0.2.1";
        "dst-ipv4" = "192.0.2.2";
        sport = 1111;
        dport = 2222;
        tos = 0;
        ttl = 64;
      };
    };
    expectedError.msg = helpers.refusals.tunnel;
  };

  # A listing's `metainfo` is metadata that nft's JSON parser ignores, so
  # text drops it.
  testListedMetainfoDropped = {
    expr = toText {
      nftables = [
        {
          metainfo = {
            version = "1.1.7";
            release_name = "Commodore Bullmoose #8";
            json_schema_version = 1;
          };
        }
        {
          table = {
            family = "inet";
            name = "t";
            handle = 1;
          };
        }
      ];
    };
    expected = "table inet t\n";
  };

  # A key that is neither a verb nor an object kind is no command, nor a
  # listed object such as `nft -j list` emits.
  testUnknownCommandThrows = {
    expr = one { ad.table = { }; };
    expectedError.msg = "^nix-nftypes: toText: unknown command or listed object 'ad'$";
  };

  # nft has no command that takes a metainfo: text and JSON both reject
  # `list metainfo`.
  testListMetainfoRefused = {
    expr = one { list.metainfo = { }; };
    expectedError.msg = helpers.refusals.noTextSpelling "list metainfo";
  };

  # nft's text has no listed meter object, and its JSON parser rejects
  # one.
  testListedMeterRefused = {
    expr = one {
      meter = {
        family = "inet";
        table = "t";
        name = "m";
        handle = 2;
      };
    };
    expectedError.msg = helpers.refusals.noTextSpelling "meter";
  };

  # The by-name meter commands still render.
  testCmdFlushMeter = {
    expr = one {
      flush.meter = {
        family = "inet";
        table = "filter";
        name = "rate_meter";
      };
    };
    expected = "flush meter inet filter rate_meter\n";
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
    expected = "add chain inet my-table my-chain\n";
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
    expected = "add rule ip t c meta iifname { \"lo\", \"eth0\" }\n";
  };

  # A bitmask is where the two ops differ: implicit `tcp flags syn` is
  # an any-bit test that also matches SYN-ACK, so JSON `==` must keep
  # its operator in text.
  testMatchBitmaskEqWritesOperator = {
    expr = one {
      add.rule = {
        family = "inet";
        table = "t";
        chain = "c";
        expr = [
          {
            match = {
              left = {
                payload = {
                  protocol = "tcp";
                  field = "flags";
                };
              };
              op = "==";
              right = "syn";
            };
          }
        ];
      };
    };
    expected = "add rule inet t c tcp flags == syn\n";
  };

  testMatchBitmaskInIsImplicit = {
    expr = one {
      add.rule = {
        family = "inet";
        table = "t";
        chain = "c";
        expr = [
          {
            match = {
              left = {
                payload = {
                  protocol = "tcp";
                  field = "flags";
                };
              };
              op = "in";
              right = "syn";
            };
          }
        ];
      };
    };
    expected = "add rule inet t c tcp flags syn\n";
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
                      { meta.key = "mark"; }
                      1
                    ];
                  }
                  2
                ];
              };
              op = "==";
              right = "1";
            };
          }
        ];
      };
    };
    expected = "add rule ip t c meta mark & 1 | 2 == 1\n";
  };

  # nft's grammar is left-associative, and it folds a JSON operand list
  # left, so every operand after the first keeps its parentheses at equal
  # precedence: `mark << 1 << 2` would load as `mark << 3`.
  testBinopRightNestedSamePrecedence = {
    expr = markSet {
      "<<" = [
        mark
        {
          "<<" = [
            1
            2
          ];
        }
      ];
    };
    expected = "add rule inet t c meta mark set meta mark << (1 << 2)\n";
  };

  testBinopRightNestedMixedShifts = {
    expr = markSet {
      "<<" = [
        mark
        {
          ">>" = [
            4
            2
          ];
        }
      ];
    };
    expected = "add rule inet t c meta mark set meta mark << (4 >> 2)\n";
  };

  testBinopLeftNestedSamePrecedence = {
    expr = markSet {
      ">>" = [
        {
          "<<" = [
            mark
            4
          ];
        }
        2
      ];
    };
    expected = "add rule inet t c meta mark set meta mark << 4 >> 2\n";
  };

  testBinopOperandListFoldsLeft = {
    expr = markSet {
      "<<" = [
        mark
        1
        {
          ">>" = [
            4
            1
          ];
        }
      ];
    };
    expected = "add rule inet t c meta mark set meta mark << 1 << (4 >> 1)\n";
  };

  # A next hop is `fwd <family> to <addr> device <dev>`. JSON ignores an
  # address without a family, and a family without an address.
  testFwd = {
    expr = map (statement: ruleIn "netdev" [ statement ]) [
      { fwd.dev = "eth0"; }
      {
        fwd = {
          dev = "eth0";
          family = "ip";
          addr = "192.0.2.1";
        };
      }
      {
        fwd = {
          dev = "eth0";
          addr = "192.0.2.1";
        };
      }
      {
        fwd = {
          dev = "eth0";
          family = "ip6";
        };
      }
    ];
    expected = [
      "add rule netdev t c fwd to \"eth0\"\n"
      "add rule netdev t c fwd ip to 192.0.2.1 device \"eth0\"\n"
      "add rule netdev t c fwd to \"eth0\"\n"
      "add rule netdev t c fwd to \"eth0\"\n"
    ];
  };

  # `queue num` takes a number or range; any other expression needs
  # `queue to`. Flags without a number come bare.
  testQueue = {
    expr = map (statement: ruleIn "ip" [ statement ]) [
      { queue = { }; }
      { queue.num = 3; }
      {
        queue = {
          num.range = [
            1
            3
          ];
          flags = [
            "bypass"
            "fanout"
          ];
        };
      }
      {
        queue.num.symhash = {
          mod = 2;
          offset = 1;
        };
      }
      {
        queue = {
          num.symhash.mod = 2;
          flags = "bypass";
        };
      }
      { queue.flags = "bypass"; }
    ];
    expected = [
      "add rule ip t c queue\n"
      "add rule ip t c queue num 3\n"
      "add rule ip t c queue flags bypass,fanout num 1-3\n"
      "add rule ip t c queue to symhash mod 2 offset 1\n"
      "add rule ip t c queue flags bypass to symhash mod 2\n"
      "add rule ip t c queue bypass\n"
    ];
  };

  # An extension header existence check is `exthdr <name>`.
  testExthdrExists = {
    expr =
      ruleIn "ip6" [
        {
          match = {
            left.exthdr.name = "frag";
            op = "==";
            right = true;
          };
        }
        {
          match = {
            left.exthdr.name = "hbh";
            op = "!=";
            right = false;
          };
        }
      ]
      + ruleIn "ip6" (
        map
          (name: {
            match = {
              left.exthdr.name = name;
              op = "==";
              right = true;
            };
          })
          [
            "rt"
            "dst"
            "mh"
          ]
      );
    expected = ''
      add rule ip6 t c exthdr frag == 1 exthdr hbh != 0
      add rule ip6 t c exthdr rt == 1 exthdr dst == 1 exthdr mh == 1
    '';
  };

  # nft's text checks only hbh, rt, frag, dst and mh for existence.
  testExthdrExistsWithoutTextKeyword = {
    expr = ruleIn "ip6" [
      {
        match = {
          left.exthdr.name = "srh";
          op = "==";
          right = true;
        };
      }
    ];
    expectedError.msg = helpers.refusals.noTextSpelling "exthdr name";
  };

  # nft's text lexes `-1` as a minus sign; quoted, it is the symbol JSON
  # loads (both load `meta mark -1` as 0x00000001).
  testNegativeIntegers = {
    expr = ruleIn "ip" [
      {
        match = {
          left = mark;
          op = "==";
          right.set = [
            (-1)
            2
          ];
        };
      }
      {
        mangle = {
          key = mark;
          value = -5;
        };
      }
    ];
    expected = "add rule ip t c meta mark == { \"-1\", 2 } meta mark set \"-5\"\n";
  };

  # ---- NAT targets ----------------------------------------------------
  # Before `:port`, an IPv6 address goes in brackets: nft would lex
  # `2001:db8::1:80` as one address.
  testDnatIpv6AddrPort = {
    expr = ip6TcpRule {
      dnat = {
        addr = "2001:db8::1";
        port = 80;
      };
    };
    expected = "add rule ip6 t c meta l4proto == tcp dnat to [2001:db8::1]:80\n";
  };

  testDnatIpv6AddrOnly = {
    expr = ip6Rule { dnat.addr = "2001:db8::1"; };
    expected = "add rule ip6 t c dnat to 2001:db8::1\n";
  };

  testSnatIpv6RangePort = {
    expr = ip6TcpRule {
      snat = {
        addr.range = [
          "2001:db8::1"
          "2001:db8::5"
        ];
        port = 1024;
      };
    };
    expected = "add rule ip6 t c meta l4proto == tcp snat to [2001:db8::1]-[2001:db8::5]:1024\n";
  };

  testTproxyIpv6AddrPort = {
    expr = ip6TcpRule {
      tproxy = {
        family = "ip6";
        addr = "2001:db8::1";
        port = 80;
      };
    };
    expected = "add rule ip6 t c meta l4proto == tcp tproxy ip6 to [2001:db8::1]:80\n";
  };

  # nft would lex `/24:80` as a string, so a space ends the prefix.
  testDnatPrefixPort = {
    expr = ip6TcpRule {
      dnat = {
        addr.prefix = {
          addr = "2001:db8::";
          len = 64;
        };
        port = 80;
      };
    };
    expected = "add rule ip6 t c meta l4proto == tcp dnat to 2001:db8::/64 :80\n";
  };

  /*
    nft's text has no `snat ip to :80`. Without an address, nft's JSON
    parser loads the table's family: it ignores the NAT family in an inet
    table, where both families load as `snat to :80`, and fails on another
    family in an ip or ip6 table. So text leaves the family out, and
    refuses one the table can't take.
  */
  testSnatFamilyPortOnlyInet = {
    expr = ruleIn "inet" [
      tcpMatch
      {
        snat = {
          family = "ip";
          port = 1024;
        };
      }
    ];
    expected = "add rule inet t c meta l4proto == tcp snat to :1024\n";
  };

  testSnatOtherFamilyPortOnlyRefused = {
    expr = ruleIn "ip" [
      tcpMatch
      {
        snat = {
          family = "ip6";
          port = 1024;
        };
      }
    ];
    expectedError.msg = helpers.refusals.noTextSpelling "nat family";
  };

  testDnatOtherFamilyPortOnlyRefused = {
    expr = ip6TcpRule {
      dnat = {
        family = "ip";
        port = 8080;
      };
    };
    expectedError.msg = helpers.refusals.noTextSpelling "nat family";
  };

  testSnatFamilyPortOnly = {
    expr = ip6TcpRule {
      snat = {
        family = "ip6";
        port = 1024;
      };
    };
    expected = "add rule ip6 t c meta l4proto == tcp snat to :1024\n";
  };

  testDnatFamilyPortOnly = {
    expr = ip6TcpRule {
      dnat = {
        family = "ip6";
        port = 8080;
      };
    };
    expected = "add rule ip6 t c meta l4proto == tcp dnat to :8080\n";
  };

  # The `netmap` flag is what nft's text spells `prefix to`; the `prefix`
  # type flag only changes how nft lists it.
  testSnatPrefix = {
    expr = ruleIn "ip" [
      {
        snat = {
          family = "ip";
          addr.prefix = {
            addr = "10.0.0.0";
            len = 24;
          };
          flags = "netmap";
          type_flags = "prefix";
        };
      }
    ];
    expected = "add rule ip t c snat ip prefix to 10.0.0.0/24\n";
  };

  testSnatPrefixTypeFlagAlone = {
    expr = ruleIn "ip" [
      {
        snat = {
          family = "ip";
          addr.prefix = {
            addr = "10.0.0.0";
            len = 24;
          };
          type_flags = [ "prefix" ];
        };
      }
    ];
    expected = "add rule ip t c snat ip to 10.0.0.0/24\n";
  };

  # nft's text sets the flags after `prefix to` in place of `netmap`.
  testSnatPrefixWithOtherFlags = {
    expr = ruleIn "ip" [
      {
        snat = {
          family = "ip";
          addr = "10.0.0.0";
          flags = [
            "netmap"
            "persistent"
          ];
        };
      }
    ];
    expectedError.msg = helpers.refusals.noTextSpelling "nat flags";
  };

  testMasqueradeNetmap = {
    expr = ruleIn "ip" [ { masquerade.flags = [ "netmap" ]; } ];
    expectedError.msg = helpers.refusals.noTextSpelling "nat flags";
  };

  # `concat` is `<family> addr . port to`; `interval` nft's evaluation
  # derives from the map, in text as in JSON.
  testSnatConcatAndInterval = {
    expr = ruleIn "ip" [
      {
        match = {
          left.meta.key = "l4proto";
          op = "==";
          right = "tcp";
        };
      }
      {
        snat = {
          family = "ip";
          addr.map = {
            key.payload = {
              protocol = "ip";
              field = "saddr";
            };
            data.set = [
              [
                "10.141.11.4"
                {
                  concat = [
                    "192.168.2.3"
                    80
                  ];
                }
              ]
            ];
          };
          type_flags = [
            "concat"
            "interval"
          ];
          flags = [ "persistent" ];
        };
      }
    ];
    expected = "add rule ip t c meta l4proto == tcp snat ip addr . port to ip saddr map { 10.141.11.4 : 192.168.2.3 . 80 } persistent\n";
  };

  testSnatConcatWithoutFamily = {
    expr = ruleIn "ip" [
      {
        snat = {
          addr = "10.0.0.1";
          type_flags = "concat";
        };
      }
    ];
    expectedError.msg = helpers.refusals.noTextSpelling "nat type_flags";
  };

  # `addr . port to` takes no port after it.
  testSnatConcatWithPort = {
    expr = ruleIn "ip" [
      tcpMatch
      {
        snat = {
          family = "ip";
          addr = "10.0.0.1";
          port = 80;
          type_flags = "concat";
        };
      }
    ];
    expectedError.msg = helpers.refusals.noTextSpelling "nat type_flags";
  };

  # A map lookup address takes its port right after the map.
  testDnatMapAddressPort = {
    expr = ruleIn "ip" [
      tcpMatch
      {
        dnat = {
          family = "ip";
          addr.map = {
            key.payload = {
              protocol = "ip";
              field = "saddr";
            };
            data.set = [
              [
                "10.0.0.1"
                "192.168.0.1"
              ]
            ];
          };
          port = 80;
        };
      }
    ];
    expected = "add rule ip t c meta l4proto == tcp dnat ip to ip saddr map { 10.0.0.1 : 192.168.0.1 }:80\n";
  };

  # ---- commands -------------------------------------------------------
  testFlushRuleset = {
    expr = one { flush.ruleset = null; };
    expected = "flush ruleset\n";
  };

  testFlushRulesetByFamily = {
    expr = one {
      flush.ruleset = {
        family = "ip";
      };
    };
    expected = "flush ruleset ip\n";
  };

  # An empty raw body flushes every family, like a null one.
  testFlushRulesetEmptyBody = {
    expr = one { flush.ruleset = { }; };
    expected = "flush ruleset\n";
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
    expected = "delete rule ip t c handle 42\n";
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
    expected = "rename chain ip t old new\n";
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
    expected = "replace rule ip t c handle 7 drop\n";
  };

  # `insert` places the rule before the rule with the handle.
  testInsertRuleByHandle = {
    expr = one {
      insert.rule = {
        family = "ip";
        table = "t";
        chain = "c";
        handle = 7;
        expr = [ { drop = null; } ];
      };
    };
    expected = "insert rule ip t c handle 7 drop\n";
  };

  # nft's JSON parser ignores a listed rule's handle, while text reads it
  # as a position, so text leaves it off.
  testListedRuleDropsHandle = {
    expr = one {
      rule = {
        family = "ip";
        table = "t";
        chain = "c";
        handle = 7;
        expr = [ { drop = null; } ];
      };
    };
    expected = "rule ip t c drop\n";
  };

  # nft 1.1.6's JSON parser ignores a handle on `add rule`, while 1.1.7's
  # and text read it as a position, so text can't load what both load.
  testAddRuleHandleRefused = {
    expr = one {
      add.rule = {
        family = "ip";
        table = "t";
        chain = "c";
        handle = 7;
        expr = [ { drop = null; } ];
      };
    };
    expectedError.msg = helpers.refusals.noTextSpelling "add rule handle";
  };

  # ---- named-set references ------------------------------------------

  # `{ set = "@name"; }` is the libnftables-JSON named-set reference
  # shape; the text grammar wants the bare reference, no braces.
  testMatchSetRef = {
    expr = one {
      add.rule = {
        family = "inet";
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
              op = "==";
              right = {
                set = "@trusted";
              };
            };
          }
        ];
      };
    };
    expected = "add rule inet t c meta iifname == @trusted\n";
  };

  # A non-`@`-prefixed string body is the footgun: the renderer used to
  # emit `{ <bare> }`, which the parser reads as a 1-element anonymous
  # set whose sole element is a literal hostname string. The guardrail
  # converts that silent miss into a loud throw.
  testRenderSetStringBodyThrows = {
    expr = one {
      add.rule = {
        family = "inet";
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
              op = "==";
              right = {
                set = "trusted";
              };
            };
          }
        ];
      };
    };
    expectedError.msg = helpers.refusals.setExpression;
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
    expected = "flush ruleset\nadd table ip t\nadd chain ip t c\n";
  };
}
// typeKeyCtObjectMapRefusals
// elementStatementRefusals
// ctFamilyAddressKeyTests
