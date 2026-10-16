{
  fixtures,
  helpers,
  internal,
  lib,
  nftlib,
  ...
}:

/*
  Interface names through every surface where one reaches a renderer.
  Text quotes each value it knows to be an interface name (ADR 0004):
  set and map elements whose type or typeof key is an interface name,
  the interface-name parts of concatenations, the right side of a match,
  vmap, or map lookup on an interface name, chain and flowtable devices,
  and dup and fwd devices. Bare, `010` loaded as `8`, `a|b` as `c`, and
  `$lan` took a host `define`; quoted, each loads the JSON string.

  One predicate (lib/nft-safe-ifname.nix) holds the quoted-string rules
  and the kernel's own name rules. The schema's `types.ifname` (chain and
  flowtable `dev`) and the renderer's `quoteIfname` both check it, and a
  value that fails it raises a Refusal naming its field. Where the
  renderer can't tell that a value is an interface name, such as an
  `add element` command, it keeps the bare-token check and refuses a
  string that nft's lexer would read as something else.
*/
let
  dsl = nftlib.dsl;
  inherit (nftlib) toJson toText toTextPretty;

  inherit (internal) nftSafeIfname;
  inherit (helpers) refusals;

  # ----- Bad / good ifname samples ----------------------------------------

  # The UTF-8 encoding of a code point.
  utf8 = codePoint: builtins.fromJSON ''"\u${codePoint}"'';

  # Names the predicate rejects: the quoted-string rules, then the
  # kernel's `dev_valid_name` rules.
  badIfnames = {
    quote = ''eth0"'';
    backslash = ''eth0\x'';
    newline = "eth\n0";
    slash = "eth/0";
    colon = "eth:0";
    space = "eth 0";
    tab = "eth\t0";
    dot = ".";
    dotdot = "..";
    empty = "";
    oversize = "abcdefghijklmnop"; # 16 bytes, IFNAMSIZ-1 is 15
    # The kernel's Latin-1 `isspace` takes byte 0xA0 as a space, so it
    # refuses every name containing it, here U+00A0 and U+00E0.
    noBreakSpace = "eth${utf8 "00a0"}0";
    byteA0 = "eth${utf8 "00e0"}";
  };

  goodIfnames = {
    short = "eth0";
    wifi = "wlp3s0";
    vlanDot = "eth0.100";
    veth = "veth-pod1";
    single = "a";
    maxLen = "abcdefghijklmno"; # 15 bytes, IFNAMSIZ-1
    # Other bytes above 0x7F are no kernel space.
    nonAscii = "eth${utf8 "00e9"}";
    # Bare, these loaded as something else or failed to parse.
    octal = "010";
    hex = "0x10";
    bitor = "a|b";
    wildcard = "eth*";
    variable = "$lan";
    exponent = "1e5";
    leadingDash = "-x";
    # Bare, these split an element list or broke the parser.
    comma = "eth0,eth1";
    semicolon = "eth0;x";
    braces = "{eth0}";
    hash = "eth0#c";
  };

  # ----- Surfaces ----------------------------------------------------------

  # Raw ruleset builders, which bypass the schema, each taking one name.
  rawRule = expr: {
    nftables = [
      {
        add.rule = {
          family = "inet";
          table = "t";
          chain = "c";
          inherit expr;
        };
      }
    ];
  };

  rawMatchRule =
    metaKey: rightVal:
    rawRule [
      {
        match = {
          left.meta.key = metaKey;
          op = "==";
          right = rightVal;
        };
      }
    ];

  rawChainDev = dev: {
    nftables = [
      {
        add.chain = {
          family = "netdev";
          table = "t";
          name = "ingress";
          type = "filter";
          hook = "ingress";
          prio = 0;
          inherit dev;
        };
      }
    ];
  };

  rawFlowtableDev = dev: {
    nftables = [
      {
        add.flowtable = {
          family = "inet";
          table = "t";
          name = "ft";
          hook = "ingress";
          prio = 0;
          inherit dev;
        };
      }
    ];
  };

  # A set object with `body`'s type and elements.
  rawSet = body: {
    nftables = [
      {
        add.set = {
          family = "inet";
          table = "t";
          name = "s";
        }
        // body;
      }
    ];
  };

  iifname.meta.key = "iifname";
  ipSaddr.payload = {
    protocol = "ip";
    field = "saddr";
  };

  # Surfaces the schema types as `ifname`: it rejects a bad name.
  schemaSurfaces = {
    inherit (fixtures.ifnameRulesets) chainDevString flowtableDevString;
    chainDevList = v: fixtures.ifnameRulesets.chainDevList [ v ];
    flowtableDevList = v: fixtures.ifnameRulesets.flowtableDevList [ v ];
  };

  # Surfaces text quotes, each with the field its Refusal names.
  textSurfaces = {
    setElem = {
      build = fixtures.ifnameRulesets.setElem;
      field = "set element";
    };
    setElemWithOptions = {
      build = fixtures.ifnameRulesets.setElemWithOptions;
      field = "set element";
    };
    mapKey = {
      build = fixtures.ifnameRulesets.mapKey;
      field = "map element";
    };
    chainDev = {
      build = v: rawChainDev [ v ];
      field = "chain device";
    };
    chainDevString = {
      build = rawChainDev;
      field = "chain device";
    };
    flowtableDev = {
      build = v: rawFlowtableDev [ v ];
      field = "flowtable device";
    };
    dupDev = {
      build =
        dev:
        rawRule [
          {
            dup = {
              addr = "192.0.2.1";
              inherit dev;
            };
          }
        ];
      field = "dup device";
    };
    fwdDev = {
      build = dev: rawRule [ { fwd.dev = dev; } ];
      field = "fwd device";
    };
    fwdNextHopDev = {
      build =
        dev:
        rawRule [
          {
            fwd = {
              inherit dev;
              family = "ip";
              addr = "192.0.2.1";
            };
          }
        ];
      field = "fwd device";
    };
  }
  // lib.listToAttrs (
    map
      (
        key:
        lib.nameValuePair "match_${key}" {
          build = rawMatchRule key;
          field = "match right";
        }
      )
      [
        "iifname"
        "oifname"
        "sdifname"
        "ibrname"
        "obrname"
      ]
  );

  # ----- Predicate --------------------------------------------------------

  predicateTests = lib.listToAttrs (
    (lib.mapAttrsToList (n: v: {
      name = "testPredicateRejects_${n}";
      value = {
        expr = nftSafeIfname.isSafe v;
        expected = false;
      };
    }) badIfnames)
    ++ (lib.mapAttrsToList (n: v: {
      name = "testPredicateAccepts_${n}";
      value = {
        expr = nftSafeIfname.isSafe v;
        expected = true;
      };
    }) goodIfnames)
  );

  # ----- Schema -----------------------------------------------------------

  schemaRejectionTests = lib.concatMapAttrs (
    surface: build:
    lib.mapAttrs' (
      badName: badValue:
      lib.nameValuePair "testSchemaRejects_${surface}_${badName}" {
        expr = toJson (build badValue);
        expectedError.msg = "interface name \\(1-15 bytes";
      }
    ) badIfnames
  ) schemaSurfaces;

  schemaAcceptanceTests = lib.concatMapAttrs (
    surface: build:
    lib.mapAttrs' (
      goodName: goodValue:
      lib.nameValuePair "testSchemaAccepts_${surface}_${goodName}" {
        expr = builtins.isString (toJson (build goodValue));
        expected = true;
      }
    ) goodIfnames
  ) schemaSurfaces;

  # ----- Text: every surface quotes a good name, refuses a bad one ---------

  textQuotingTests = lib.concatMapAttrs (
    surface:
    { build, ... }:
    lib.mapAttrs' (
      goodName: goodValue:
      lib.nameValuePair "testTextQuotes_${surface}_${goodName}" {
        expr = lib.hasInfix ''"${goodValue}"'' (toText (build goodValue));
        expected = true;
      }
    ) goodIfnames
  ) textSurfaces;

  textRefusalTests = lib.concatMapAttrs (
    surface:
    { build, field }:
    lib.mapAttrs' (
      badName: badValue:
      lib.nameValuePair "testTextRefuses_${surface}_${badName}" {
        expr = toTextPretty (build badValue);
        expectedError.msg = refusals.ifname field;
      }
    ) badIfnames
  ) textSurfaces;

  # ----- Text: exact spellings --------------------------------------------

  matchTests = {
    # Non-ifname meta keys are unaffected — `mark` accepts integer
    # comparison and shouldn't see a stricter ifname check applied.
    testMatchAcceptsNonIfnameKey = {
      expr = builtins.isString (toText (rawMatchRule "mark" 100));
      expected = true;
    };

    # Safe ifname renders QUOTED post-fix (the new behaviour). Pin the
    # exact output so a future refactor that drops the quoting breaks
    # here.
    testMatchQuotesSafeIfname = {
      expr = toText (rawMatchRule "iifname" "eth0");
      expected = "add rule inet t c meta iifname == \"eth0\"";
    };

    # `@`-prefixed string is the named-set reference form; must stay
    # bare so nft reads it as a setRef and not as a quoted ifname
    # literal.
    testMatchPreservesSetRefBare = {
      expr = toText (rawMatchRule "iifname" "@trusted");
      expected = "add rule inet t c meta iifname == @trusted";
    };

    testMatchQuotesAnonymousSetElements = {
      expr = toText (
        rawMatchRule "iifname" {
          set = [
            "lo"
            "eth*"
          ];
        }
      );
      expected = "add rule inet t c meta iifname == { \"lo\", \"eth*\" }";
    };

    testMatchQuotesConcatenationComponents = {
      expr = toText (rawRule [
        {
          match = {
            left.concat = [
              iifname
              ipSaddr
            ];
            op = "==";
            right.set = [
              {
                concat = [
                  "010"
                  "10.0.0.1"
                ];
              }
            ];
          };
        }
      ]);
      expected = "add rule inet t c meta iifname . ip saddr == { \"010\" . 10.0.0.1 }";
    };

    testMatchQuotesFibOifname = {
      expr = toText (rawRule [
        {
          match = {
            left.fib = {
              flags = [
                "daddr"
                "iif"
              ];
              result = "oifname";
            };
            op = "!=";
            right = "0x10";
          };
        }
      ]);
      expected = "add rule inet t c fib daddr . iif oifname != \"0x10\"";
    };

    testVmapQuotesKeys = {
      expr = toText (rawRule [
        {
          vmap = {
            key = iifname;
            data.set = [
              [
                "010"
                { accept = null; }
              ]
            ];
          };
        }
      ]);
      expected = "add rule inet t c meta iifname vmap { \"010\" : accept }";
    };

    testMapLookupQuotesKeys = {
      expr = toText (rawRule [
        {
          mangle = {
            key.meta.key = "mark";
            value.map = {
              key = iifname;
              data.set = [
                [
                  "$lan"
                  3
                ]
              ];
            };
          };
        }
      ]);
      expected = "add rule inet t c meta mark set meta iifname map { \"$lan\" : 3 }";
    };
  };

  quotingTests = {
    # Bare, `010` loads as `8`; quoted, it loads the JSON string.
    testQuotesTypedSetElements = {
      expr = toText (rawSet {
        type = "ifname";
        elem = [
          "eth0"
          "010"
          "$lan"
        ];
      });
      expected = "add set inet t s { type ifname; elements = { \"eth0\", \"010\", \"$lan\" }; }";
    };

    testQuotesMapKeysAndValues = {
      expr = toText {
        nftables = [
          {
            add.map = {
              family = "inet";
              table = "t";
              name = "m";
              type = "ifname";
              map = "ifname";
              elem = [
                [
                  "010"
                  "0x10"
                ]
              ];
            };
          }
        ];
      };
      expected = "add map inet t m { type ifname : ifname; elements = { \"010\" : \"0x10\" }; }";
    };

    testQuotesElementWithOptions = {
      expr = toText (rawSet {
        type = "ifname";
        elem = [
          {
            elem = {
              val = "a|b";
              comment = "c";
            };
          }
        ];
      });
      expected = "add set inet t s { type ifname; elements = { \"a|b\" comment \"c\" }; }";
    };

    testQuotesConcatenationComponents = {
      expr = toText (rawSet {
        type = [
          "ipv4_addr"
          "ifname"
        ];
        elem = [
          {
            concat = [
              "10.0.0.1"
              "1e5"
            ];
          }
        ];
      });
      expected = "add set inet t s { type ipv4_addr . ifname; elements = { 10.0.0.1 . \"1e5\" }; }";
    };

    # The type line belongs to #34; only the elements are pinned here.
    testQuotesTypeofSetElements = {
      expr = lib.hasInfix ''elements = { "-x" }'' (
        toText (rawSet {
          type.typeof = iifname;
          elem = [ "-x" ];
        })
      );
      expected = true;
    };

    testQuotesTypeofConcatenationComponents = {
      expr = lib.hasInfix ''elements = { "-x" . 10.0.0.1 }'' (
        toText (rawSet {
          type.typeof.concat = [
            iifname
            ipSaddr
          ];
          elem = [
            {
              concat = [
                "-x"
                "10.0.0.1"
              ];
            }
          ];
        })
      );
      expected = true;
    };

    testQuotesChainDevices = {
      expr = lib.hasInfix ''devices = { "010", "eth1" }'' (
        toText (rawChainDev [
          "010"
          "eth1"
        ])
      );
      expected = true;
    };

    # JSON reads `*` as the catch-all element, which text spells bare.
    testKeepsCatchAllBare = {
      expr = toText (rawSet {
        type = "ifname";
        elem = [ "*" ];
      });
      expected = "add set inet t s { type ifname; elements = { * }; }";
    };
  };

  # ----- Values the renderer can't identify --------------------------------

  # An `add element` command doesn't carry its set's type, so its values
  # keep the bare-token check, and a string must be one nft's lexer reads
  # as written: bare, `010` loads as `8` into an interface-name set.
  rawElementCommand = elem: {
    nftables = [
      {
        add.element = {
          family = "inet";
          table = "t";
          name = "s";
          inherit elem;
        };
      }
    ];
  };

  # Strings nft's lexer reads as something else: a number (`010` loads as
  # `8`, `0x10` as `16`), a variable, an expression (`a|b` loads as `c`), a
  # range, or several tokens.
  misreadElements = {
    octal = "010";
    hex = "0x10";
    variable = "$lan";
    bitor = "a|b";
    range = "1-5";
    leadingDigit = "0eth";
    leadingDash = "-x";
    mapElement = "a:b:c";
    ip4Tail = "1.2.3.4.5";
  };

  # Strings it reads as written: a name, an address, a reference.
  writtenElements = {
    name = "eth0";
    dotted = "eth0.100";
    dashed = "veth-pod1";
    wildcard = "eth*";
    ip4 = "192.0.2.1";
    ip6 = "2001:db8::1";
    ip6Full = "2001:db8:0:0:0:0:0:1";
    ip6Ip4 = "::ffff:192.0.2.1";
    mac = "aa:bb:cc:dd:ee:ff";
    reference = "@s";
    catchAll = "*";
  };

  elementTests =
    lib.mapAttrs' (
      name: value:
      lib.nameValuePair "testElementCommandRefuses_${name}" {
        expr = toText (rawElementCommand [ value ]);
        expectedError.msg = refusals.unidentified "element";
      }
    ) misreadElements
    // lib.mapAttrs' (
      name: value:
      lib.nameValuePair "testElementCommandRendersBare_${name}" {
        expr = toText (rawElementCommand [ value ]);
        expected = "add element inet t s { ${value} }";
      }
    ) writtenElements;

  unidentifiedTests = elementTests // {
    testElementCommandRendersInteger = {
      expr = toText (rawElementCommand [ 8 ]);
      expected = "add element inet t s { 8 }";
    };
    testElementCommandRefusesConcatPart = {
      expr = toText (rawElementCommand [
        {
          concat = [
            "eth0"
            "010"
          ];
        }
      ]);
      expectedError.msg = refusals.unidentified "element";
    };
    testElementCommandRefusesRangeEnd = {
      expr = toText (rawElementCommand [
        {
          range = [
            "a"
            "010"
          ];
        }
      ]);
      expectedError.msg = refusals.unidentified "element";
    };
    testElementCommandRefusesElemValue = {
      expr = toText (rawElementCommand [ { elem.val = "010"; } ]);
      expectedError.msg = refusals.unidentified "element";
    };
    testElementCommandRefusesMapValue = {
      expr = toText (rawElementCommand [
        [
          "eth0"
          "010"
        ]
      ]);
      expectedError.msg = refusals.unidentified "element value";
    };
    testElementCommandRefusesUnsafeToken = {
      expr = toText (rawElementCommand [ "eth0,eth1" ]);
      expectedError.msg = refusals.scalar;
    };
    # A set whose type isn't an interface name is not quoted either.
    testStringSetRefusesUnsafeToken = {
      expr = toText (rawSet {
        type = "string";
        elem = [ "a,b" ];
      });
      expectedError.msg = refusals.scalar;
    };
  };

  jsonTests = {
    # JSON quotes the bytes, so no name can widen a set there.
    testJsonRoundTripsLiteralBytes = {
      expr = toJson (rawSet {
        type = "ifname";
        elem = [ "eth0,eth1" ];
      });
      expected = "{\"nftables\":[{\"add\":{\"set\":{\"elem\":[\"eth0,eth1\"],\"family\":\"inet\",\"name\":\"s\",\"table\":\"t\",\"type\":\"ifname\"}}}]}";
    };
    # The table tree no longer checks set elements: text quotes them.
    testTableTreeAcceptsAnyQuotableElement = {
      expr = builtins.isString (toJson (fixtures.ifnameRulesets.setElem "eth0,eth1"));
      expected = true;
    };
  };
in
predicateTests
// schemaRejectionTests
// schemaAcceptanceTests
// textQuotingTests
// textRefusalTests
// matchTests
// quotingTests
// unidentifiedTests
// jsonTests
