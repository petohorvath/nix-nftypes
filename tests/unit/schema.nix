{
  helpers,
  internal,
  lib,
  nftlib,
  ...
}:

let
  inherit (helpers) roundtrip;
  inherit (nftlib) toJson;

  # A stateful-object reference selected by destination port.
  portMapReference.map = {
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
  portMapReferenceJson = "{\"map\":{\"data\":{\"set\":[[22,\"a\"],[80,\"b\"]]},\"key\":{\"payload\":{\"field\":\"dport\",\"protocol\":\"tcp\"}}}}";

  # A listed command validated as a singleton ruleset, deep-forced so
  # lazy submodule checks run.
  readBack =
    command:
    let
      ruleset = helpers.validate nftlib.types.ruleset { nftables = [ command ]; };
    in
    builtins.deepSeq ruleset ruleset;

  # Schema↔text drift: every tag in the schema's `statement`,
  # `taggedExpression`, and `addObject`/`readBackObject` unions must have a
  # matching entry in the corresponding text/* dispatch table —
  # otherwise the renderer throws at *render time* (`no renderer for
  # tag '…'`) instead of failing eval-time. Catches the regression class
  # where a new schema tag is added without a renderer.
  textDriftTests =
    let
      inherit (internal) textDispatch;

      # Tags in `xs` that don't appear in `ys`. A non-empty result lists
      # the offenders verbatim, which makes the failure output
      # self-explanatory.
      missing = xs: ys: lib.subtractLists ys xs;
      statementTags = builtins.attrNames nftlib.types.statement.functor.payload.tags;
      expressionTags = builtins.attrNames nftlib.types.taggedExpression.functor.payload.tags;
      # Renderable object kinds: every union tag in addObject ∪
      # readBackObject (the latter adds `metainfo`, `meter`, and the
      # Read-back-only `tunnel`) plus `ruleset`, which appears only as a
      # command-level envelope but still needs a header renderer for
      # `list/flush/reset ruleset`.
      objectKinds =
        lib.unique (
          builtins.attrNames nftlib.types.addObject.functor.payload.tags
          ++ builtins.attrNames nftlib.types.readBackObject.functor.payload.tags
        )
        ++ [ "ruleset" ];
    in
    {
      # Schema → renderer: every tag the schema accepts must be
      # renderable (otherwise renderStatement/Expression/Object throws
      # at render time).
      testTextDrift_statementTagsCovered = {
        expr = missing statementTags textDispatch.statementTags;
        expected = [ ];
      };
      testTextDrift_expressionTagsCovered = {
        expr = missing expressionTags textDispatch.expressionTags;
        expected = [ ];
      };
      testTextDrift_objectKindsCovered = {
        expr = missing objectKinds textDispatch.objectKinds;
        expected = [ ];
      };

      # Renderer → schema: every entry in the renderer dispatch table
      # must correspond to a real schema tag (otherwise it's dead code
      # — unreachable because no schema route emits that tag).
      testTextDrift_statementRendererHasNoOrphans = {
        expr = missing textDispatch.statementTags statementTags;
        expected = [ ];
      };
      testTextDrift_expressionRendererHasNoOrphans = {
        expr = missing textDispatch.expressionTags expressionTags;
        expected = [ ];
      };
      testTextDrift_objectRendererHasNoOrphans = {
        expr = missing textDispatch.objectKinds objectKinds;
        expected = [ ];
      };
    };

  /*
    Commands nft mishandles are Known differences (ADR 0010), each with a
    live "still misbehaves" case in tests/fixtures/nft-misbehaviour.nix:
    delete or destroy of a ct expectation deletes its table, list of one
    lists the table, ct timeout delete fails and list aborts, and nft 1.1.7
    aborts on delete or destroy of a ct count.
  */
  mishandledCommandTests =
    let
      bodies = {
        "ct count" = {
          family = "inet";
          table = "t";
          name = "cc";
          val = 10;
        };
        "ct expectation" = {
          family = "inet";
          table = "t";
          name = "ce";
          protocol = "tcp";
          dport = 21;
          timeout = 1000;
          size = 10;
          l3proto = "ip";
        };
        "ct timeout" = {
          family = "inet";
          table = "t";
          name = "cto";
          protocol = "tcp";
          l3proto = "ip";
          policy.established = 100;
        };
      };
      mishandled = lib.mapAttrs (_: command: lib.splitString ":" command) {
        testDeleteCtCountRejected = "delete:ct count";
        testDestroyCtCountRejected = "destroy:ct count";
        testDeleteCtExpectationRejected = "delete:ct expectation";
        testDestroyCtExpectationRejected = "destroy:ct expectation";
        testListCtExpectationRejected = "list:ct expectation";
        testDeleteCtTimeoutRejected = "delete:ct timeout";
        testDestroyCtTimeoutRejected = "destroy:ct timeout";
        testListCtTimeoutRejected = "list:ct timeout";
      };
    in
    lib.mapAttrs (_: command: {
      expr = roundtrip nftlib.types.command (lib.setAttrByPath command bodies.${lib.last command});
      expectedError.msg = "validate\\.${builtins.head command}.*is not of type";
    }) mishandled
    // {
      # The same objects still add, and still read back as listed objects.
      testMishandledKindsStillAdd = {
        expr = map (
          kind: builtins.isString (roundtrip nftlib.types.command { add.${kind} = bodies.${kind}; })
        ) (builtins.attrNames bodies);
        expected = [
          true
          true
          true
        ];
      };
      testMishandledKindsStillReadBack = {
        expr = map (
          kind:
          builtins.isAttrs (readBack {
            ${kind} = bodies.${kind};
          })
        ) (builtins.attrNames bodies);
        expected = [
          true
          true
          true
        ];
      };
    };

  /*
    nft's JSON parser writes a tunnel's dport into its sport and leaves a
    missing port, ttl, or tos uninitialised, and nft crashes on delete,
    destroy, and list of a tunnel. So types.command rejects every tunnel
    command (Known differences, ADR 0010), each with a live "still
    misbehaves" case in tests/fixtures/nft-misbehaviour.nix, and only the
    Read-back shape validates.
  */
  tunnelCommandTests =
    let
      tunnel = {
        family = "netdev";
        table = "t";
        name = "tun";
        id = 10;
        "src-ipv4" = "192.0.2.1";
        "dst-ipv4" = "192.0.2.2";
        sport = 1111;
        dport = 2222;
        tos = 0;
        ttl = 64;
      };
    in
    lib.mapAttrs
      (_: verb: {
        expr = roundtrip nftlib.types.command { ${verb}.tunnel = tunnel; };
        expectedError.msg = "validate\\.${verb}.*is not of type";
      })
      {
        testAddTunnelRejected = "add";
        testCreateTunnelRejected = "create";
        testDeleteTunnelRejected = "delete";
        testDestroyTunnelRejected = "destroy";
        testListTunnelRejected = "list";
      }
    // {
      testTunnelStillReadsBack = {
        expr = builtins.isAttrs (readBack {
          tunnel = tunnel // {
            handle = 1;
          };
        });
        expected = true;
      };
    };

  # Each command requires the fields nft's JSON parser requires for it
  # (parser_json.c), and no others: a command missing one fails naming the
  # field, and a field nft ignores for the verb isn't demanded.
  commandRequirementTests =
    let
      missing = field: "validate\\.${field}' was accessed but has no value defined";
      selector = {
        family = "inet";
        table = "t";
        name = "ft";
      };
      byHandle = removeAttrs selector [ "name" ] // {
        handle = 4;
      };
      flowtable = selector // {
        hook = "ingress";
        prio = 0;
        dev = "lo";
      };
    in
    {
      testRenameChainRequiresNewname = {
        expr = roundtrip nftlib.types.command {
          rename.chain = {
            family = "ip";
            table = "t";
            name = "c";
          };
        };
        expectedError.msg = missing "rename\\.chain\\.newname";
      };
      testRenameChainWithNewname = {
        expr = roundtrip nftlib.types.command {
          rename.chain = {
            family = "ip";
            table = "t";
            name = "c";
            newname = "d";
          };
        };
        expected = "{\"rename\":{\"chain\":{\"family\":\"ip\",\"name\":\"c\",\"newname\":\"d\",\"table\":\"t\"}}}";
      };
      # `newname` belongs to the rename command, not to a chain.
      testAddChainRejectsNewname = {
        expr = roundtrip nftlib.types.command {
          add.chain = {
            family = "ip";
            table = "t";
            name = "c";
            newname = "d";
          };
        };
        expectedError.msg = "newname' does not exist";
      };
      testReplaceRuleRequiresHandle = {
        expr = roundtrip nftlib.types.command {
          replace.rule = {
            family = "ip";
            table = "t";
            chain = "c";
            expr = [ { accept = null; } ];
          };
        };
        expectedError.msg = missing "replace\\.rule\\.handle";
      };
      # nft treats handle 0 as missing: "Handle is required when replacing
      # a rule."
      testReplaceRuleRejectsHandleZero = {
        expr = roundtrip nftlib.types.command {
          replace.rule = {
            family = "ip";
            table = "t";
            chain = "c";
            handle = 0;
            expr = [ { accept = null; } ];
          };
        };
        expectedError.msg = "validate\\.replace\\.rule\\.handle.*is not of type";
      };
      testAddFlowtableRequiresHook = {
        expr = roundtrip nftlib.types.command {
          add.flowtable = removeAttrs flowtable [ "hook" ];
        };
        expectedError.msg = missing "add\\.flowtable\\.hook";
      };
      testAddFlowtableRequiresPrio = {
        expr = roundtrip nftlib.types.command {
          add.flowtable = removeAttrs flowtable [ "prio" ];
        };
        expectedError.msg = missing "add\\.flowtable\\.prio";
      };
      testCreateFlowtableRequiresHook = {
        expr = roundtrip nftlib.types.command {
          create.flowtable = removeAttrs flowtable [ "hook" ];
        };
        expectedError.msg = missing "create\\.flowtable\\.hook";
      };
      testAddFlowtableWithHookAndPrio = {
        expr = roundtrip nftlib.types.command { add.flowtable = flowtable; };
        expected = "{\"add\":{\"flowtable\":{\"dev\":\"lo\",\"family\":\"inet\",\"hook\":\"ingress\",\"name\":\"ft\",\"prio\":0,\"table\":\"t\"}}}";
      };
      # Delete and destroy select the flowtable by name only.
      testDeleteFlowtableWithoutHook = {
        expr = roundtrip nftlib.types.command { delete.flowtable = selector; };
        expected = "{\"delete\":{\"flowtable\":{\"family\":\"inet\",\"name\":\"ft\",\"table\":\"t\"}}}";
      };
      testDestroyFlowtableWithoutHook = {
        expr = roundtrip nftlib.types.command { destroy.flowtable = selector; };
        expected = "{\"destroy\":{\"flowtable\":{\"family\":\"inet\",\"name\":\"ft\",\"table\":\"t\"}}}";
      };
      # nft's JSON parser ignores a set's or map's datatypes, a limit's
      # rate and a synproxy's mss and wscale on delete and destroy.
      testDeleteAndDestroySelectByName = {
        expr =
          lib.concatMap
            (
              verb:
              map (kind: roundtrip nftlib.types.command { ${verb}.${kind} = selector; }) [
                "set"
                "map"
                "limit"
                "synproxy"
              ]
            )
            [
              "delete"
              "destroy"
            ];
        expected = [
          ''{"delete":{"set":{"family":"inet","name":"ft","table":"t"}}}''
          ''{"delete":{"map":{"family":"inet","name":"ft","table":"t"}}}''
          ''{"delete":{"limit":{"family":"inet","name":"ft","table":"t"}}}''
          ''{"delete":{"synproxy":{"family":"inet","name":"ft","table":"t"}}}''
          ''{"destroy":{"set":{"family":"inet","name":"ft","table":"t"}}}''
          ''{"destroy":{"map":{"family":"inet","name":"ft","table":"t"}}}''
          ''{"destroy":{"limit":{"family":"inet","name":"ft","table":"t"}}}''
          ''{"destroy":{"synproxy":{"family":"inet","name":"ft","table":"t"}}}''
        ];
      };
      # Adding one still needs them.
      testAddSetRequiresType = {
        expr = roundtrip nftlib.types.command { add.set = selector; };
        expectedError.msg = missing "add\\.set\\.type";
      };
      testAddLimitRequiresRate = {
        expr = roundtrip nftlib.types.command {
          add.limit = selector // {
            per = "second";
          };
        };
        expectedError.msg = missing "add\\.limit\\.rate";
      };
      # nft rejects a destroy by handle alone ("Object item not found:
      # name").
      testDestroyRequiresName = {
        expr = map (kind: helpers.validates nftlib.types.command { destroy.${kind} = byHandle; }) [
          "set"
          "map"
          "limit"
          "flowtable"
          "counter"
          "chain"
        ];
        expected = [
          false
          false
          false
          false
          false
          false
        ];
      };
      testDestroySetRequiresName = {
        expr = roundtrip nftlib.types.command { destroy.set = byHandle; };
        expectedError.msg = missing "destroy\\.set\\.name";
      };
      testDestroyTableRequiresName = {
        expr = roundtrip nftlib.types.command {
          destroy.table = {
            family = "inet";
            handle = 1;
          };
        };
        expectedError.msg = missing "destroy\\.table\\.name";
      };
      testReplaceRuleWithHandle = {
        expr = roundtrip nftlib.types.command {
          replace.rule = {
            family = "ip";
            table = "t";
            chain = "c";
            handle = 4;
            expr = [ { accept = null; } ];
          };
        };
        expected = "{\"replace\":{\"rule\":{\"chain\":\"c\",\"expr\":[{\"accept\":null}],\"family\":\"ip\",\"handle\":4,\"table\":\"t\"}}}";
      };
    };

  # nft's `list` command, in text and JSON, has no singular selector for a
  # ct count, element, flowtable, metainfo, rule, or synproxy ("Unknown
  # object passed to list command"), so the schema rejects each (ADR 0009).
  listSelectorTests =
    let
      inTable = {
        family = "inet";
        table = "t";
      };
      bodies = {
        "ct count" = inTable // {
          name = "cc";
          val = 10;
        };
        element = inTable // {
          name = "s";
          elem = [ "10.0.0.1" ];
        };
        flowtable = inTable // {
          name = "ft";
          hook = "ingress";
          prio = 0;
        };
        metainfo = {
          version = "1.1.6";
          release_name = "Commodore Bullmoose #7";
          json_schema_version = 1;
        };
        rule = inTable // {
          chain = "c";
          handle = 2;
          expr = [ ];
        };
        synproxy = inTable // {
          name = "sp";
          mss = 1460;
          wscale = 7;
        };
      };
    in
    {
      testListRejectsKindsWithoutSelector = {
        expr = lib.mapAttrs (
          kind: body: helpers.validates nftlib.types.command { list.${kind} = body; }
        ) bodies;
        expected = lib.mapAttrs (_: _: false) bodies;
      };
      # Each body still reads back, so the rejection is the kind's.
      testListBodiesReadBack = {
        expr = lib.mapAttrs (
          kind: body: helpers.validates nftlib.types.readBackObject { ${kind} = body; }
        ) bodies;
        expected = lib.mapAttrs (_: _: true) bodies;
      };
    };

  /*
    nft 1.1.6's JSON parser ignores a handle on `add rule` and appends the
    rule, so the schema rejects one there (a Known difference, ADR 0010).
    `insert` places the rule before the handle's rule, and a listed rule
    carries its handle.
  */
  ruleHandleTests =
    let
      rule = {
        family = "ip";
        table = "t";
        chain = "c";
        handle = 3;
        expr = [ { accept = null; } ];
      };
    in
    {
      testAddRuleRejectsHandle = {
        expr = roundtrip nftlib.types.command { add.rule = rule; };
        expectedError.msg = "add\\.rule\\.handle' does not exist";
      };
      testAddRuleWithoutHandle = {
        expr = roundtrip nftlib.types.command { add.rule = removeAttrs rule [ "handle" ]; };
        expected = "{\"add\":{\"rule\":{\"chain\":\"c\",\"expr\":[{\"accept\":null}],\"family\":\"ip\",\"table\":\"t\"}}}";
      };
      testInsertRuleKeepsHandle = {
        expr = roundtrip nftlib.types.command { insert.rule = rule; };
        expected = "{\"insert\":{\"rule\":{\"chain\":\"c\",\"expr\":[{\"accept\":null}],\"family\":\"ip\",\"handle\":3,\"table\":\"t\"}}}";
      };
      testListedRuleKeepsHandle = {
        expr = roundtrip nftlib.types.readBackObject { inherit rule; };
        expected = "{\"rule\":{\"chain\":\"c\",\"expr\":[{\"accept\":null}],\"family\":\"ip\",\"handle\":3,\"table\":\"t\"}}";
      };
    };
in
textDriftTests
// mishandledCommandTests
// tunnelCommandTests
// commandRequirementTests
// ruleHandleTests
// listSelectorTests
// {
  # ------------------------------------------------------------------
  # Verdicts
  # ------------------------------------------------------------------
  testAcceptVerdict = {
    expr = roundtrip nftlib.types.statement { accept = null; };
    expected = ''{"accept":null}'';
  };

  testDropVerdict = {
    expr = roundtrip nftlib.types.statement { drop = null; };
    expected = ''{"drop":null}'';
  };

  testJumpVerdict = {
    expr = roundtrip nftlib.types.statement {
      jump = {
        target = "inbound";
      };
    };
    expected = ''{"jump":{"target":"inbound"}}'';
  };

  # ------------------------------------------------------------------
  # Match with payload expression
  # ------------------------------------------------------------------
  testMatchPayload = {
    expr = roundtrip nftlib.types.statement {
      match = {
        left = {
          payload = {
            protocol = "tcp";
            field = "dport";
          };
        };
        right = 22;
        op = "==";
      };
    };
    expected = "{\"match\":{\"left\":{\"payload\":{\"field\":\"dport\",\"protocol\":\"tcp\"}},\"op\":\"==\",\"right\":22}}";
  };

  # ------------------------------------------------------------------
  # Match with IPv6 address and prefix
  # ------------------------------------------------------------------
  testMatchIPv6Prefix = {
    expr = roundtrip nftlib.types.statement {
      match = {
        left = {
          payload = {
            protocol = "ip6";
            field = "saddr";
          };
        };
        right = {
          prefix = {
            addr = "2001:db8::";
            len = 32;
          };
        };
        op = "==";
      };
    };
    expected = "{\"match\":{\"left\":{\"payload\":{\"field\":\"saddr\",\"protocol\":\"ip6\"}},\"op\":\"==\",\"right\":{\"prefix\":{\"addr\":\"2001:db8::\",\"len\":32}}}}";
  };

  # ------------------------------------------------------------------
  # Port range
  # ------------------------------------------------------------------
  testPortRange = {
    expr = roundtrip nftlib.types.expression {
      range = [
        1024
        65535
      ];
    };
    expected = ''{"range":[1024,65535]}'';
  };

  # ------------------------------------------------------------------
  # Anonymous set of ports
  # ------------------------------------------------------------------
  testAnonymousSet = {
    expr = roundtrip nftlib.types.statement {
      match = {
        left = {
          payload = {
            protocol = "tcp";
            field = "dport";
          };
        };
        right = {
          set = [
            22
            80
            443
          ];
        };
        op = "==";
      };
    };
    expected = "{\"match\":{\"left\":{\"payload\":{\"field\":\"dport\",\"protocol\":\"tcp\"}},\"op\":\"==\",\"right\":{\"set\":[22,80,443]}}}";
  };

  # ------------------------------------------------------------------
  # inet_service lookup via @set-reference string
  # ------------------------------------------------------------------
  testSetReference = {
    expr = roundtrip nftlib.types.statement {
      match = {
        left = {
          payload = {
            protocol = "tcp";
            field = "dport";
          };
        };
        right = "@allowed_ports";
        op = "==";
      };
    };
    expected = "{\"match\":{\"left\":{\"payload\":{\"field\":\"dport\",\"protocol\":\"tcp\"}},\"op\":\"==\",\"right\":\"@allowed_ports\"}}";
  };

  # ------------------------------------------------------------------
  # `{ set = "@name" }` — canonical libnftables-JSON named-set
  # reference shape (vs. the bare-string form above). Both shapes are
  # accepted by `nft -j`; this asserts the JSON renderer emits the
  # shape unchanged so consumers using `expr.setRef` get the documented
  # form on the wire.
  # ------------------------------------------------------------------
  testSetReferenceWrapped = {
    expr = roundtrip nftlib.types.statement {
      match = {
        left = {
          meta = {
            key = "iifname";
          };
        };
        right = {
          set = "@trusted";
        };
        op = "==";
      };
    };
    expected = "{\"match\":{\"left\":{\"meta\":{\"key\":\"iifname\"}},\"op\":\"==\",\"right\":{\"set\":\"@trusted\"}}}";
  };

  # ------------------------------------------------------------------
  # DNAT with port
  # ------------------------------------------------------------------
  testDnat = {
    expr = roundtrip nftlib.types.statement {
      dnat = {
        addr = "10.0.0.1";
        port = 8080;
        family = "ip";
      };
    };
    expected = ''{"dnat":{"addr":"10.0.0.1","family":"ip","port":8080}}'';
  };

  # ------------------------------------------------------------------
  # SNAT with flags
  # ------------------------------------------------------------------
  testSnatFlags = {
    expr = roundtrip nftlib.types.statement {
      snat = {
        addr = "192.0.2.1";
        flags = [
          "random"
          "persistent"
        ];
      };
    };
    expected = "{\"snat\":{\"addr\":\"192.0.2.1\",\"flags\":[\"random\",\"persistent\"]}}";
  };

  # ------------------------------------------------------------------
  # Masquerade (no addr)
  # ------------------------------------------------------------------
  testMasquerade = {
    expr = roundtrip nftlib.types.statement { masquerade = { }; };
    expected = ''{"masquerade":{}}'';
  };

  # ------------------------------------------------------------------
  # Named set using ipv4_addr type
  # ------------------------------------------------------------------
  testNamedSet = {
    expr = roundtrip nftlib.types.objects.set {
      set = {
        family = "inet";
        table = "filter";
        name = "trusted_hosts";
        type = "ipv4_addr";
        flags = [ "interval" ];
        elem = [
          {
            prefix = {
              addr = "10.0.0.0";
              len = 8;
            };
          }
          "192.168.1.1"
        ];
      };
    };
    expected = "{\"set\":{\"elem\":[{\"prefix\":{\"addr\":\"10.0.0.0\",\"len\":8}},\"192.168.1.1\"],\"family\":\"inet\",\"flags\":[\"interval\"],\"name\":\"trusted_hosts\",\"table\":\"filter\",\"type\":\"ipv4_addr\"}}";
  };

  # ------------------------------------------------------------------
  # Map with concatenated key AND value: both sides are tuple types.
  # The nftables JSON parser (parser_json.c:3365) accepts datatype lists
  # for `type`/`map`; the dot-separated string form the adoc suggests
  # ("ipv4_addr . inet_service") is rejected at runtime.
  # ------------------------------------------------------------------
  testMapConcatenated = {
    expr = roundtrip nftlib.types.objects.map {
      map = {
        family = "ip";
        table = "nat";
        name = "port_forward";
        type = [
          "ipv4_addr"
          "inet_service"
        ];
        map = [
          "ipv4_addr"
          "inet_service"
        ];
        flags = [ "interval" ];
      };
    };
    expected = "{\"map\":{\"family\":\"ip\",\"flags\":[\"interval\"],\"map\":[\"ipv4_addr\",\"inet_service\"],\"name\":\"port_forward\",\"table\":\"nat\",\"type\":[\"ipv4_addr\",\"inet_service\"]}}";
  };

  # ------------------------------------------------------------------
  # vmap (verdict map) with jumps
  # ------------------------------------------------------------------
  testVmap = {
    expr = roundtrip nftlib.types.statement {
      vmap = {
        key = {
          meta = {
            key = "iifname";
          };
        };
        data = "@iifname_vmap";
      };
    };
    expected = "{\"vmap\":{\"data\":\"@iifname_vmap\",\"key\":{\"meta\":{\"key\":\"iifname\"}}}}";
  };

  # ------------------------------------------------------------------
  # Meta expression
  # ------------------------------------------------------------------
  testMetaExpr = {
    expr = roundtrip nftlib.types.expression {
      meta = {
        key = "mark";
      };
    };
    expected = ''{"meta":{"key":"mark"}}'';
  };

  # ------------------------------------------------------------------
  # CT expression with direction
  # ------------------------------------------------------------------
  testCtExpr = {
    expr = roundtrip nftlib.types.expression {
      ct = {
        key = "saddr";
        dir = "original";
        family = "ip";
      };
    };
    expected = ''{"ct":{"dir":"original","family":"ip","key":"saddr"}}'';
  };

  # ------------------------------------------------------------------
  # Binary AND operation (mask)
  # ------------------------------------------------------------------
  testBitAnd = {
    expr = roundtrip nftlib.types.expression {
      "&" = [
        {
          meta = {
            key = "mark";
          };
        }
        255
      ];
    };
    expected = ''{"&":[{"meta":{"key":"mark"}},255]}'';
  };

  # ------------------------------------------------------------------
  # Log with level and flags
  # ------------------------------------------------------------------
  testLog = {
    expr = roundtrip nftlib.types.statement {
      log = {
        prefix = "DROPPED: ";
        level = "info";
        flags = [
          "tcp options"
          "ip options"
        ];
      };
    };
    expected = "{\"log\":{\"flags\":[\"tcp options\",\"ip options\"],\"level\":\"info\",\"prefix\":\"DROPPED: \"}}";
  };

  # ------------------------------------------------------------------
  # Limit with per-unit
  # ------------------------------------------------------------------
  testLimit = {
    expr = roundtrip nftlib.types.statement {
      limit = {
        rate = 100;
        per = "second";
        burst = 50;
      };
    };
    expected = ''{"limit":{"burst":50,"per":"second","rate":100}}'';
  };

  # ------------------------------------------------------------------
  # Counter (named reference)
  # ------------------------------------------------------------------
  testCounterReference = {
    expr = roundtrip nftlib.types.statement { counter = "http_hits"; };
    expected = ''{"counter":"http_hits"}'';
  };

  # ------------------------------------------------------------------
  # Counter (anonymous)
  # ------------------------------------------------------------------
  testCounterAnonymous = {
    expr = roundtrip nftlib.types.statement {
      counter = {
        packets = 0;
        bytes = 0;
      };
    };
    expected = ''{"counter":{"bytes":0,"packets":0}}'';
  };

  # nft parses an inline counter only with both fields; any other object
  # is taken for a named-counter reference and fails.
  testCounterInlineNeedsPacketsAndBytes = {
    expr = map (body: helpers.validates nftlib.types.statement { counter = body; }) [
      { }
      { packets = 5; }
      { bytes = 5; }
    ];
    expected = [
      false
      false
      false
    ];
  };

  # A counter with one of them is a type error naming both, not a missing
  # option.
  testCounterInlineWithOnlyPacketsIsATypeError = {
    expr = roundtrip nftlib.types.statement { counter.packets = 5; };
    expectedError.msg = "is not of type .*inline counter with packets and bytes";
  };
  testCounterInlineWithOnlyBytesIsATypeError = {
    expr = roundtrip nftlib.types.statement { counter.bytes = 5; };
    expectedError.msg = "is not of type .*inline counter with packets and bytes";
  };

  # tproxy, snat and dnat translate to an address or a port: nft refuses
  # an empty tproxy ("Either address or port must be specified!"), and the
  # kernel an snat or dnat with neither ("Invalid argument").
  testTranslationNeedsAddressOrPort = {
    expr = map (helpers.validates nftlib.types.statement) [
      { tproxy = { }; }
      { tproxy.family = "ip"; }
      { tproxy = null; }
      { snat = { }; }
      { snat.flags = [ "random" ]; }
      { snat = null; }
      { dnat = { }; }
      { dnat.family = "ip"; }
      { tproxy.port = 8080; }
      { tproxy.addr = "10.0.0.1"; }
      { snat.port = 1024; }
      { dnat.addr = "10.0.0.1"; }
    ];
    expected = [
      false
      false
      false
      false
      false
      false
      false
      false
      true
      true
      true
      true
    ];
  };

  # nft lists a statement with no options as a null body, and its JSON
  # parser loads that body back.
  testReadBackNullStatementBodies = {
    expr = toJson (readBack {
      rule = {
        family = "inet";
        table = "t";
        chain = "c";
        handle = 2;
        expr = [
          { log = null; }
          { masquerade = null; }
          { redirect = null; }
          { queue = null; }
          { reject = null; }
        ];
      };
    });
    expected = "{\"nftables\":[{\"rule\":{\"chain\":\"c\",\"expr\":[{\"log\":null},{\"masquerade\":null},{\"redirect\":null},{\"queue\":null},{\"reject\":null}],\"family\":\"inet\",\"handle\":2,\"table\":\"t\"}}]}";
  };

  # ------------------------------------------------------------------
  # FIB reverse-path check
  # ------------------------------------------------------------------
  testFib = {
    expr = roundtrip nftlib.types.expression {
      fib = {
        result = "oif";
        flags = [
          "saddr"
          "mark"
        ];
      };
    };
    expected = ''{"fib":{"flags":["saddr","mark"],"result":"oif"}}'';
  };

  # ------------------------------------------------------------------
  # FIB result "check" — predicate form (parser_json.c:1181, special
  # NFT_FIB_F_PRESENT branch).
  # ------------------------------------------------------------------
  testFibResultCheck = {
    expr = roundtrip nftlib.types.expression {
      fib = {
        result = "check";
        flags = [ "saddr" ];
      };
    };
    expected = ''{"fib":{"flags":["saddr"],"result":"check"}}'';
  };

  # ------------------------------------------------------------------
  # rt key "ipsec" — NFT_RT_XFRM token (parser_json.c:993-997).
  # ------------------------------------------------------------------
  testRtIpsecKey = {
    expr = roundtrip nftlib.types.expression {
      rt = {
        key = "ipsec";
        family = "ip";
      };
    };
    expected = ''{"rt":{"family":"ip","key":"ipsec"}}'';
  };

  # ------------------------------------------------------------------
  # osf key "version" — second branch in parser_json.c:486-489 that
  # was missed when the schema was first derived (only "name" present).
  # ------------------------------------------------------------------
  testOsfVersionKey = {
    expr = roundtrip nftlib.types.expression {
      osf = {
        key = "version";
        ttl = "loose";
      };
    };
    expected = ''{"osf":{"key":"version","ttl":"loose"}}'';
  };

  # ------------------------------------------------------------------
  # `flush meter` — accepted by parser_json.c:4302 but previously
  # missing from the schema's `flushObject` union.
  # ------------------------------------------------------------------
  testFlushMeter = {
    expr = roundtrip nftlib.types.command {
      flush = {
        meter = {
          family = "inet";
          table = "filter";
          name = "rate_meter";
        };
      };
    };
    expected = "{\"flush\":{\"meter\":{\"family\":\"inet\",\"name\":\"rate_meter\",\"table\":\"filter\"}}}";
  };

  # ------------------------------------------------------------------
  # `flush flowtable` — rejected by parser_json.c (no `flowtable` row
  # in `cmd_obj_table[]` at line 4297-4304). Schema previously
  # accepted it; this asserts that's no longer the case.
  # ------------------------------------------------------------------
  testFlushFlowtableRejected = {
    expr = roundtrip nftlib.types.command {
      flush = {
        flowtable = {
          family = "inet";
          table = "filter";
          name = "ft";
        };
      };
    };
    expectedError.msg = "validate\\.flush.*is not of type";
  };

  # nftables rejects `create rule` explicitly. `create` must not reuse the
  # broader add-object union or raw typed input would accept an impossible
  # command even though the DSL omits its constructor.
  testCreateRuleRejected = {
    expr = roundtrip nftlib.types.command {
      create = {
        rule = {
          family = "inet";
          table = "filter";
          chain = "input";
          expr = [ ];
        };
      };
    };
    expectedError.msg = "validate\\.create.*is not of type";
  };

  # ------------------------------------------------------------------
  # Limit object: only fields the JSON parser actually reads
  # (parser_json.c:3863-3884). The previously-exposed `unit` field was
  # vestigial — the limit type is derived from `rate_unit`. Asserts
  # that a `unit` key is now rejected so future re-additions get caught.
  # ------------------------------------------------------------------
  testLimitObjectMinimal = {
    expr = roundtrip nftlib.types.objects.limit {
      limit = {
        family = "inet";
        table = "filter";
        name = "slow";
        rate = 5;
        per = "second";
        burst = 10;
      };
    };
    expected = "{\"limit\":{\"burst\":10,\"family\":\"inet\",\"name\":\"slow\",\"per\":\"second\",\"rate\":5,\"table\":\"filter\"}}";
  };

  testLimitObjectUnitRejected = {
    expr = roundtrip nftlib.types.objects.limit {
      limit = {
        family = "inet";
        table = "filter";
        name = "slow";
        rate = 5;
        per = "second";
        unit = "packets";
      };
    };
    expectedError.msg = "validate\\.limit\\.unit.*does not exist";
  };

  # ------------------------------------------------------------------
  # Numgen
  # ------------------------------------------------------------------
  testNumgen = {
    expr = roundtrip nftlib.types.expression {
      numgen = {
        mode = "inc";
        mod = 4;
        offset = 100;
      };
    };
    expected = ''{"numgen":{"mod":4,"mode":"inc","offset":100}}'';
  };

  # ------------------------------------------------------------------
  # Concatenation expression
  # ------------------------------------------------------------------
  testConcat = {
    expr = roundtrip nftlib.types.expression {
      concat = [
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
    expected = "{\"concat\":[{\"payload\":{\"field\":\"saddr\",\"protocol\":\"ip\"}},{\"payload\":{\"field\":\"dport\",\"protocol\":\"tcp\"}}]}";
  };

  # ------------------------------------------------------------------
  # Table object
  # ------------------------------------------------------------------
  testTable = {
    expr = roundtrip nftlib.types.objects.table {
      table = {
        family = "inet";
        name = "filter";
      };
    };
    expected = ''{"table":{"family":"inet","name":"filter"}}'';
  };

  # ------------------------------------------------------------------
  # Base chain
  # ------------------------------------------------------------------
  testBaseChain = {
    expr = roundtrip nftlib.types.objects.chain {
      chain = {
        family = "inet";
        table = "filter";
        name = "input";
        type = "filter";
        hook = "input";
        prio = 0;
        policy = "drop";
      };
    };
    expected = "{\"chain\":{\"family\":\"inet\",\"hook\":\"input\",\"name\":\"input\",\"policy\":\"drop\",\"prio\":0,\"table\":\"filter\",\"type\":\"filter\"}}";
  };

  /*
    nft's chain parser reads type, hook and prio as one optional group,
    so a chain missing any of them loads as a regular chain whose rules
    never see packets. The schema takes all three or none (a Known
    difference, ADR 0010), in commands and in Read-back.
  */
  testBaseChainNeedsTypeHookAndPrio =
    let
      chain = {
        family = "ip";
        table = "t";
        name = "c";
      };
      placements = [
        { }
        { type = "filter"; }
        { hook = "input"; }
        { prio = 0; }
        {
          type = "filter";
          hook = "input";
        }
        {
          type = "filter";
          prio = 0;
        }
        {
          hook = "input";
          prio = 0;
        }
        {
          type = "filter";
          hook = "input";
          prio = 0;
        }
      ];
      validatesIn = placement: {
        add = helpers.validates nftlib.types.command { add.chain = chain // placement; };
        create = helpers.validates nftlib.types.command { create.chain = chain // placement; };
        readBack = helpers.validates nftlib.types.ruleset {
          nftables = [ { chain = chain // placement // { handle = 1; }; } ];
        };
      };
      everywhere = accepted: {
        add = accepted;
        create = accepted;
        readBack = accepted;
      };
    in
    {
      expr = map validatesIn placements;
      expected = [
        (everywhere true)
        (everywhere false)
        (everywhere false)
        (everywhere false)
        (everywhere false)
        (everywhere false)
        (everywhere false)
        (everywhere true)
      ];
    };

  testBaseChainWithoutTypeNamesTheConstraint = {
    expr = helpers.validate nftlib.types.command {
      add.chain = {
        family = "ip";
        table = "t";
        name = "c";
        hook = "input";
        prio = 0;
      };
    };
    expectedError.msg = "type, hook and prio";
  };

  # ------------------------------------------------------------------
  # Rule with multiple statements
  # ------------------------------------------------------------------
  testRule = {
    expr = roundtrip nftlib.types.objects.rule {
      rule = {
        family = "inet";
        table = "filter";
        chain = "input";
        expr = [
          {
            match = {
              left = {
                payload = {
                  protocol = "tcp";
                  field = "dport";
                };
              };
              right = 22;
              op = "==";
            };
          }
          {
            counter = {
              packets = 0;
              bytes = 0;
            };
          }
          { accept = null; }
        ];
      };
    };
    expected = "{\"rule\":{\"chain\":\"input\",\"expr\":[{\"match\":{\"left\":{\"payload\":{\"field\":\"dport\",\"protocol\":\"tcp\"}},\"op\":\"==\",\"right\":22}},{\"counter\":{\"bytes\":0,\"packets\":0}},{\"accept\":null}],\"family\":\"inet\",\"table\":\"filter\"}}";
  };

  # ------------------------------------------------------------------
  # Flush ruleset command
  # ------------------------------------------------------------------
  testFlushRuleset = {
    expr = roundtrip nftlib.types.command {
      flush = {
        ruleset = null;
      };
    };
    expected = ''{"flush":{"ruleset":null}}'';
  };

  # ------------------------------------------------------------------
  # Add command wrapping a table
  # ------------------------------------------------------------------
  testAddCommand = {
    expr = roundtrip nftlib.types.command {
      add = {
        table = {
          family = "ip";
          name = "nat";
        };
      };
    };
    expected = ''{"add":{"table":{"family":"ip","name":"nat"}}}'';
  };

  # ------------------------------------------------------------------
  # Whole ruleset envelope
  # ------------------------------------------------------------------
  testRulesetEnvelope = {
    expr = roundtrip nftlib.types.ruleset {
      nftables = [
        {
          flush = {
            ruleset = null;
          };
        }
        {
          add = {
            table = {
              family = "inet";
              name = "filter";
            };
          };
        }
      ];
    };
    expected = "{\"nftables\":[{\"flush\":{\"ruleset\":null}},{\"add\":{\"table\":{\"family\":\"inet\",\"name\":\"filter\"}}}]}";
  };

  # ------------------------------------------------------------------
  # Element object
  # ------------------------------------------------------------------
  testElement = {
    expr = roundtrip nftlib.types.objects.element {
      element = {
        family = "inet";
        table = "filter";
        name = "blocklist";
        elem = [
          "1.2.3.4"
          "5.6.7.8"
        ];
      };
    };
    expected = "{\"element\":{\"elem\":[\"1.2.3.4\",\"5.6.7.8\"],\"family\":\"inet\",\"name\":\"blocklist\",\"table\":\"filter\"}}";
  };

  # ------------------------------------------------------------------
  # Element statements: nft lists each element's stateful statement as a
  # key beside `val` (json.c set_elem_expr_json), and its JSON parser
  # ignores both that and a `stmt` list on input (ADR 0010).
  # ------------------------------------------------------------------
  testReadBackElementStatements = {
    expr = builtins.isAttrs (readBack {
      set = {
        family = "ip";
        name = "s";
        table = "t";
        type = "ipv4_addr";
        handle = 3;
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
          {
            elem = {
              val = "10.0.0.2";
              quota = {
                val = 100;
                val_unit = "bytes";
                used = 40;
                used_unit = "bytes";
              };
            };
          }
          {
            elem = {
              val = "10.0.0.3";
              limit = {
                rate = 5;
                burst = 0;
                per = "second";
              };
            };
          }
          {
            elem = {
              val = "10.0.0.4";
              last.used = 1200;
            };
          }
        ];
        stmt = [ { counter = null; } ];
      };
    });
    expected = true;
  };

  # `nft -s` lists a counter and a last statement without state.
  testReadBackStatelessElementStatements = {
    expr = builtins.isAttrs (readBack {
      add.element = {
        family = "ip";
        name = "s";
        table = "t";
        elem = [
          {
            elem = {
              val = "10.0.0.1";
              counter = null;
              last = null;
            };
          }
        ];
      };
    });
    expected = true;
  };

  # The keys keep their statement bodies: a partial counter is refused
  # here as in a rule.
  testElementCounterRejectsPartialBody = {
    expr = readBack {
      add.element = {
        family = "ip";
        name = "s";
        table = "t";
        elem = [
          {
            elem.val = "10.0.0.1";
            elem.counter.packets = 1;
          }
        ];
      };
    };
    expectedError.msg = "elem\.counter.*is not of type";
  };

  # No listing emits a `stmt` list, and nft's JSON parser ignores it.
  testElementRejectsStmt = {
    expr = roundtrip nftlib.types.expression {
      elem = {
        val = "1.2.3.4";
        stmt = [ { counter = null; } ];
      };
    };
    expectedError.msg = "elem\.stmt' does not exist";
  };

  # ------------------------------------------------------------------
  # Reject with icmp code
  # ------------------------------------------------------------------
  testReject = {
    expr = roundtrip nftlib.types.statement {
      reject = {
        type = "icmp";
        expr = "host-unreachable";
      };
    };
    expected = ''{"reject":{"expr":"host-unreachable","type":"icmp"}}'';
  };

  # ------------------------------------------------------------------
  # Meter statement
  # ------------------------------------------------------------------
  testMeter = {
    expr = roundtrip nftlib.types.statement {
      meter = {
        name = "http_ratelimit";
        key = {
          meta = {
            key = "iifname";
          };
        };
        stmt = {
          limit = {
            rate = 100;
            per = "second";
          };
        };
      };
    };
    expected = "{\"meter\":{\"key\":{\"meta\":{\"key\":\"iifname\"}},\"name\":\"http_ratelimit\",\"stmt\":{\"limit\":{\"per\":\"second\",\"rate\":100}}}}";
  };

  # ------------------------------------------------------------------
  # List-of-singleton flag coercion: single flag written as a string
  # ------------------------------------------------------------------
  testSingletonFlag = {
    expr = roundtrip nftlib.types.statement {
      snat = {
        addr = "192.0.2.1";
        flags = "random";
      };
    };
    expected = ''{"snat":{"addr":"192.0.2.1","flags":"random"}}'';
  };

  # ------------------------------------------------------------------
  # Raw payload form (base+offset+len)
  # ------------------------------------------------------------------
  testRawPayload = {
    expr = roundtrip nftlib.types.expression {
      payload = {
        base = "nh";
        offset = 72;
        len = 16;
      };
    };
    expected = ''{"payload":{"base":"nh","len":16,"offset":72}}'';
  };

  # ------------------------------------------------------------------
  # Mixed raw+named payload keys must be rejected (spec: mutually exclusive)
  # ------------------------------------------------------------------
  testPayloadMixingRejected = {
    expr = roundtrip nftlib.types.expression {
      payload = {
        base = "nh";
        offset = 0;
        len = 16;
        protocol = "tcp";
        field = "dport";
      };
    };
    expectedError.msg = "validate\\.payload\\.field.*does not exist";
  };

  # ------------------------------------------------------------------
  # Incomplete raw payload (missing len) must be rejected
  # ------------------------------------------------------------------
  testRawPayloadIncompleteRejected = {
    expr = roundtrip nftlib.types.expression {
      payload = {
        base = "nh";
        offset = 0;
      };
    };
    expectedError.msg = "validate\\.payload. is not of type";
  };

  # ------------------------------------------------------------------
  # Incomplete named payload (missing field) must be rejected
  # ------------------------------------------------------------------
  testNamedPayloadIncompleteRejected = {
    expr = roundtrip nftlib.types.expression {
      payload = {
        protocol = "tcp";
      };
    };
    expectedError.msg = "validate\\.payload. is not of type";
  };

  # ------------------------------------------------------------------
  # `last` statement (bare null form)
  # ------------------------------------------------------------------
  testLastStmtNull = {
    expr = roundtrip nftlib.types.statement { last = null; };
    expected = ''{"last":null}'';
  };

  # ------------------------------------------------------------------
  # Counter stateless null form (emitted by `nft -j list --stateless`)
  # ------------------------------------------------------------------
  testCounterStatelessNull = {
    expr = roundtrip nftlib.types.statement { counter = null; };
    expected = ''{"counter":null}'';
  };

  # ------------------------------------------------------------------
  # `last` statement with timestamp
  # ------------------------------------------------------------------
  testLastStmtUsed = {
    expr = roundtrip nftlib.types.statement {
      last = {
        used = -1;
      };
    };
    expected = ''{"last":{"used":-1}}'';
  };

  # ------------------------------------------------------------------
  # `flow` offload statement
  # ------------------------------------------------------------------
  testFlowStmt = {
    expr = roundtrip nftlib.types.statement {
      flow = {
        op = "add";
        flowtable = "@ft";
      };
    };
    expected = ''{"flow":{"flowtable":"@ft","op":"add"}}'';
  };

  # ------------------------------------------------------------------
  # `tproxy` transparent proxy
  # ------------------------------------------------------------------
  testTproxyStmt = {
    expr = roundtrip nftlib.types.statement {
      tproxy = {
        family = "ip";
        addr = "127.0.0.1";
        port = 8080;
      };
    };
    expected = ''{"tproxy":{"addr":"127.0.0.1","family":"ip","port":8080}}'';
  };

  # ------------------------------------------------------------------
  # `synproxy` anonymous configuration
  # ------------------------------------------------------------------
  testSynproxyAnon = {
    expr = roundtrip nftlib.types.statement {
      synproxy = {
        mss = 1460;
        wscale = 7;
        flags = [
          "timestamp"
          "sack-perm"
        ];
      };
    };
    expected = "{\"synproxy\":{\"flags\":[\"timestamp\",\"sack-perm\"],\"mss\":1460,\"wscale\":7}}";
  };

  # A string is a name, never a module path: the anonymous body doesn't
  # claim a path-like reference and import it.
  testSynproxyPathLikeNameIsAName = {
    expr = roundtrip nftlib.types.statement { synproxy = "/sp1"; };
    expected = ''{"synproxy":"/sp1"}'';
  };

  testSynproxyObjectPathLikeNameIsAName = {
    expr = roundtrip nftlib.types.command {
      add.synproxy = {
        family = "inet";
        table = "t";
        name = "/sp1";
        mss = 1460;
        wscale = 7;
      };
    };
    expected = "{\"add\":{\"synproxy\":{\"family\":\"inet\",\"mss\":1460,\"name\":\"/sp1\",\"table\":\"t\",\"wscale\":7}}}";
  };

  # A body is an attrset of fields: a path-like string or a module function
  # in a body position is a schema error, not a module to import or call.
  testBodiesAreData = {
    expr = map (helpers.validates nftlib.types.statement) [
      { jump = "/c"; }
      { jump = _: { target = "c"; }; }
      {
        jump = {
          target = "c";
          _module.check = false;
          bogus = 1;
        };
      }
      { counter = "/c"; }
    ];
    expected = [
      false
      false
      false
      true
    ];
  };

  # ------------------------------------------------------------------
  # `synproxy` empty (all defaults)
  # ------------------------------------------------------------------
  testSynproxyNull = {
    expr = roundtrip nftlib.types.statement { synproxy = null; };
    expected = ''{"synproxy":null}'';
  };

  # ------------------------------------------------------------------
  # `reset` tcp option strip
  # ------------------------------------------------------------------
  testResetStmt = {
    expr = roundtrip nftlib.types.statement {
      reset = {
        "tcp option" = {
          name = "sack-perm";
        };
      };
    };
    expected = ''{"reset":{"tcp option":{"name":"sack-perm"}}}'';
  };

  # ------------------------------------------------------------------
  # `secmark` and `tunnel` statements (reference forms)
  # ------------------------------------------------------------------
  testSecmarkStmt = {
    expr = roundtrip nftlib.types.statement { secmark = "@my_secmark"; };
    expected = ''{"secmark":"@my_secmark"}'';
  };

  testTunnelStmt = {
    expr = roundtrip nftlib.types.statement { tunnel = "@my_tunnel"; };
    expected = ''{"tunnel":"@my_tunnel"}'';
  };

  # ------------------------------------------------------------------
  # `ipsec` (xfrm) expression
  # ------------------------------------------------------------------
  testIpsecExpr = {
    expr = roundtrip nftlib.types.expression {
      ipsec = {
        key = "saddr";
        family = "ip";
        dir = "in";
      };
    };
    expected = ''{"ipsec":{"dir":"in","family":"ip","key":"saddr"}}'';
  };

  # ------------------------------------------------------------------
  # `tunnel` expression (metadata key)
  # ------------------------------------------------------------------
  testTunnelExpr = {
    expr = roundtrip nftlib.types.expression {
      tunnel = {
        key = "id";
      };
    };
    expected = ''{"tunnel":{"key":"id"}}'';
  };

  # ------------------------------------------------------------------
  # `secmark` named object
  # ------------------------------------------------------------------
  testSecmarkObject = {
    expr = roundtrip nftlib.types.objects.secmark {
      secmark = {
        family = "inet";
        table = "filter";
        name = "sec_http";
        context = "system_u:object_r:http_packet_t:s0";
      };
    };
    expected = "{\"secmark\":{\"context\":\"system_u:object_r:http_packet_t:s0\",\"family\":\"inet\",\"name\":\"sec_http\",\"table\":\"filter\"}}";
  };

  # ------------------------------------------------------------------
  # `synproxy` named object
  # ------------------------------------------------------------------
  testSynproxyObject = {
    expr = roundtrip nftlib.types.objects.synproxy {
      synproxy = {
        family = "inet";
        table = "filter";
        name = "sp1";
        mss = 1460;
        wscale = 7;
        flags = [ "timestamp" ];
      };
    };
    expected = "{\"synproxy\":{\"family\":\"inet\",\"flags\":[\"timestamp\"],\"mss\":1460,\"name\":\"sp1\",\"table\":\"filter\",\"wscale\":7}}";
  };

  # ------------------------------------------------------------------
  # `ct count` named object (nftables 1.1.7+)
  # ------------------------------------------------------------------
  testCtCountObject = {
    expr = roundtrip nftlib.types.objects.ctCount {
      "ct count" = {
        family = "ip";
        table = "t";
        name = "c1";
        val = 5;
        inv = true;
        comment = "over five";
      };
    };
    expected = "{\"ct count\":{\"comment\":\"over five\",\"family\":\"ip\",\"inv\":true,\"name\":\"c1\",\"table\":\"t\",\"val\":5}}";
  };

  testCtCountObjectRequiresVal = {
    expr = roundtrip nftlib.types.objects.ctCount {
      "ct count" = {
        family = "ip";
        table = "t";
        name = "c1";
      };
    };
    expectedError.msg = "val.*was accessed but has no value defined";
  };

  # ------------------------------------------------------------------
  # Stateful statements reference a named object by name or by a map
  # expression that selects the name (objref).
  # ------------------------------------------------------------------
  testCtCountNamedReference = {
    expr = roundtrip nftlib.types.statement { "ct count" = "c1"; };
    expected = ''{"ct count":"c1"}'';
  };

  testStatefulMapReferences = {
    expr = map (tag: roundtrip nftlib.types.statement { ${tag} = portMapReference; }) [
      "counter"
      "quota"
      "limit"
      "ct count"
      "synproxy"
    ];
    expected = map (tag: ''{"${tag}":${portMapReferenceJson}}'') [
      "counter"
      "quota"
      "limit"
      "ct count"
      "synproxy"
    ];
  };

  # A reference is only a name or a map: other expressions stay rejected
  # where the statement has no inline form that accepts them.
  testCtCountRejectsNonMapExpression = {
    expr = roundtrip nftlib.types.statement {
      "ct count".payload = {
        protocol = "tcp";
        field = "dport";
      };
    };
    expectedError.msg = "validate\\.\"ct count\"\\.payload.*does not exist";
  };

  # ------------------------------------------------------------------
  # NAT flag: netmap (added alongside random/fully-random/persistent)
  # ------------------------------------------------------------------
  testNetmapNatFlag = {
    expr = roundtrip nftlib.types.statement {
      dnat = {
        addr = "10.0.0.0/24";
        flags = [ "netmap" ];
      };
    };
    expected = ''{"dnat":{"addr":"10.0.0.0/24","flags":["netmap"]}}'';
  };

  # ------------------------------------------------------------------
  # `destroy` command (like delete but idempotent)
  # ------------------------------------------------------------------
  testDestroyCommand = {
    expr = roundtrip nftlib.types.command {
      destroy = {
        table = {
          family = "ip";
          name = "old";
        };
      };
    };
    expected = ''{"destroy":{"table":{"family":"ip","name":"old"}}}'';
  };

  # ------------------------------------------------------------------
  # Tunnel object: VXLAN encapsulation
  # ------------------------------------------------------------------
  testTunnelVxlan = {
    expr = roundtrip nftlib.types.objects.tunnel {
      tunnel = {
        family = "inet";
        table = "t";
        name = "v";
        id = 42;
        "src-ipv4" = "10.0.0.1";
        "dst-ipv4" = "10.0.0.2";
        type = "vxlan";
        tunnel = {
          gbp = 100;
        };
      };
    };
    expected = "{\"tunnel\":{\"dst-ipv4\":\"10.0.0.2\",\"family\":\"inet\",\"id\":42,\"name\":\"v\",\"src-ipv4\":\"10.0.0.1\",\"table\":\"t\",\"tunnel\":{\"gbp\":100},\"type\":\"vxlan\"}}";
  };

  # ------------------------------------------------------------------
  # Tunnel object: ERSPAN v1
  # ------------------------------------------------------------------
  testTunnelErspanV1 = {
    expr = roundtrip nftlib.types.objects.tunnel {
      tunnel = {
        family = "inet";
        table = "t";
        name = "e1";
        type = "erspan";
        tunnel = {
          version = 1;
          index = 7;
        };
      };
    };
    expected = "{\"tunnel\":{\"family\":\"inet\",\"name\":\"e1\",\"table\":\"t\",\"tunnel\":{\"index\":7,\"version\":1},\"type\":\"erspan\"}}";
  };

  # ------------------------------------------------------------------
  # Tunnel object: ERSPAN v2
  # ------------------------------------------------------------------
  testTunnelErspanV2 = {
    expr = roundtrip nftlib.types.objects.tunnel {
      tunnel = {
        family = "inet";
        table = "t";
        name = "e2";
        type = "erspan";
        tunnel = {
          version = 2;
          dir = "ingress";
          hwid = 3;
        };
      };
    };
    expected = "{\"tunnel\":{\"family\":\"inet\",\"name\":\"e2\",\"table\":\"t\",\"tunnel\":{\"dir\":\"ingress\",\"hwid\":3,\"version\":2},\"type\":\"erspan\"}}";
  };

  # ------------------------------------------------------------------
  # Tunnel object: GENEVE (list of options)
  # ------------------------------------------------------------------
  testTunnelGeneve = {
    expr = roundtrip nftlib.types.objects.tunnel {
      tunnel = {
        family = "inet";
        table = "t";
        name = "g";
        type = "geneve";
        tunnel = [
          {
            class = 258;
            "opt-type" = 128;
            data = "deadbeef";
          }
        ];
      };
    };
    expected = "{\"tunnel\":{\"family\":\"inet\",\"name\":\"g\",\"table\":\"t\",\"tunnel\":[{\"class\":258,\"data\":\"deadbeef\",\"opt-type\":128}],\"type\":\"geneve\"}}";
  };

  # ------------------------------------------------------------------
  # Audit-pass additions: fields confirmed in parser_json.c
  # ------------------------------------------------------------------

  # limit.per is required in inline form (parser_json.c:2084)
  testLimitPerRejectedWithoutPer = {
    expr = roundtrip nftlib.types.statement {
      limit = {
        rate = 100;
      };
    };
    expectedError.msg = "validate\\.limit\\.per.*was accessed but has no value defined";
  };

  # queue without num is valid
  testQueueNoNum = {
    expr = roundtrip nftlib.types.statement {
      queue = {
        flags = [ "bypass" ];
      };
    };
    expected = ''{"queue":{"flags":["bypass"]}}'';
  };

  # meter.size (parser_json.c:2793)
  testMeterSize = {
    expr = roundtrip nftlib.types.statement {
      meter = {
        name = "m";
        key = {
          meta = {
            key = "iifname";
          };
        };
        stmt = {
          counter = {
            packets = 0;
            bytes = 0;
          };
        };
        size = 4096;
      };
    };
    expected = "{\"meter\":{\"key\":{\"meta\":{\"key\":\"iifname\"}},\"name\":\"m\",\"size\":4096,\"stmt\":{\"counter\":{\"bytes\":0,\"packets\":0}}}}";
  };

  # nat.type_flags (parser_json.c:2353)
  testNatTypeFlags = {
    expr = roundtrip nftlib.types.statement {
      dnat = {
        addr = "10.0.0.0/24";
        type_flags = [
          "interval"
          "prefix"
        ];
      };
    };
    expected = "{\"dnat\":{\"addr\":\"10.0.0.0/24\",\"type_flags\":[\"interval\",\"prefix\"]}}";
  };

  # ip option expression (parser_json.c:822)
  testIpOptionExpr = {
    expr = roundtrip nftlib.types.expression {
      "ip option" = {
        name = "lsrr";
        field = "length";
      };
    };
    expected = ''{"ip option":{"field":"length","name":"lsrr"}}'';
  };

  # tcp option raw form (parser_json.c:745)
  testTcpOptionRaw = {
    expr = roundtrip nftlib.types.expression {
      "tcp option" = {
        base = 2;
        offset = 16;
        len = 16;
      };
    };
    expected = ''{"tcp option":{"base":2,"len":16,"offset":16}}'';
  };

  # payload tunnel form (parser_json.c:686)
  testPayloadTunnelForm = {
    expr = roundtrip nftlib.types.expression {
      payload = {
        tunnel = "vxlan";
        protocol = "ip";
        field = "daddr";
      };
    };
    expected = "{\"payload\":{\"field\":\"daddr\",\"protocol\":\"ip\",\"tunnel\":\"vxlan\"}}";
  };

  # payload base "ih" (inner header)
  testPayloadInnerHeader = {
    expr = roundtrip nftlib.types.expression {
      payload = {
        base = "ih";
        offset = 0;
        len = 8;
      };
    };
    expected = ''{"payload":{"base":"ih","len":8,"offset":0}}'';
  };

  # Chain dev accepts string list (parser_json.c:3143 via json_parse_devs)
  testChainDevList = {
    expr = roundtrip nftlib.types.objects.chain {
      chain = {
        family = "netdev";
        table = "filter";
        name = "ingress";
        type = "filter";
        hook = "ingress";
        prio = -500;
        dev = [
          "eth0"
          "eth1"
        ];
      };
    };
    expected = "{\"chain\":{\"dev\":[\"eth0\",\"eth1\"],\"family\":\"netdev\",\"hook\":\"ingress\",\"name\":\"ingress\",\"prio\":-500,\"table\":\"filter\",\"type\":\"filter\"}}";
  };

  # secmark object: context is optional (parser_json.c:3769)
  testSecmarkObjectNoContext = {
    expr = roundtrip nftlib.types.objects.secmark {
      secmark = {
        family = "inet";
        table = "t";
        name = "x";
      };
    };
    expected = ''{"secmark":{"family":"inet","name":"x","table":"t"}}'';
  };

  # ct helper object: protocol/type optional (parser_json.c:3782-3809)
  testCtHelperObjectMinimal = {
    expr = roundtrip nftlib.types.objects.ctHelper {
      "ct helper" = {
        family = "inet";
        table = "t";
        name = "h";
      };
    };
    expected = ''{"ct helper":{"family":"inet","name":"h","table":"t"}}'';
  };

  # ------------------------------------------------------------------
  # Mixing VXLAN keys into an ERSPAN tunnel nested object must be rejected
  # ------------------------------------------------------------------
  testTunnelNestedDisjoint = {
    expr = roundtrip nftlib.types.objects.tunnel {
      tunnel = {
        family = "inet";
        table = "t";
        name = "bad";
        type = "vxlan";
        tunnel = {
          version = 1;
          gbp = 10;
        };
      };
    };
    expectedError.msg = "validate\\.tunnel\\.tunnel\\.gbp.*does not exist";
  };

  # ------------------------------------------------------------------
  # Socket keys: mark and wildcard (added in audit pass)
  # ------------------------------------------------------------------
  testSocketMark = {
    expr = roundtrip nftlib.types.expression {
      socket = {
        key = "mark";
      };
    };
    expected = ''{"socket":{"key":"mark"}}'';
  };

  testSocketWildcard = {
    expr = roundtrip nftlib.types.expression {
      socket = {
        key = "wildcard";
      };
    };
    expected = ''{"socket":{"key":"wildcard"}}'';
  };

  # ------------------------------------------------------------------
  # Meta keys added from meta_templates audit
  # ------------------------------------------------------------------
  testMetaIpsecKey = {
    expr = roundtrip nftlib.types.expression {
      meta = {
        key = "ipsec";
      };
    };
    expected = ''{"meta":{"key":"ipsec"}}'';
  };

  testMetaTimeKey = {
    expr = roundtrip nftlib.types.expression {
      meta = {
        key = "time";
      };
    };
    expected = ''{"meta":{"key":"time"}}'';
  };

  testMetaSdifKey = {
    expr = roundtrip nftlib.types.expression {
      meta = {
        key = "sdif";
      };
    };
    expected = ''{"meta":{"key":"sdif"}}'';
  };

  # ------------------------------------------------------------------
  # ct timeout object: nested `policy` mapping state → seconds
  # ------------------------------------------------------------------
  testCtTimeoutObject = {
    expr = roundtrip nftlib.types.objects.ctTimeout {
      "ct timeout" = {
        family = "ip";
        table = "filter";
        name = "fast_tcp";
        protocol = "tcp";
        l3proto = "ip";
        policy = {
          established = 300;
          syn_sent = 30;
          close = 5;
        };
      };
    };
    expected = "{\"ct timeout\":{\"family\":\"ip\",\"l3proto\":\"ip\",\"name\":\"fast_tcp\",\"policy\":{\"close\":5,\"established\":300,\"syn_sent\":30},\"protocol\":\"tcp\",\"table\":\"filter\"}}";
  };

  # ------------------------------------------------------------------
  # set statement: delete op plus stmt attachment
  # ------------------------------------------------------------------
  testSetStmtDeleteWithStmt = {
    expr = roundtrip nftlib.types.statement {
      set = {
        op = "delete";
        elem = "10.0.0.1";
        set = "@blocked";
        stmt = [
          {
            counter = {
              packets = 0;
              bytes = 0;
            };
          }
        ];
      };
    };
    expected = "{\"set\":{\"elem\":\"10.0.0.1\",\"op\":\"delete\",\"set\":\"@blocked\",\"stmt\":[{\"counter\":{\"bytes\":0,\"packets\":0}}]}}";
  };

  # ------------------------------------------------------------------
  # map statement (distinct from vmap)
  # ------------------------------------------------------------------
  testMapStatement = {
    expr = roundtrip nftlib.types.statement {
      map = {
        op = "update";
        elem = "10.0.0.1";
        data = 42;
        map = "@cache";
      };
    };
    expected = "{\"map\":{\"data\":42,\"elem\":\"10.0.0.1\",\"map\":\"@cache\",\"op\":\"update\"}}";
  };

  # nft's JSON parser rejects a set, map or flow statement reference
  # without its `@` ("Illegal set reference").
  testStatementReferencesNeedAt = {
    expr = map (helpers.validates nftlib.types.statement) [
      {
        set = {
          op = "add";
          elem = "10.0.0.1";
          set = "blocked";
        };
      }
      {
        map = {
          op = "update";
          elem = "10.0.0.1";
          data = 42;
          map = "cache";
        };
      }
      {
        flow = {
          op = "add";
          flowtable = "ft";
        };
      }
      {
        set = {
          op = "add";
          elem = "10.0.0.1";
          set = "@";
        };
      }
    ];
    expected = [
      false
      false
      false
      false
    ];
  };

  # ------------------------------------------------------------------
  # table with comment
  # ------------------------------------------------------------------
  testTableComment = {
    expr = roundtrip nftlib.types.objects.table {
      table = {
        family = "inet";
        name = "filter";
        comment = "main firewall";
      };
    };
    expected = "{\"table\":{\"comment\":\"main firewall\",\"family\":\"inet\",\"name\":\"filter\"}}";
  };

  # ------------------------------------------------------------------
  # chain with comment
  # ------------------------------------------------------------------
  testChainComment = {
    expr = roundtrip nftlib.types.objects.chain {
      chain = {
        family = "inet";
        table = "filter";
        name = "input";
        comment = "accept established";
      };
    };
    expected = "{\"chain\":{\"comment\":\"accept established\",\"family\":\"inet\",\"name\":\"input\",\"table\":\"filter\"}}";
  };

  # ------------------------------------------------------------------
  # Comment on a named object (counter)
  # ------------------------------------------------------------------
  testObjectComment = {
    expr = roundtrip nftlib.types.objects.counter {
      counter = {
        family = "ip";
        table = "filter";
        name = "pkts";
        comment = "HTTP hits";
      };
    };
    expected = "{\"counter\":{\"comment\":\"HTTP hits\",\"family\":\"ip\",\"name\":\"pkts\",\"table\":\"filter\"}}";
  };

  # ------------------------------------------------------------------
  # `_type` tag stripping — libraries built on top of nftypes (e.g.
  # nix-nftzones, matching nix-libnet's convention) tag values with
  # `_type = "<lib>.<kind>"` for boundary checks. clean drops the tag
  # so rendered output stays accepted by `nft -j -f` (which rejects
  # unknown top-level keys).
  # ------------------------------------------------------------------
  testCleanStripsTypeRuleset = {
    expr = toJson {
      _type = "x.y";
      nftables = [ ];
    };
    expected = ''{"nftables":[]}'';
  };

  testCleanStripsTypeArbitraryAttrset = {
    expr = toJson {
      _type = "x.y";
      foo = 1;
    };
    expected = ''{"foo":1}'';
  };

  # A marker doesn't hide the null sentinel: a marked verdict stays a
  # verdict instead of becoming `{}`.
  testCleanKeepsMarkedVerdict = {
    expr = nftlib.cleanValue {
      accept = null;
      _type = "x.y";
    };
    expected = {
      accept = null;
    };
  };

  testCleanKeepsMarkedVerdictInRule = {
    expr = toJson {
      expr = [
        {
          drop = null;
          _type = "x.y";
        }
      ];
    };
    expected = ''{"expr":[{"drop":null}]}'';
  };

  # ------------------------------------------------------------------
  # resolvePriority — int passthrough
  # ------------------------------------------------------------------
  testResolvePriorityIntPassthroughIp = {
    expr = nftlib.resolvePriority "ip" 42;
    expected = 42;
  };

  testResolvePriorityIntPassthroughBridge = {
    expr = nftlib.resolvePriority "bridge" (-100);
    expected = -100;
  };

  # ------------------------------------------------------------------
  # resolvePriority — default table (ip / ip6 / inet / arp / netdev)
  # ------------------------------------------------------------------
  testResolvePriorityIpFilter = {
    expr = nftlib.resolvePriority "ip" "filter";
    expected = 0;
  };

  testResolvePriorityIp6Raw = {
    expr = nftlib.resolvePriority "ip6" "raw";
    expected = -300;
  };

  testResolvePriorityInetSrcnat = {
    expr = nftlib.resolvePriority "inet" "srcnat";
    expected = 100;
  };

  testResolvePriorityNetdevMangle = {
    expr = nftlib.resolvePriority "netdev" "mangle";
    expected = -150;
  };

  # ------------------------------------------------------------------
  # resolvePriority — bridge table (overrides default values)
  # ------------------------------------------------------------------
  testResolvePriorityBridgeFilter = {
    expr = nftlib.resolvePriority "bridge" "filter";
    expected = -200;
  };

  testResolvePriorityBridgeOut = {
    expr = nftlib.resolvePriority "bridge" "out";
    expected = 100;
  };

  testResolvePriorityBridgeDstnat = {
    expr = nftlib.resolvePriority "bridge" "dstnat";
    expected = -300;
  };

  # ------------------------------------------------------------------
  # resolvePriority — unknown family throws
  # ------------------------------------------------------------------
  testResolvePriorityUnknownFamilyThrows = {
    expr = nftlib.resolvePriority "wat" "filter";
    expectedError.msg = "nix-nftypes: resolvePriority: unknown family 'wat'";
  };

  # ------------------------------------------------------------------
  # resolvePriority — unknown symbol throws (default table)
  # ------------------------------------------------------------------
  testResolvePriorityUnknownSymbolThrowsDefault = {
    expr = nftlib.resolvePriority "ip" "out";
    expectedError.msg = "nix-nftypes: resolvePriority: unknown priority symbol 'out' for family 'ip'";
  };

  # ------------------------------------------------------------------
  # resolvePriority — symbol valid in the default table is rejected for
  # bridge if it isn't in the bridge table (`raw`/`mangle`/`security`
  # are default-only).
  # ------------------------------------------------------------------
  testResolvePriorityUnknownSymbolThrowsBridge = {
    expr = nftlib.resolvePriority "bridge" "raw";
    expectedError.msg = "unknown priority symbol 'raw' for family 'bridge'";
  };

  # Every symbol of every family resolves to its value in `man nft`
  # Table 6 (bridge: Table 7).
  testResolvePriorityEverySymbol =
    let
      defaultTable = {
        raw = -300;
        mangle = -150;
        dstnat = -100;
        filter = 0;
        security = 50;
        srcnat = 100;
      };
      tables = {
        arp = defaultTable;
        bridge = {
          dstnat = -300;
          filter = -200;
          out = 100;
          srcnat = 300;
        };
        inet = defaultTable;
        ip = defaultTable;
        ip6 = defaultTable;
        netdev = defaultTable;
      };
    in
    {
      expr = lib.mapAttrs (family: lib.mapAttrs (symbol: _: nftlib.resolvePriority family symbol)) tables;
      expected = tables;
    };

  # ------------------------------------------------------------------
  # compatibility matrix spot-checks
  # ------------------------------------------------------------------
  testCompatHooksNetdev = {
    expr = nftlib.compatibility.hooksByFamily.netdev;
    expected = [
      "ingress"
      "egress"
    ];
  };

  testCompatHooksArp = {
    expr = nftlib.compatibility.hooksByFamily.arp;
    expected = [
      "input"
      "output"
    ];
  };

  # `inet` supports `ingress` (with devices = {…}) since kernel 5.10
  # — see `str2hooknum` in nftables `src/evaluate.c`.
  testCompatHooksInetIncludesIngress = {
    expr = builtins.elem "ingress" nftlib.compatibility.hooksByFamily.inet;
    expected = true;
  };

  testCompatNatExcludesBridge = {
    expr = builtins.elem "bridge" nftlib.compatibility.familiesByChainType.nat;
    expected = false;
  };

  testCompatNatExcludesNetdev = {
    expr = builtins.elem "netdev" nftlib.compatibility.familiesByChainType.nat;
    expected = false;
  };

  testCompatNatExcludesArp = {
    expr = builtins.elem "arp" nftlib.compatibility.familiesByChainType.nat;
    expected = false;
  };

  testCompatRouteFamilies = {
    expr = nftlib.compatibility.familiesByChainType.route;
    expected = [
      "ip"
      "ip6"
      "inet"
    ];
  };

  testCompatHooksWithOifname = {
    expr = nftlib.compatibility.hooksWithOifname;
    expected = [
      "forward"
      "output"
      "postrouting"
    ];
  };

  testCompatPriorityDefaultFilter = {
    expr = nftlib.compatibility.priorityIntsByFamily.ip.filter;
    expected = 0;
  };

  testCompatPriorityBridgeFilter = {
    expr = nftlib.compatibility.priorityIntsByFamily.bridge.filter;
    expected = -200;
  };

  # ------------------------------------------------------------------
  # hooksByChainType — `null` is the "any hook the family exposes"
  # sentinel for `filter`; `nat` and `route` carry explicit lists.
  # ------------------------------------------------------------------
  testCompatHooksByChainTypeFilterSentinel = {
    expr = nftlib.compatibility.hooksByChainType.filter;
    expected = null;
  };

  testCompatHooksByChainTypeNat = {
    expr = nftlib.compatibility.hooksByChainType.nat;
    expected = [
      "prerouting"
      "input"
      "output"
      "postrouting"
    ];
  };

  testCompatHooksByChainTypeRoute = {
    expr = nftlib.compatibility.hooksByChainType.route;
    expected = [ "output" ];
  };

  # ------------------------------------------------------------------
  # validChainPlacement — (family, chainType, hook) → bool. Cases
  # mirror the kernel-probed matrix on Linux 6.8 / nftables 1.0.9.
  # ------------------------------------------------------------------
  testValidChainPlacementIpFilterPrerouting = {
    expr = nftlib.validChainPlacement "ip" "filter" "prerouting";
    expected = true;
  };

  testValidChainPlacementIpNatPrerouting = {
    expr = nftlib.validChainPlacement "ip" "nat" "prerouting";
    expected = true;
  };

  testValidChainPlacementIpNatForward = {
    expr = nftlib.validChainPlacement "ip" "nat" "forward";
    expected = false;
  };

  testValidChainPlacementIpRouteOutput = {
    expr = nftlib.validChainPlacement "ip" "route" "output";
    expected = true;
  };

  testValidChainPlacementIpRoutePrerouting = {
    expr = nftlib.validChainPlacement "ip" "route" "prerouting";
    expected = false;
  };

  # Verified on real kernel 6.8 / nftables 1.0.9: `inet route hook
  # output` is accepted (the kernel dispatches inet route via the
  # per-protocol implementations).
  testValidChainPlacementInetRouteOutput = {
    expr = nftlib.validChainPlacement "inet" "route" "output";
    expected = true;
  };

  testValidChainPlacementNetdevFilterIngress = {
    expr = nftlib.validChainPlacement "netdev" "filter" "ingress";
    expected = true;
  };

  testValidChainPlacementNetdevNatIngress = {
    expr = nftlib.validChainPlacement "netdev" "nat" "ingress";
    expected = false;
  };

  testValidChainPlacementArpFilterInput = {
    expr = nftlib.validChainPlacement "arp" "filter" "input";
    expected = true;
  };

  testValidChainPlacementArpFilterForward = {
    expr = nftlib.validChainPlacement "arp" "filter" "forward";
    expected = false;
  };

  # Unknown family / chainType / hook strings fall through to false
  # rather than throw — consumers can probe freely without try/catch.
  testValidChainPlacementUnknownFamily = {
    expr = nftlib.validChainPlacement "wat" "filter" "input";
    expected = false;
  };

  testValidChainPlacementUnknownChainType = {
    expr = nftlib.validChainPlacement "ip" "wat" "input";
    expected = false;
  };

  # ------------------------------------------------------------------
  # priorityIntsByFamily — one symbol→int table per family, indexed
  # like hooksByFamily. The same tables back resolvePriority,
  # priorityNameOf, and chainTypeFor.
  # ------------------------------------------------------------------
  testPriorityIntsByFamilyCoversEveryFamily = {
    expr = builtins.attrNames nftlib.compatibility.priorityIntsByFamily;
    expected = [
      "arp"
      "bridge"
      "inet"
      "ip"
      "ip6"
      "netdev"
    ];
  };

  testPriorityIntsByFamilyInet = {
    expr = nftlib.compatibility.priorityIntsByFamily.inet;
    expected = {
      raw = -300;
      mangle = -150;
      dstnat = -100;
      filter = 0;
      security = 50;
      srcnat = 100;
    };
  };

  testPriorityIntsByFamilyBridge = {
    expr = nftlib.compatibility.priorityIntsByFamily.bridge;
    expected = {
      dstnat = -300;
      filter = -200;
      out = 100;
      srcnat = 300;
    };
  };

  # ------------------------------------------------------------------
  # priorityNameOf — int → symbol reverse of resolvePriority.
  # ------------------------------------------------------------------
  testPriorityNameOfIpZero = {
    expr = nftlib.priorityNameOf "ip" 0;
    expected = "filter";
  };

  testPriorityNameOfIpFilterPassthrough = {
    expr = nftlib.priorityNameOf "ip" "filter";
    expected = "filter";
  };

  testPriorityNameOfIpSrcnat = {
    expr = nftlib.priorityNameOf "ip" 100;
    expected = "srcnat";
  };

  testPriorityNameOfIpUnknownInt = {
    expr = nftlib.priorityNameOf "ip" 17;
    expected = 17;
  };

  # Bridge-specific: -200 is bridge filter (not 0).
  testPriorityNameOfBridgeFilter = {
    expr = nftlib.priorityNameOf "bridge" (-200);
    expected = "filter";
  };

  testPriorityNameOfBridgeSrcnat = {
    expr = nftlib.priorityNameOf "bridge" 300;
    expected = "srcnat";
  };

  # 0 is `filter` for ip but unknown for bridge — no canonicalization.
  testPriorityNameOfBridgeZero = {
    expr = nftlib.priorityNameOf "bridge" 0;
    expected = 0;
  };

  testPriorityNameOfUnknownFamilyThrows = {
    expr = nftlib.priorityNameOf "nope" 0;
    expectedError.msg = "nix-nftypes: priorityNameOf: unknown family 'nope'";
  };

  # ------------------------------------------------------------------
  # chainTypeFor — derive chain type from (family, hook, priority).
  # ------------------------------------------------------------------
  testChainTypeForIpInputFilter = {
    expr = nftlib.chainTypeFor "ip" "input" "filter";
    expected = "filter";
  };

  testChainTypeForIpInputZero = {
    expr = nftlib.chainTypeFor "ip" "input" 0;
    expected = "filter";
  };

  testChainTypeForIpPostroutingSrcnat = {
    expr = nftlib.chainTypeFor "ip" "postrouting" "srcnat";
    expected = "nat";
  };

  testChainTypeForIpPreroutingDstnat = {
    expr = nftlib.chainTypeFor "ip" "prerouting" "dstnat";
    expected = "nat";
  };

  testChainTypeForIpOutputMangle = {
    expr = nftlib.chainTypeFor "ip" "output" "mangle";
    expected = "route";
  };

  testChainTypeForIpPreroutingMangle = {
    expr = nftlib.chainTypeFor "ip" "prerouting" "mangle";
    expected = "filter";
  };

  # The bridge family has no nat chain type, so bridge srcnat (300, not
  # 100) is a filter chain in both symbol and int form.
  testChainTypeForBridgePostroutingSrcnatSymbol = {
    expr = nftlib.chainTypeFor "bridge" "postrouting" "srcnat";
    expected = "filter";
  };

  testChainTypeForBridgePostroutingSrcnatInt = {
    expr = nftlib.chainTypeFor "bridge" "postrouting" 300;
    expected = "filter";
  };

  # nat doesn't attach at forward.
  testChainTypeForIpForwardDstnat = {
    expr = nftlib.chainTypeFor "ip" "forward" "dstnat";
    expected = "filter";
  };

  # arp has neither nat nor route chains.
  testChainTypeForArpOutputMangle = {
    expr = nftlib.chainTypeFor "arp" "output" "mangle";
    expected = "filter";
  };

  testChainTypeForNetdevIngressSrcnatInt = {
    expr = nftlib.chainTypeFor "netdev" "ingress" 100;
    expected = "filter";
  };

  /*
    Every hook each family exposes, at every priority symbol of the
    family and every int either priority table names (plus two no table
    names), lists the placements whose type `validChainPlacement`
    rejects. A hook the family lacks has no valid type at all.
  */
  testChainTypeForPassesValidChainPlacement =
    let
      inherit (nftlib.compatibility) hooksByFamily priorityIntsByFamily;
      tableInts = lib.concatMap lib.attrValues (lib.attrValues priorityIntsByFamily);
      priorities =
        family:
        lib.attrNames priorityIntsByFamily.${family}
        ++ lib.unique tableInts
        ++ [
          (-1)
          1000
        ];
      placements = lib.concatMap (
        family:
        lib.concatMap (
          hook:
          map (prio: {
            inherit family hook prio;
            type = nftlib.chainTypeFor family hook prio;
          }) (priorities family)
        ) hooksByFamily.${family}
      ) (lib.attrNames hooksByFamily);
    in
    {
      expr = {
        count = builtins.length placements;
        rejected = builtins.filter (p: !(nftlib.validChainPlacement p.family p.type p.hook)) placements;
      };
      # 5 + 5 + 6 + 2 + 2 hooks at 6 symbols + 10 ints, and 5 bridge hooks
      # at 4 symbols + 10 ints.
      expected = {
        count = 20 * 16 + 5 * 14;
        rejected = [ ];
      };
    };

  testChainTypeForBridgeInputFilter = {
    expr = nftlib.chainTypeFor "bridge" "input" "filter";
    expected = "filter";
  };

  testChainTypeForBridgeInputFilterInt = {
    expr = nftlib.chainTypeFor "bridge" "input" (-200);
    expected = "filter";
  };

  # Bridge `out` is bridge-specific and not a NAT/route signal.
  testChainTypeForBridgeOutputOut = {
    expr = nftlib.chainTypeFor "bridge" "output" "out";
    expected = "filter";
  };

  # Symbol unknown to the family returns null (not "filter") — the
  # placement is uninterpretable, distinct from a known-filter case.
  testChainTypeForUnknownSymbol = {
    expr = nftlib.chainTypeFor "ip" "input" "wat";
    expected = null;
  };

  testChainTypeForUnknownFamilyThrows = {
    expr = nftlib.chainTypeFor "nope" "input" "filter";
    expectedError.msg = "nix-nftypes: chainTypeFor: unknown family 'nope'";
  };

  # Read-back validation: the source-side checks validate each listed
  # command as a singleton ruleset. Bare listed objects with handles are
  # accepted; junk in read-back position is not.
  testRulesetAcceptsBareListing = {
    expr = builtins.isAttrs (readBack {
      table = {
        family = "inet";
        name = "t";
        handle = 1;
      };
    });
    expected = true;
  };

  testRulesetRejectsUnknownTopTag = {
    expr = readBack { gizmo = { }; };
    expectedError.msg = "validate\\.nftables\\..*is not of type";
  };

  testRulesetRejectsUnknownField = {
    expr = readBack {
      table = {
        family = "inet";
        name = "t";
        frobnicate = 1;
      };
    };
    expectedError.msg = "table\\.frobnicate.*does not exist";
  };

  testRulesetRejectsUnknownStatement = {
    expr = readBack {
      rule = {
        family = "inet";
        table = "t";
        chain = "c";
        handle = 2;
        expr = [ { not_a_stmt = { }; } ];
      };
    };
    expectedError.msg = "rule\\.expr\\..*is not of type";
  };

  # nft 1.1.6 lists an inet ct helper, timeout and expectation with
  # `l3proto: "inet"` (the table family, when none was given), and also
  # accepts it on input.
  testReadBackInetCtHelper = {
    expr = builtins.isAttrs (readBack {
      "ct helper" = {
        family = "inet";
        name = "h";
        table = "t";
        handle = 1;
        type = "ftp";
        protocol = "tcp";
        l3proto = "inet";
      };
    });
    expected = true;
  };

  testReadBackInetCtTimeout = {
    expr = builtins.isAttrs (readBack {
      "ct timeout" = {
        family = "inet";
        name = "to";
        table = "t";
        handle = 4;
        protocol = "tcp";
        l3proto = "inet";
        policy.established = 300;
      };
    });
    expected = true;
  };

  testReadBackInetCtExpectation = {
    expr = builtins.isAttrs (readBack {
      "ct expectation" = {
        family = "inet";
        name = "e";
        table = "t";
        handle = 1;
        protocol = "tcp";
        dport = 21;
        timeout = 1000;
        size = 1;
        l3proto = "inet";
      };
    });
    expected = true;
  };

  # inet is the only family added: nft's parser takes any family name,
  # but no listing emits the others.
  testCtL3protoRejectsBridge = {
    expr = readBack {
      "ct helper" = {
        family = "inet";
        name = "h";
        table = "t";
        l3proto = "bridge";
      };
    };
    expectedError.msg = "ct helper.\\.l3proto.*is not of type";
  };

  testReadBackCommentedSet = {
    expr = builtins.isAttrs (readBack {
      set = {
        family = "inet";
        name = "s";
        table = "t";
        type = "ipv4_addr";
        handle = 6;
        comment = "a set";
      };
    });
    expected = true;
  };

  testReadBackCommentedMap = {
    expr = builtins.isAttrs (readBack {
      map = {
        family = "inet";
        name = "m";
        table = "t";
        type = "ipv4_addr";
        handle = 7;
        comment = "a map";
        map = "verdict";
      };
    });
    expected = true;
  };

  # A set or map comment is a quoted string like every other comment.
  testSetCommentRejectsQuote = {
    expr = readBack {
      set = {
        family = "inet";
        name = "s";
        table = "t";
        type = "ipv4_addr";
        comment = "a \"set\"";
      };
    };
    expectedError.msg = "set\\.comment.*is not of type";
  };

  # A wrong value in an expression field is a type error naming the
  # field. The recursive `expression` type's description used to recurse
  # without end, so the error was "infinite recursion encountered".
  testWrongExpressionIsATypeError = {
    expr = builtins.deepSeq (helpers.validate nftlib.types.statement {
      match = {
        op = "==";
        left = 1.5;
        right = 1;
      };
    }) true;
    expectedError = {
      type = "ThrownError";
      msg = "validate\\.match\\.left' is not of type `nft expression";
    };
  };

  /*
    In one batch, nft (1.1.6 and 1.1.7, JSON and text) runs a reset of a
    counter, quota, set, map, or rule only when it is the batch's last
    command: followed by any other command, it resets nothing and nft
    exits 0. A reset of an element runs anywhere.
  */
  testResetOnlyAsLastCommand =
    let
      scope = {
        family = "ip";
        table = "t";
      };
      reset = kind: body: { reset.${kind} = scope // body; };
      counter = reset "counter" { name = "a"; };
      quota = reset "quota" {
        name = "q";
        bytes = 1;
      };
      set = reset "set" {
        name = "s";
        type = "ipv4_addr";
      };
      map = reset "map" {
        name = "m";
        type = "ipv4_addr";
        map = "mark";
      };
      rule = reset "rule" {
        chain = "c";
        handle = 2;
        expr = [ { accept = null; } ];
      };
      element = reset "element" {
        name = "s";
        elem = [ "10.0.0.1" ];
      };
      addTable.add.table = {
        family = "ip";
        name = "x";
      };
      accepts = commands: helpers.validates nftlib.types.ruleset { nftables = commands; };
    in
    {
      expr = {
        counterLast = accepts [
          addTable
          counter
        ];
        counterThenQuota = accepts [
          counter
          quota
        ];
        counterTwice = accepts [
          counter
          counter
        ];
        quotaThenTable = accepts [
          quota
          addTable
        ];
        setThenCounter = accepts [
          set
          counter
        ];
        mapThenElement = accepts [
          map
          element
        ];
        ruleThenTable = accepts [
          rule
          addTable
        ];
        elementThenTable = accepts [
          element
          addTable
        ];
        elementThenCounter = accepts [
          element
          counter
        ];
      };
      expected = {
        counterLast = true;
        counterThenQuota = false;
        counterTwice = false;
        quotaThenTable = false;
        setThenCounter = false;
        mapThenElement = false;
        ruleThenTable = false;
        elementThenTable = true;
        elementThenCounter = true;
      };
    };

  testResetNotLastNamesTheRule = {
    expr = builtins.deepSeq (helpers.validate nftlib.types.ruleset {
      nftables = [
        {
          reset.counter = {
            family = "ip";
            table = "t";
            name = "a";
          };
        }
        {
          add.table = {
            family = "ip";
            name = "x";
          };
        }
      ];
    }) true;
    expectedError.msg = "is not of type `nft ruleset whose reset of a counter, quota, set, map, or rule is its last command'";
  };
}
