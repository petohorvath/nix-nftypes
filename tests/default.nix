{ pkgs, nftlib }:

let
  inherit (pkgs) lib;
  inherit (nftlib) toJson;

  dslTests = import ./dsl-parity.nix { inherit lib nftlib; };

  # Validate a value against an nftables type by evaluating it through a module
  # option. If the value fails to type-check, this will throw.
  validate =
    valueType: value:
    (lib.evalModules {
      modules = [
        {
          options.v = lib.mkOption { type = valueType; };
        }
        { v = value; }
      ];
    }).config.v;

  roundtrip = valueType: value: toJson (validate valueType value);

  # One drift assertion per primitive enum: the list under
  # `nftlib.enums.<x>` must match the value list `types.enum` was
  # constructed from (exposed by nixpkgs as `functor.payload.values`).
  # Single-source binding in `lib/schema/primitives.nix` guarantees
  # this; the test exists so any future regression that introduces
  # parallel lists trips here.
  enumDriftTests = lib.mapAttrs' (
    name: list:
    lib.nameValuePair "testEnumDrift_${name}" {
      expr = list == nftlib.types.${name}.functor.payload.values;
      expected = true;
    }
  ) nftlib.enums;

  baseTests = dslTests // enumDriftTests;

  tests = baseTests // {
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
      expected = ''{"match":{"left":{"payload":{"field":"dport","protocol":"tcp"}},"op":"==","right":22}}'';
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
      expected = ''{"match":{"left":{"payload":{"field":"saddr","protocol":"ip6"}},"op":"==","right":{"prefix":{"addr":"2001:db8::","len":32}}}}'';
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
      expected = ''{"match":{"left":{"payload":{"field":"dport","protocol":"tcp"}},"op":"==","right":{"set":[22,80,443]}}}'';
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
      expected = ''{"match":{"left":{"payload":{"field":"dport","protocol":"tcp"}},"op":"==","right":"@allowed_ports"}}'';
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
      expected = ''{"match":{"left":{"meta":{"key":"iifname"}},"op":"==","right":{"set":"@trusted"}}}'';
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
      expected = ''{"snat":{"addr":"192.0.2.1","flags":["random","persistent"]}}'';
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
      expected = ''{"set":{"elem":[{"prefix":{"addr":"10.0.0.0","len":8}},"192.168.1.1"],"family":"inet","flags":["interval"],"name":"trusted_hosts","table":"filter","type":"ipv4_addr"}}'';
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
      expected = ''{"map":{"family":"ip","flags":["interval"],"map":["ipv4_addr","inet_service"],"name":"port_forward","table":"nat","type":["ipv4_addr","inet_service"]}}'';
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
      expected = ''{"vmap":{"data":"@iifname_vmap","key":{"meta":{"key":"iifname"}}}}'';
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
      expected = ''{"log":{"flags":["tcp options","ip options"],"level":"info","prefix":"DROPPED: "}}'';
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
      expected = ''{"flush":{"meter":{"family":"inet","name":"rate_meter","table":"filter"}}}'';
    };

    # ------------------------------------------------------------------
    # `flush flowtable` — rejected by parser_json.c (no `flowtable` row
    # in `cmd_obj_table[]` at line 4297-4304). Schema previously
    # accepted it; this asserts that's no longer the case.
    # ------------------------------------------------------------------
    testFlushFlowtableRejected = {
      expr =
        (builtins.tryEval (
          roundtrip nftlib.types.command {
            flush = {
              flowtable = {
                family = "inet";
                table = "filter";
                name = "ft";
              };
            };
          }
        )).success;
      expected = false;
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
      expected = ''{"limit":{"burst":10,"family":"inet","name":"slow","per":"second","rate":5,"table":"filter"}}'';
    };

    testLimitObjectUnitRejected = {
      expr =
        (builtins.tryEval (
          roundtrip nftlib.types.objects.limit {
            limit = {
              family = "inet";
              table = "filter";
              name = "slow";
              rate = 5;
              per = "second";
              unit = "packets";
            };
          }
        )).success;
      expected = false;
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
      expected = ''{"concat":[{"payload":{"field":"saddr","protocol":"ip"}},{"payload":{"field":"dport","protocol":"tcp"}}]}'';
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
      expected = ''{"chain":{"family":"inet","hook":"input","name":"input","policy":"drop","prio":0,"table":"filter","type":"filter"}}'';
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
      expected = ''{"rule":{"chain":"input","expr":[{"match":{"left":{"payload":{"field":"dport","protocol":"tcp"}},"op":"==","right":22}},{"counter":{"bytes":0,"packets":0}},{"accept":null}],"family":"inet","table":"filter"}}'';
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
      expected = ''{"nftables":[{"flush":{"ruleset":null}},{"add":{"table":{"family":"inet","name":"filter"}}}]}'';
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
      expected = ''{"element":{"elem":["1.2.3.4","5.6.7.8"],"family":"inet","name":"blocklist","table":"filter"}}'';
    };

    # ------------------------------------------------------------------
    # Element body with attached `stmt` — parser_json.c json_parse_set_elem
    # accepts a `stmt` array alongside `val`/`timeout`/`expires` for stateful
    # statements (counter/quota/limit/…) that fire on element match.
    # ------------------------------------------------------------------
    testElementStmtCounterRef = {
      expr = roundtrip nftlib.types.expression {
        elem = {
          val = "1.2.3.4";
          timeout = 60;
          stmt = [ { counter = "tracker-hits"; } ];
        };
      };
      expected = ''{"elem":{"stmt":[{"counter":"tracker-hits"}],"timeout":60,"val":"1.2.3.4"}}'';
    };

    # Element body with multiple stateful statements (counter + limit).
    testElementStmtMulti = {
      expr = roundtrip nftlib.types.expression {
        elem = {
          val = "10.0.0.1";
          stmt = [
            {
              counter = {
                packets = 0;
                bytes = 0;
              };
            }
            {
              limit = {
                rate = 5;
                per = "second";
              };
            }
          ];
        };
      };
      expected = ''{"elem":{"stmt":[{"counter":{"bytes":0,"packets":0}},{"limit":{"per":"second","rate":5}}],"val":"10.0.0.1"}}'';
    };

    # Element body inside a set object — full add-set command shape with
    # element-attached counter ref. End-to-end check that the schema route
    # accepts the value and toJson emits the libnftables-json wire form.
    testSetElementsWithStmt = {
      expr = roundtrip nftlib.types.objects.set {
        set = {
          family = "ip";
          table = "filter";
          name = "tracker";
          type = "ipv4_addr";
          elem = [
            {
              elem = {
                val = "1.2.3.4";
                timeout = 60;
                stmt = [ { counter = "tracker-hits"; } ];
              };
            }
          ];
        };
      };
      expected = ''{"set":{"elem":[{"elem":{"stmt":[{"counter":"tracker-hits"}],"timeout":60,"val":"1.2.3.4"}}],"family":"ip","name":"tracker","table":"filter","type":"ipv4_addr"}}'';
    };

    # An invalid statement shape inside `stmt` must fail validation —
    # confirms the back-reference resolves to the real statement type and
    # isn't accepting arbitrary attrsets.
    testElementStmtRejectsInvalid = {
      expr =
        (builtins.tryEval (
          roundtrip nftlib.types.expression {
            elem = {
              val = "1.2.3.4";
              stmt = [ { not_a_real_statement = { }; } ];
            };
          }
        )).success;
      expected = false;
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
      expected = ''{"meter":{"key":{"meta":{"key":"iifname"}},"name":"http_ratelimit","stmt":{"limit":{"per":"second","rate":100}}}}'';
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
      expr =
        (builtins.tryEval (
          roundtrip nftlib.types.expression {
            payload = {
              base = "nh";
              offset = 0;
              len = 16;
              protocol = "tcp";
              field = "dport";
            };
          }
        )).success;
      expected = false;
    };

    # ------------------------------------------------------------------
    # Incomplete raw payload (missing len) must be rejected
    # ------------------------------------------------------------------
    testRawPayloadIncompleteRejected = {
      expr =
        (builtins.tryEval (
          roundtrip nftlib.types.expression {
            payload = {
              base = "nh";
              offset = 0;
            };
          }
        )).success;
      expected = false;
    };

    # ------------------------------------------------------------------
    # Incomplete named payload (missing field) must be rejected
    # ------------------------------------------------------------------
    testNamedPayloadIncompleteRejected = {
      expr =
        (builtins.tryEval (
          roundtrip nftlib.types.expression {
            payload = {
              protocol = "tcp";
            };
          }
        )).success;
      expected = false;
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
      expected = ''{"synproxy":{"flags":["timestamp","sack-perm"],"mss":1460,"wscale":7}}'';
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
      expected = ''{"secmark":{"context":"system_u:object_r:http_packet_t:s0","family":"inet","name":"sec_http","table":"filter"}}'';
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
      expected = ''{"synproxy":{"family":"inet","flags":["timestamp"],"mss":1460,"name":"sp1","table":"filter","wscale":7}}'';
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
      expected = ''{"tunnel":{"dst-ipv4":"10.0.0.2","family":"inet","id":42,"name":"v","src-ipv4":"10.0.0.1","table":"t","tunnel":{"gbp":100},"type":"vxlan"}}'';
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
      expected = ''{"tunnel":{"family":"inet","name":"e1","table":"t","tunnel":{"index":7,"version":1},"type":"erspan"}}'';
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
      expected = ''{"tunnel":{"family":"inet","name":"e2","table":"t","tunnel":{"dir":"ingress","hwid":3,"version":2},"type":"erspan"}}'';
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
      expected = ''{"tunnel":{"family":"inet","name":"g","table":"t","tunnel":[{"class":258,"data":"deadbeef","opt-type":128}],"type":"geneve"}}'';
    };

    # ------------------------------------------------------------------
    # Audit-pass additions: fields confirmed in parser_json.c
    # ------------------------------------------------------------------

    # limit.per is required in inline form (parser_json.c:2084)
    testLimitPerRejectedWithoutPer = {
      expr =
        (builtins.tryEval (
          roundtrip nftlib.types.statement {
            limit = {
              rate = 100;
            };
          }
        )).success;
      expected = false;
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
      expected = ''{"meter":{"key":{"meta":{"key":"iifname"}},"name":"m","size":4096,"stmt":{"counter":{"bytes":0,"packets":0}}}}'';
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
      expected = ''{"dnat":{"addr":"10.0.0.0/24","type_flags":["interval","prefix"]}}'';
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
      expected = ''{"payload":{"field":"daddr","protocol":"ip","tunnel":"vxlan"}}'';
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
      expected = ''{"chain":{"dev":["eth0","eth1"],"family":"netdev","hook":"ingress","name":"ingress","prio":-500,"table":"filter","type":"filter"}}'';
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
      expr =
        (builtins.tryEval (
          roundtrip nftlib.types.objects.tunnel {
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
          }
        )).success;
      expected = false;
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
      expected = ''{"ct timeout":{"family":"ip","l3proto":"ip","name":"fast_tcp","policy":{"close":5,"established":300,"syn_sent":30},"protocol":"tcp","table":"filter"}}'';
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
      expected = ''{"set":{"elem":"10.0.0.1","op":"delete","set":"@blocked","stmt":[{"counter":{"bytes":0,"packets":0}}]}}'';
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
      expected = ''{"map":{"data":42,"elem":"10.0.0.1","map":"@cache","op":"update"}}'';
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
      expected = ''{"table":{"comment":"main firewall","family":"inet","name":"filter"}}'';
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
      expected = ''{"chain":{"comment":"accept established","family":"inet","name":"input","table":"filter"}}'';
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
      expected = ''{"counter":{"comment":"HTTP hits","family":"ip","name":"pkts","table":"filter"}}'';
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
      expr = (builtins.tryEval (nftlib.resolvePriority "wat" "filter")).success;
      expected = false;
    };

    # ------------------------------------------------------------------
    # resolvePriority — unknown symbol throws (default table)
    # ------------------------------------------------------------------
    testResolvePriorityUnknownSymbolThrowsDefault = {
      expr = (builtins.tryEval (nftlib.resolvePriority "ip" "out")).success;
      expected = false;
    };

    # ------------------------------------------------------------------
    # resolvePriority — symbol valid in the default table is rejected for
    # bridge if it isn't in the bridge table (`raw`/`mangle`/`security`
    # are default-only).
    # ------------------------------------------------------------------
    testResolvePriorityUnknownSymbolThrowsBridge = {
      expr = (builtins.tryEval (nftlib.resolvePriority "bridge" "raw")).success;
      expected = false;
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

    # Sanity check: the drift suite is generated, so an accidental
    # truncation of `enumValues` would silently shrink coverage. We
    # currently expose 36 enums; assert the count cannot drop below
    # the existing surface without an explicit test update.
    testEnumCountSanity = {
      expr = builtins.length (builtins.attrNames nftlib.enums) >= 36;
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
      expr = nftlib.compatibility.priorityIntsDefault.filter;
      expected = 0;
    };

    testCompatPriorityBridgeFilter = {
      expr = nftlib.compatibility.priorityIntsBridge.filter;
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
  };

  runTests =
    pkgs':
    let
      results = lib.runTests tests;
      fmt = res: lib.generators.toPretty { } res;
    in
    if results == [ ] then
      pkgs'.runCommandLocal "nft-schema-tests-pass" { } ''
        echo "All ${toString (builtins.length (builtins.attrNames tests))} tests passed"
        touch $out
      ''
    else
      pkgs'.runCommandLocal "nft-schema-tests-fail" { } ''
        cat <<'EOF'
        Schema tests failed:
        ${fmt results}
        EOF
        exit 1
      '';
in
{
  inherit tests runTests;
}
