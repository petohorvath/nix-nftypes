{ pkgs, nftlib }:

let
  inherit (pkgs) lib;
  inherit (nftlib) toJSON;

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

  roundtrip = valueType: value: toJSON (validate valueType value);

  tests = {
    # ------------------------------------------------------------------
    # Verdicts
    # ------------------------------------------------------------------
    testAcceptVerdict = {
      expr = roundtrip nftlib.statement { accept = null; };
      expected = ''{"accept":null}'';
    };

    testDropVerdict = {
      expr = roundtrip nftlib.statement { drop = null; };
      expected = ''{"drop":null}'';
    };

    testJumpVerdict = {
      expr = roundtrip nftlib.statement {
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
      expr = roundtrip nftlib.statement {
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
      expr = roundtrip nftlib.statement {
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
      expr = roundtrip nftlib.expression {
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
      expr = roundtrip nftlib.statement {
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
      expr = roundtrip nftlib.statement {
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
    # DNAT with port
    # ------------------------------------------------------------------
    testDnat = {
      expr = roundtrip nftlib.statement {
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
      expr = roundtrip nftlib.statement {
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
      expr = roundtrip nftlib.statement { masquerade = { }; };
      expected = ''{"masquerade":{}}'';
    };

    # ------------------------------------------------------------------
    # Named set using ipv4_addr type
    # ------------------------------------------------------------------
    testNamedSet = {
      expr = roundtrip nftlib.objects.set {
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
    # Map with concatenated key: ipv4_addr . inet_service → ipv4_addr . inet_service
    # ------------------------------------------------------------------
    testMapConcatenated = {
      expr = roundtrip nftlib.objects.map {
        map = {
          family = "ip";
          table = "nat";
          name = "port_forward";
          type = [
            "ipv4_addr"
            "inet_service"
          ];
          map = "ipv4_addr . inet_service";
          flags = [ "interval" ];
        };
      };
      expected = ''{"map":{"family":"ip","flags":["interval"],"map":"ipv4_addr . inet_service","name":"port_forward","table":"nat","type":["ipv4_addr","inet_service"]}}'';
    };

    # ------------------------------------------------------------------
    # vmap (verdict map) with jumps
    # ------------------------------------------------------------------
    testVmap = {
      expr = roundtrip nftlib.statement {
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
      expr = roundtrip nftlib.expression {
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
      expr = roundtrip nftlib.expression {
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
      expr = roundtrip nftlib.expression {
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
      expr = roundtrip nftlib.statement {
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
      expr = roundtrip nftlib.statement {
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
      expr = roundtrip nftlib.statement { counter = "http_hits"; };
      expected = ''{"counter":"http_hits"}'';
    };

    # ------------------------------------------------------------------
    # Counter (anonymous)
    # ------------------------------------------------------------------
    testCounterAnonymous = {
      expr = roundtrip nftlib.statement {
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
      expr = roundtrip nftlib.expression {
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
    # Numgen
    # ------------------------------------------------------------------
    testNumgen = {
      expr = roundtrip nftlib.expression {
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
      expr = roundtrip nftlib.expression {
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
      expr = roundtrip nftlib.objects.table {
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
      expr = roundtrip nftlib.objects.chain {
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
      expr = roundtrip nftlib.objects.rule {
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
      expr = roundtrip nftlib.command {
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
      expr = roundtrip nftlib.command {
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
      expr = roundtrip nftlib.ruleset {
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
      expr = roundtrip nftlib.objects.element {
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
    # Reject with icmp code
    # ------------------------------------------------------------------
    testReject = {
      expr = roundtrip nftlib.statement {
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
      expr = roundtrip nftlib.statement {
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
      expr = roundtrip nftlib.statement {
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
      expr = roundtrip nftlib.expression {
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
          roundtrip nftlib.expression {
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
          roundtrip nftlib.expression {
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
          roundtrip nftlib.expression {
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
      expr = roundtrip nftlib.statement { last = null; };
      expected = ''{"last":null}'';
    };

    # ------------------------------------------------------------------
    # Counter stateless null form (emitted by `nft -j list --stateless`)
    # ------------------------------------------------------------------
    testCounterStatelessNull = {
      expr = roundtrip nftlib.statement { counter = null; };
      expected = ''{"counter":null}'';
    };

    # ------------------------------------------------------------------
    # `last` statement with timestamp
    # ------------------------------------------------------------------
    testLastStmtUsed = {
      expr = roundtrip nftlib.statement {
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
      expr = roundtrip nftlib.statement {
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
      expr = roundtrip nftlib.statement {
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
      expr = roundtrip nftlib.statement {
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
      expr = roundtrip nftlib.statement { synproxy = null; };
      expected = ''{"synproxy":null}'';
    };

    # ------------------------------------------------------------------
    # `reset` tcp option strip
    # ------------------------------------------------------------------
    testResetStmt = {
      expr = roundtrip nftlib.statement {
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
      expr = roundtrip nftlib.statement { secmark = "@my_secmark"; };
      expected = ''{"secmark":"@my_secmark"}'';
    };

    testTunnelStmt = {
      expr = roundtrip nftlib.statement { tunnel = "@my_tunnel"; };
      expected = ''{"tunnel":"@my_tunnel"}'';
    };

    # ------------------------------------------------------------------
    # `ipsec` (xfrm) expression
    # ------------------------------------------------------------------
    testIpsecExpr = {
      expr = roundtrip nftlib.expression {
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
      expr = roundtrip nftlib.expression {
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
      expr = roundtrip nftlib.objects.secmark {
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
      expr = roundtrip nftlib.objects.synproxy {
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
      expr = roundtrip nftlib.statement {
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
      expr = roundtrip nftlib.command {
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
      expr = roundtrip nftlib.objects.tunnel {
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
      expr = roundtrip nftlib.objects.tunnel {
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
      expr = roundtrip nftlib.objects.tunnel {
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
      expr = roundtrip nftlib.objects.tunnel {
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
          roundtrip nftlib.statement {
            limit = {
              rate = 100;
            };
          }
        )).success;
      expected = false;
    };

    # queue without num is valid
    testQueueNoNum = {
      expr = roundtrip nftlib.statement {
        queue = {
          flags = [ "bypass" ];
        };
      };
      expected = ''{"queue":{"flags":["bypass"]}}'';
    };

    # meter.size (parser_json.c:2793)
    testMeterSize = {
      expr = roundtrip nftlib.statement {
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
      expr = roundtrip nftlib.statement {
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
      expr = roundtrip nftlib.expression {
        "ip option" = {
          name = "lsrr";
          field = "length";
        };
      };
      expected = ''{"ip option":{"field":"length","name":"lsrr"}}'';
    };

    # tcp option raw form (parser_json.c:745)
    testTcpOptionRaw = {
      expr = roundtrip nftlib.expression {
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
      expr = roundtrip nftlib.expression {
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
      expr = roundtrip nftlib.expression {
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
      expr = roundtrip nftlib.objects.chain {
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
      expr = roundtrip nftlib.objects.secmark {
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
      expr = roundtrip nftlib.objects.ctHelper {
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
          roundtrip nftlib.objects.tunnel {
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
      expr = roundtrip nftlib.expression {
        socket = {
          key = "mark";
        };
      };
      expected = ''{"socket":{"key":"mark"}}'';
    };

    testSocketWildcard = {
      expr = roundtrip nftlib.expression {
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
      expr = roundtrip nftlib.expression {
        meta = {
          key = "ipsec";
        };
      };
      expected = ''{"meta":{"key":"ipsec"}}'';
    };

    testMetaTimeKey = {
      expr = roundtrip nftlib.expression {
        meta = {
          key = "time";
        };
      };
      expected = ''{"meta":{"key":"time"}}'';
    };

    testMetaSdifKey = {
      expr = roundtrip nftlib.expression {
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
      expr = roundtrip nftlib.objects.ctTimeout {
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
      expr = roundtrip nftlib.statement {
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
      expr = roundtrip nftlib.statement {
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
      expr = roundtrip nftlib.objects.table {
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
      expr = roundtrip nftlib.objects.chain {
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
      expr = roundtrip nftlib.objects.counter {
        counter = {
          family = "ip";
          table = "filter";
          name = "pkts";
          comment = "HTTP hits";
        };
      };
      expected = ''{"counter":{"comment":"HTTP hits","family":"ip","name":"pkts","table":"filter"}}'';
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
