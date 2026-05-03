{ lib, nftlib }:

# Parity tests for the `dsl` layer. Each test asserts that a DSL value
# renders to the same JSON as a hand-written attrset, going through the same
# evalModules type-check. That proves the DSL is pure sugar: the field
# trees, operators, variant namespaces, and declarative table structure all
# collapse to attrsets the schema already accepts.

let
  inherit (nftlib) toJSON;
  dsl = nftlib.dsl;

  validate =
    t: v:
    (lib.evalModules {
      modules = [
        { options.v = lib.mkOption { type = t; }; }
        { v = v; }
      ];
    }).config.v;
  roundtrip = t: v: toJSON (validate t v);

  parity = t: nftValue: handwritten: {
    expr = roundtrip t nftValue;
    expected = roundtrip t handwritten;
  };

  pe = parity nftlib.types.expression;
  ps = parity nftlib.types.statement;
  pr = parity nftlib.types.ruleset;
  pc = parity nftlib.types.command;
in
{
  # =========================================================================
  # Field trees — payload protocols
  # =========================================================================

  testFieldTcpDport = pe dsl.fields.tcp.dport {
    payload = {
      protocol = "tcp";
      field = "dport";
    };
  };
  testFieldUdpSport = pe dsl.fields.udp.sport {
    payload = {
      protocol = "udp";
      field = "sport";
    };
  };
  testFieldIpSaddr = pe dsl.fields.ip.saddr {
    payload = {
      protocol = "ip";
      field = "saddr";
    };
  };
  testFieldIpFragOff = pe dsl.fields.ip.fragOff {
    payload = {
      protocol = "ip";
      field = "frag-off";
    };
  };
  testFieldIp6Daddr = pe dsl.fields.ip6.daddr {
    payload = {
      protocol = "ip6";
      field = "daddr";
    };
  };
  testFieldIcmpv6PacketTooBig = pe dsl.fields.icmpv6.packetTooBig {
    payload = {
      protocol = "icmpv6";
      field = "packet-too-big";
    };
  };
  testFieldEtherSaddr = pe dsl.fields.ether.saddr {
    payload = {
      protocol = "ether";
      field = "saddr";
    };
  };
  testFieldVlanId = pe dsl.fields.vlan.id {
    payload = {
      protocol = "vlan";
      field = "id";
    };
  };

  # -- Field trees — meta / ct / rt / socket / fib / ipsec / tunnelMeta -----

  testFieldMetaMark = pe dsl.fields.meta.mark {
    meta = {
      key = "mark";
    };
  };
  testFieldMetaIifname = pe dsl.fields.meta.iifname {
    meta = {
      key = "iifname";
    };
  };
  testFieldCtState = pe dsl.fields.ct.state {
    ct = {
      key = "state";
    };
  };
  testFieldCtProtoSrc = pe dsl.fields.ct.protoSrc {
    ct = {
      key = "proto-src";
    };
  };
  testFieldRtMtu = pe dsl.fields.rt.mtu {
    rt = {
      key = "mtu";
    };
  };
  testFieldRtIpsec = pe dsl.fields.rt.ipsec {
    rt = {
      key = "ipsec";
    };
  };
  testFieldSocketTransparent = pe dsl.fields.socket.transparent {
    socket = {
      key = "transparent";
    };
  };
  testFieldFibOif = pe dsl.fields.fib.oif {
    fib = {
      result = "oif";
    };
  };
  testFieldFibCheck = pe dsl.fields.fib.check {
    fib = {
      result = "check";
    };
  };
  testFieldOsfName = pe dsl.fields.osf.name {
    osf = {
      key = "name";
    };
  };
  testFieldOsfVersion = pe dsl.fields.osf.version {
    osf = {
      key = "version";
    };
  };
  testFieldIpsecReqid = pe dsl.fields.ipsec.reqid {
    ipsec = {
      key = "reqid";
    };
  };
  testFieldTunnelMetaId = pe dsl.fields.tunnelMeta.id {
    tunnel = {
      key = "id";
    };
  };

  # =========================================================================
  # Escape hatches
  # =========================================================================

  testPayloadEscape =
    pe
      (dsl.payload {
        protocol = "tcp";
        field = "dport";
      })
      {
        payload = {
          protocol = "tcp";
          field = "dport";
        };
      };

  testPayloadRaw =
    pe
      (dsl.payloadRaw {
        base = "nh";
        offset = 72;
        len = 16;
      })
      {
        payload = {
          base = "nh";
          offset = 72;
          len = 16;
        };
      };

  testPayloadTunnel =
    pe
      (dsl.payloadTunnel {
        tunnel = "vxlan";
        protocol = "ip";
        field = "daddr";
      })
      {
        payload = {
          tunnel = "vxlan";
          protocol = "ip";
          field = "daddr";
        };
      };

  testTcpOption = pe (dsl.expr.tcpOption { name = "sack-perm"; }) {
    "tcp option" = {
      name = "sack-perm";
    };
  };

  testTcpOptionRaw =
    pe
      (dsl.expr.tcpOptionRaw {
        base = 2;
        offset = 16;
        len = 16;
      })
      {
        "tcp option" = {
          base = 2;
          offset = 16;
          len = 16;
        };
      };

  testIpOption =
    pe
      (dsl.expr.ipOption {
        name = "lsrr";
        field = "length";
      })
      {
        "ip option" = {
          name = "lsrr";
          field = "length";
        };
      };

  testSctpChunk =
    pe
      (dsl.expr.sctpChunk {
        name = "data";
        field = "tsn";
      })
      {
        "sctp chunk" = {
          name = "data";
          field = "tsn";
        };
      };

  testDccpOption = pe (dsl.expr.dccpOption 42) {
    "dccp option" = {
      type = 42;
    };
  };

  testExthdr =
    pe
      (dsl.expr.exthdr {
        name = "frag";
        field = "nexthdr";
      })
      {
        exthdr = {
          name = "frag";
          field = "nexthdr";
        };
      };

  # =========================================================================
  # Expression helpers
  # =========================================================================

  testExprConcat =
    pe
      (dsl.expr.concat [
        dsl.fields.ip.saddr
        dsl.fields.tcp.dport
      ])
      {
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

  testExprSet =
    pe
      (dsl.expr.set [
        22
        80
        443
      ])
      {
        set = [
          22
          80
          443
        ];
      };

  testExprMap =
    pe
      (dsl.expr.map {
        key = dsl.fields.tcp.dport;
        data = "@pf";
      })
      {
        map = {
          key = {
            payload = {
              protocol = "tcp";
              field = "dport";
            };
          };
          data = "@pf";
        };
      };

  testExprPrefix = pe (dsl.expr.prefix "10.0.0.0" 8) {
    prefix = {
      addr = "10.0.0.0";
      len = 8;
    };
  };

  testExprRange = pe (dsl.expr.range 1024 65535) {
    range = [
      1024
      65535
    ];
  };

  testExprNumgen =
    pe
      (dsl.expr.numgen {
        mode = "inc";
        mod = 4;
        offset = 100;
      })
      {
        numgen = {
          mode = "inc";
          mod = 4;
          offset = 100;
        };
      };

  testExprJhash =
    pe
      (dsl.expr.jhash {
        mod = 256;
        expr = dsl.fields.ip.saddr;
        seed = 42;
      })
      {
        jhash = {
          mod = 256;
          expr = {
            payload = {
              protocol = "ip";
              field = "saddr";
            };
          };
          seed = 42;
        };
      };

  testExprSymhash =
    pe
      (dsl.expr.symhash {
        mod = 8;
        offset = 1;
      })
      {
        symhash = {
          mod = 8;
          offset = 1;
        };
      };

  testExprFibRefined =
    pe
      (dsl.expr.fib {
        result = "oif";
        flags = [
          "saddr"
          "mark"
        ];
      })
      {
        fib = {
          result = "oif";
          flags = [
            "saddr"
            "mark"
          ];
        };
      };

  testExprCtRefined =
    pe
      (dsl.expr.ct {
        key = "saddr";
        dir = "original";
        family = "ip";
      })
      {
        ct = {
          key = "saddr";
          dir = "original";
          family = "ip";
        };
      };

  testExprRtRefined =
    pe
      (dsl.expr.rt {
        key = "nexthop";
        family = "ip6";
      })
      {
        rt = {
          key = "nexthop";
          family = "ip6";
        };
      };

  testExprOsf =
    pe
      (dsl.expr.osf {
        key = "name";
        ttl = "loose";
      })
      {
        osf = {
          key = "name";
          ttl = "loose";
        };
      };

  testExprIpsecRefined =
    pe
      (dsl.expr.ipsec {
        key = "saddr";
        family = "ip";
        dir = "in";
      })
      {
        ipsec = {
          key = "saddr";
          family = "ip";
          dir = "in";
        };
      };

  testExprElem =
    pe
      (dsl.expr.elem {
        val = "10.0.0.1";
        timeout = 60;
      })
      {
        elem = {
          val = "10.0.0.1";
          timeout = 60;
        };
      };

  # `stmt = null` must not appear in the rendered shape — the DSL `compact`
  # helper drops null-valued attrs before wrapping.
  testExprElemNoStmt = {
    expr = toJSON (
      dsl.expr.elem {
        val = "1.2.3.4";
        timeout = 60;
      }
    );
    expected = ''{"elem":{"timeout":60,"val":"1.2.3.4"}}'';
  };

  # Element-attached stateful statement via expr.elem — produces the same
  # shape as a hand-written attrset.
  testExprElemWithStmt =
    pe
      (dsl.expr.elem {
        val = "1.2.3.4";
        stmt = [ { counter = "tracker-hits"; } ];
      })
      {
        elem = {
          val = "1.2.3.4";
          stmt = [ { counter = "tracker-hits"; } ];
        };
      };

  testExprBitor = pe (dsl.expr.bitor dsl.fields.meta.mark 255) {
    "|" = [
      {
        meta = {
          key = "mark";
        };
      }
      255
    ];
  };
  testExprBitxor = pe (dsl.expr.bitxor 1 2) {
    "^" = [
      1
      2
    ];
  };
  testExprBitand = pe (dsl.expr.bitand dsl.fields.meta.mark 255) {
    "&" = [
      {
        meta = {
          key = "mark";
        };
      }
      255
    ];
  };
  testExprLshift = pe (dsl.expr.lshift 1 4) {
    "<<" = [
      1
      4
    ];
  };
  testExprRshift = pe (dsl.expr.rshift 16 4) {
    ">>" = [
      16
      4
    ];
  };

  # =========================================================================
  # Verdicts (as statements and as expressions)
  # =========================================================================

  testVerdictAcceptStmt = ps dsl.accept { accept = null; };
  testVerdictDropStmt = ps dsl.drop { drop = null; };
  testVerdictContinueStmt = ps dsl.continue { continue = null; };
  testVerdictReturnStmt = ps dsl.return { return = null; };
  testVerdictNotrackStmt = ps dsl.notrack { notrack = null; };
  testVerdictJumpStmt = ps (dsl.jump "inbound") {
    jump = {
      target = "inbound";
    };
  };
  testVerdictGotoStmt = ps (dsl.goto "elsewhere") {
    goto = {
      target = "elsewhere";
    };
  };

  testVerdictAcceptExpr = pe dsl.accept { accept = null; };
  testVerdictJumpExpr = pe (dsl.jump "vmap-target") {
    jump = {
      target = "vmap-target";
    };
  };

  # =========================================================================
  # Operators
  # =========================================================================

  testOpEq = ps (dsl.eq dsl.fields.tcp.dport 22) {
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
  testOpNe = ps (dsl.ne 1 2) {
    match = {
      left = 1;
      right = 2;
      op = "!=";
    };
  };
  testOpLt = ps (dsl.lt 1 2) {
    match = {
      left = 1;
      right = 2;
      op = "<";
    };
  };
  testOpGt = ps (dsl.gt 1 2) {
    match = {
      left = 1;
      right = 2;
      op = ">";
    };
  };
  testOpLe = ps (dsl.le 1 2) {
    match = {
      left = 1;
      right = 2;
      op = "<=";
    };
  };
  testOpGe = ps (dsl.ge 1 2) {
    match = {
      left = 1;
      right = 2;
      op = ">=";
    };
  };

  # inSet with list rhs auto-wraps as { set = ... }
  testOpInSetList =
    ps
      (dsl.inSet dsl.fields.ct.state [
        "established"
        "related"
      ])
      {
        match = {
          left = {
            ct = {
              key = "state";
            };
          };
          right = {
            set = [
              "established"
              "related"
            ];
          };
          op = "==";
        };
      };
  # inSet with string rhs passes through (typical @name usage)
  testOpInSetRef = ps (dsl.inSet dsl.fields.ip.saddr "@trusted") {
    match = {
      left = {
        payload = {
          protocol = "ip";
          field = "saddr";
        };
      };
      right = "@trusted";
      op = "==";
    };
  };
  testOpNotInSetList =
    ps
      (dsl.notInSet dsl.fields.tcp.dport [
        22
        80
      ])
      {
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
            ];
          };
          op = "!=";
        };
      };

  # within synonym
  testOpWithin =
    ps
      (dsl.within dsl.fields.tcp.dport [
        1024
        65535
      ])
      {
        match = {
          left = {
            payload = {
              protocol = "tcp";
              field = "dport";
            };
          };
          right = {
            set = [
              1024
              65535
            ];
          };
          op = "==";
        };
      };

  # match.in for bitwise flag semantics
  testOpMatchIn = ps (dsl.match.in_ dsl.fields.ct.state (dsl.expr.set [ "established" ])) {
    match = {
      left = {
        ct = {
          key = "state";
        };
      };
      right = {
        set = [ "established" ];
      };
      op = "in";
    };
  };

  # match.raw escape hatch
  testOpMatchRaw =
    ps
      (dsl.match.raw {
        op = ">=";
        left = dsl.fields.tcp.dport;
        right = 1024;
      })
      {
        match = {
          left = {
            payload = {
              protocol = "tcp";
              field = "dport";
            };
          };
          right = 1024;
          op = ">=";
        };
      };

  # =========================================================================
  # Variant namespaces
  # =========================================================================

  # counter — base call, .auto, .ref
  testCounterBase =
    ps
      (dsl.counter {
        packets = 0;
        bytes = 0;
      })
      {
        counter = {
          packets = 0;
          bytes = 0;
        };
      };
  testCounterAuto = ps dsl.counter.auto { counter = null; };
  testCounterRef = ps (dsl.counter.ref "pkts") { counter = "pkts"; };

  # reject — base, .plain, .icmp, .icmpv6, .icmpx, .tcpReset
  testRejectBase =
    ps
      (dsl.reject {
        type = "icmp";
        expr = "host-unreachable";
      })
      {
        reject = {
          type = "icmp";
          expr = "host-unreachable";
        };
      };
  testRejectPlain = ps dsl.reject.plain { reject = { }; };
  testRejectIcmp = ps (dsl.reject.icmp "net-unreachable") {
    reject = {
      type = "icmp";
      expr = "net-unreachable";
    };
  };
  testRejectIcmpv6 = ps (dsl.reject.icmpv6 "no-route") {
    reject = {
      type = "icmpv6";
      expr = "no-route";
    };
  };
  testRejectIcmpx = ps (dsl.reject.icmpx "admin-prohibited") {
    reject = {
      type = "icmpx";
      expr = "admin-prohibited";
    };
  };
  testRejectTcpReset = ps dsl.reject.tcpReset {
    reject = {
      type = "tcp reset";
    };
  };

  # log — base, .plain, camelCase rename
  testLogBase =
    ps
      (dsl.log {
        prefix = "DROPPED: ";
        level = "info";
        flags = [
          "tcp options"
          "ip options"
        ];
      })
      {
        log = {
          prefix = "DROPPED: ";
          level = "info";
          flags = [
            "tcp options"
            "ip options"
          ];
        };
      };
  testLogPlain = ps dsl.log.plain { log = { }; };
  testLogQueueThreshold = ps (dsl.log { queueThreshold = 50; }) {
    log = {
      "queue-threshold" = 50;
    };
  };

  # limit / quota
  testLimitBase =
    ps
      (dsl.limit {
        rate = 10;
        per = "minute";
        burst = 5;
      })
      {
        limit = {
          rate = 10;
          per = "minute";
          burst = 5;
        };
      };
  testLimitRef = ps (dsl.limit.ref "lim") { limit = "lim"; };
  testQuotaBase =
    ps
      (dsl.quota {
        val = 1000;
        val_unit = "mbytes";
      })
      {
        quota = {
          val = 1000;
          val_unit = "mbytes";
        };
      };
  testQuotaRef = ps (dsl.quota.ref "q1") { quota = "q1"; };

  # NAT family
  testSnat =
    ps
      (dsl.snat {
        addr = "192.0.2.1";
        family = "ip";
      })
      {
        snat = {
          addr = "192.0.2.1";
          family = "ip";
        };
      };
  testDnat =
    ps
      (dsl.dnat {
        addr = "10.0.0.1";
        family = "ip";
        port = 8080;
      })
      {
        dnat = {
          addr = "10.0.0.1";
          family = "ip";
          port = 8080;
        };
      };
  testMasqueradeBase = ps (dsl.masquerade { flags = [ "random" ]; }) {
    masquerade = {
      flags = [ "random" ];
    };
  };
  testMasqueradePlain = ps dsl.masquerade.plain { masquerade = { }; };
  testRedirectBase = ps (dsl.redirect { port = 8080; }) {
    redirect = {
      port = 8080;
    };
  };
  testRedirectPlain = ps dsl.redirect.plain { redirect = { }; };
  testFwd = ps (dsl.fwd { dev = "eth0"; }) {
    fwd = {
      dev = "eth0";
    };
  };
  testDup =
    ps
      (dsl.dup {
        addr = "10.0.0.1";
        dev = "eth0";
      })
      {
        dup = {
          addr = "10.0.0.1";
          dev = "eth0";
        };
      };
  testTproxy =
    ps
      (dsl.tproxy {
        family = "ip";
        addr = "127.0.0.1";
        port = 8080;
      })
      {
        tproxy = {
          family = "ip";
          addr = "127.0.0.1";
          port = 8080;
        };
      };

  # synproxy
  testSynproxyBase =
    ps
      (dsl.synproxy {
        mss = 1460;
        wscale = 7;
      })
      {
        synproxy = {
          mss = 1460;
          wscale = 7;
        };
      };
  testSynproxyAuto = ps dsl.synproxy.auto { synproxy = null; };
  testSynproxyRef = ps (dsl.synproxy.ref "sp1") { synproxy = "sp1"; };

  # queue
  testQueueBase =
    ps
      (dsl.queue {
        num = 1;
        flags = [ "bypass" ];
      })
      {
        queue = {
          num = 1;
          flags = [ "bypass" ];
        };
      };
  testQueuePlain = ps dsl.queue.plain { queue = { }; };

  # ct set/count statements
  testCtHelper = ps (dsl.ctHelper "ftp") { "ct helper" = "ftp"; };
  testCtTimeout = ps (dsl.ctTimeout "fast_tcp") { "ct timeout" = "fast_tcp"; };
  testCtExpectation = ps (dsl.ctExpectation "e1") { "ct expectation" = "e1"; };
  testCtCount =
    ps
      (dsl.ctCount {
        val = 100;
        inv = true;
      })
      {
        "ct count" = {
          val = 100;
          inv = true;
        };
      };

  # flow / meter / vmap
  testFlow = ps (dsl.flow { flowtable = "@ft"; }) {
    flow = {
      op = "add";
      flowtable = "@ft";
    };
  };
  testMeter =
    ps
      (dsl.meter {
        name = "m";
        key = dsl.fields.meta.iifname;
        stmt = dsl.counter {
          packets = 0;
          bytes = 0;
        };
        size = 4096;
      })
      {
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
  testVmap = ps (dsl.vmap dsl.fields.meta.iifname "@v") {
    vmap = {
      key = {
        meta = {
          key = "iifname";
        };
      };
      data = "@v";
    };
  };

  # mangle / dynamic set/map / misc
  testMangle = ps (dsl.mangle dsl.fields.meta.mark 42) {
    mangle = {
      key = {
        meta = {
          key = "mark";
        };
      };
      value = 42;
    };
  };
  testSetStmt =
    ps
      (dsl.setStmt {
        op = "add";
        elem = "10.0.0.1";
        set = "@blocked";
      })
      {
        set = {
          op = "add";
          elem = "10.0.0.1";
          set = "@blocked";
        };
      };
  testMapStmt =
    ps
      (dsl.mapStmt {
        op = "update";
        elem = "10.0.0.1";
        data = 42;
        map = "@cache";
      })
      {
        map = {
          op = "update";
          elem = "10.0.0.1";
          data = 42;
          map = "@cache";
        };
      };
  testReset = ps (dsl.reset (dsl.expr.tcpOption { name = "sack-perm"; })) {
    reset = {
      "tcp option" = {
        name = "sack-perm";
      };
    };
  };
  testSecmark = ps (dsl.secmark "@my_secmark") { secmark = "@my_secmark"; };
  testTunnelStmt = ps (dsl.tunnel "@my_tunnel") { tunnel = "@my_tunnel"; };
  testXt = ps (dsl.xt "match" "connlimit") {
    xt = {
      type = "match";
      name = "connlimit";
    };
  };
  testLast = ps dsl.last { last = null; };
  testLastUsed = ps (dsl.lastUsed (-1)) {
    last = {
      used = -1;
    };
  };

  # =========================================================================
  # Declarative table / renderer
  # =========================================================================

  # Empty table — single add.table command.
  testRenderEmptyTable = pr (dsl.ruleset [ (dsl.table "inet" "t" { }) ]) {
    nftables = [
      {
        add = {
          table = {
            family = "inet";
            name = "t";
          };
        };
      }
    ];
  };

  # Flush + table with options.
  testRenderTableWithOptions =
    pr
      (dsl.ruleset [
        dsl.flush
        (dsl.table "inet" "t" { comment = "demo"; })
      ])
      {
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
                name = "t";
                comment = "demo";
              };
            };
          }
        ];
      };

  # Set inside table — demonstrates `elements` (DSL) → `elem` (JSON) rename.
  testRenderTableWithSet =
    pr
      (dsl.ruleset [
        (dsl.table "inet" "t" {
          sets.trusted = {
            type = "ipv4_addr";
            flags = [ "interval" ];
            elements = [ (dsl.expr.prefix "10.0.0.0" 8) ];
          };
        })
      ])
      {
        nftables = [
          {
            add = {
              table = {
                family = "inet";
                name = "t";
              };
            };
          }
          {
            add = {
              set = {
                family = "inet";
                table = "t";
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
          }
        ];
      };

  # DSL `elements` key translates to JSON `elem` key in set/map bodies.
  # The DSL name is plural to match `rules`, `flags`, etc.; the JSON schema
  # uses singular `elem`. This test pins the rename behaviour explicitly.
  testRenderSetElementsRename =
    pr
      (dsl.ruleset [
        (dsl.table "inet" "t" {
          sets.foo = {
            type = "ipv4_addr";
            elements = [
              "1.2.3.4"
              "5.6.7.8"
            ];
          };
        })
      ])
      {
        nftables = [
          {
            add = {
              table = {
                family = "inet";
                name = "t";
              };
            };
          }
          {
            add = {
              set = {
                family = "inet";
                table = "t";
                name = "foo";
                type = "ipv4_addr";
                elem = [
                  "1.2.3.4"
                  "5.6.7.8"
                ];
              };
            };
          }
        ];
      };

  # Same rename applies to the standalone `element` object kind (used to
  # add elements to an existing set/map).
  testRenderElementObjectRename =
    pr
      (dsl.ruleset [
        (dsl.table "inet" "t" {
          elements.blocked = {
            elements = [
              "10.0.0.1"
              "10.0.0.2"
            ];
          };
        })
      ])
      {
        nftables = [
          {
            add = {
              table = {
                family = "inet";
                name = "t";
              };
            };
          }
          {
            add = {
              element = {
                family = "inet";
                table = "t";
                name = "blocked";
                elem = [
                  "10.0.0.1"
                  "10.0.0.2"
                ];
              };
            };
          }
        ];
      };

  # Map with camelCase-aliased gcInterval (→ "gc-interval").
  testRenderMapGcInterval =
    pr
      (dsl.ruleset [
        (dsl.table "inet" "t" {
          maps.c = {
            type = "inet_service";
            map = "inet_service";
            gcInterval = 60;
          };
        })
      ])
      {
        nftables = [
          {
            add = {
              table = {
                family = "inet";
                name = "t";
              };
            };
          }
          {
            add = {
              map = {
                family = "inet";
                table = "t";
                name = "c";
                type = "inet_service";
                map = "inet_service";
                "gc-interval" = 60;
              };
            };
          }
        ];
      };

  # Chain with rules — verifies chain-before-rule emission order.
  testRenderChainWithRules =
    pr
      (dsl.ruleset [
        (dsl.table "inet" "t" {
          chains.input = {
            type = "filter";
            hook = "input";
            prio = 0;
            policy = "drop";
            rules = [
              [ dsl.accept ]
              [
                (dsl.eq dsl.fields.tcp.dport 22)
                dsl.accept
              ]
            ];
          };
        })
      ])
      {
        nftables = [
          {
            add = {
              table = {
                family = "inet";
                name = "t";
              };
            };
          }
          {
            add = {
              chain = {
                family = "inet";
                table = "t";
                name = "input";
                type = "filter";
                hook = "input";
                prio = 0;
                policy = "drop";
              };
            };
          }
          {
            add = {
              rule = {
                family = "inet";
                table = "t";
                chain = "input";
                expr = [ { accept = null; } ];
              };
            };
          }
          {
            add = {
              rule = {
                family = "inet";
                table = "t";
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
                  { accept = null; }
                ];
              };
            };
          }
        ];
      };

  # Two chains — verifies chain-adds cluster before rule-adds
  # (alphabetical: input, output).
  testRenderTwoChains =
    pr
      (dsl.ruleset [
        (dsl.table "inet" "t" {
          chains.output = {
            rules = [ [ dsl.accept ] ];
          };
          chains.input = {
            rules = [ [ dsl.drop ] ];
          };
        })
      ])
      {
        nftables = [
          {
            add = {
              table = {
                family = "inet";
                name = "t";
              };
            };
          }
          {
            add = {
              chain = {
                family = "inet";
                table = "t";
                name = "input";
              };
            };
          }
          {
            add = {
              chain = {
                family = "inet";
                table = "t";
                name = "output";
              };
            };
          }
          {
            add = {
              rule = {
                family = "inet";
                table = "t";
                chain = "input";
                expr = [ { drop = null; } ];
              };
            };
          }
          {
            add = {
              rule = {
                family = "inet";
                table = "t";
                chain = "output";
                expr = [ { accept = null; } ];
              };
            };
          }
        ];
      };

  # Rule attrset form (with handle/comment).
  testRenderRuleAttrset =
    pr
      (dsl.ruleset [
        (dsl.table "inet" "t" {
          chains.c = {
            rules = [
              {
                expr = [ dsl.accept ];
                handle = 42;
                comment = "the rule";
              }
            ];
          };
        })
      ])
      {
        nftables = [
          {
            add = {
              table = {
                family = "inet";
                name = "t";
              };
            };
          }
          {
            add = {
              chain = {
                family = "inet";
                table = "t";
                name = "c";
              };
            };
          }
          {
            add = {
              rule = {
                family = "inet";
                table = "t";
                chain = "c";
                expr = [ { accept = null; } ];
                handle = 42;
                comment = "the rule";
              };
            };
          }
        ];
      };

  # Tunnel object with hyphenated keys — camelCase → hyphen rename.
  testRenderTunnelHyphenRename =
    pr
      (dsl.ruleset [
        (dsl.table "inet" "t" {
          tunnels.v = {
            id = 42;
            srcIpv4 = "10.0.0.1";
            dstIpv4 = "10.0.0.2";
            type = "vxlan";
            tunnel = {
              gbp = 100;
            };
          };
        })
      ])
      {
        nftables = [
          {
            add = {
              table = {
                family = "inet";
                name = "t";
              };
            };
          }
          {
            add = {
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
          }
        ];
      };

  # Mixing raw commands with table nodes.
  testRenderMixRawAndTable =
    pr
      (dsl.ruleset [
        dsl.flush
        (dsl.table "ip" "x" { })
        {
          add = {
            table = {
              family = "ip";
              name = "y";
            };
          };
        }
      ])
      {
        nftables = [
          {
            flush = {
              ruleset = null;
            };
          }
          {
            add = {
              table = {
                family = "ip";
                name = "x";
              };
            };
          }
          {
            add = {
              table = {
                family = "ip";
                name = "y";
              };
            };
          }
        ];
      };

  # All-object kinds roundtrip.
  testRenderAllObjectKinds =
    pr
      (dsl.ruleset [
        (dsl.table "inet" "t" {
          counters.hits = {
            packets = 0;
            bytes = 0;
          };
          quotas.q = {
            bytes = 1000;
          };
          limits.lim = {
            rate = 10;
            per = "second";
          };
          secmarks.s = {
            context = "u:r:t:s0";
          };
          synproxies.sp = {
            mss = 1460;
            wscale = 7;
            flags = [ "timestamp" ];
          };
        })
      ])
      {
        nftables = [
          {
            add = {
              table = {
                family = "inet";
                name = "t";
              };
            };
          }
          {
            add = {
              counter = {
                family = "inet";
                table = "t";
                name = "hits";
                packets = 0;
                bytes = 0;
              };
            };
          }
          {
            add = {
              limit = {
                family = "inet";
                table = "t";
                name = "lim";
                rate = 10;
                per = "second";
              };
            };
          }
          {
            add = {
              quota = {
                family = "inet";
                table = "t";
                name = "q";
                bytes = 1000;
              };
            };
          }
          {
            add = {
              secmark = {
                family = "inet";
                table = "t";
                name = "s";
                context = "u:r:t:s0";
              };
            };
          }
          {
            add = {
              synproxy = {
                family = "inet";
                table = "t";
                name = "sp";
                mss = 1460;
                wscale = 7;
                flags = [ "timestamp" ];
              };
            };
          }
        ];
      };

  # =========================================================================
  # Renderer — error cases and edge cases
  # =========================================================================

  # Empty ruleset evaluates to an empty command list.
  testRenderEmptyRuleset = pr (dsl.ruleset [ ]) { nftables = [ ]; };

  # Nested lists flatten — callers can interpolate sub-groups of commands.
  testRenderNestedListFlatten =
    pr
      (dsl.ruleset [
        dsl.flush
        [
          (dsl.table "ip" "a" { })
          (dsl.table "ip" "b" { })
        ]
        (dsl.table "ip" "c" { })
      ])
      {
        nftables = [
          {
            flush = {
              ruleset = null;
            };
          }
          {
            add = {
              table = {
                family = "ip";
                name = "a";
              };
            };
          }
          {
            add = {
              table = {
                family = "ip";
                name = "b";
              };
            };
          }
          {
            add = {
              table = {
                family = "ip";
                name = "c";
              };
            };
          }
        ];
      };

  # Deeply nested lists still flatten to a single-level command list.
  testRenderDeepNestedListFlatten =
    pr
      (dsl.ruleset [
        [ [ [ dsl.flush ] ] ]
        [ (dsl.table "ip" "x" { }) ]
      ])
      {
        nftables = [
          {
            flush = {
              ruleset = null;
            };
          }
          {
            add = {
              table = {
                family = "ip";
                name = "x";
              };
            };
          }
        ];
      };

  # Invalid children (wrong type) must throw. `toJSON` forces evaluation so
  # the thrown exception is caught by tryEval — the renderer builds a lazy
  # list and the throw wouldn't fire until a consumer walks it.
  testRenderRejectString = {
    expr = (builtins.tryEval (toJSON (dsl.ruleset [ "not-a-command" ]))).success;
    expected = false;
  };

  testRenderRejectInt = {
    expr = (builtins.tryEval (toJSON (dsl.ruleset [ 42 ]))).success;
    expected = false;
  };

  testRenderRejectBool = {
    expr = (builtins.tryEval (toJSON (dsl.ruleset [ true ]))).success;
    expected = false;
  };

  testRenderRejectNull = {
    expr = (builtins.tryEval (toJSON (dsl.ruleset [ null ]))).success;
    expected = false;
  };

  # Invalid child nested inside a list is detected too (recursion reaches it).
  testRenderRejectNestedInvalid = {
    expr = (builtins.tryEval (toJSON (dsl.ruleset [ [ "bad" ] ]))).success;
    expected = false;
  };

  # Table with an empty `chains` attrset emits only the table-add command.
  testRenderTableEmptyChains = pr (dsl.ruleset [ (dsl.table "inet" "t" { chains = { }; }) ]) {
    nftables = [
      {
        add = {
          table = {
            family = "inet";
            name = "t";
          };
        };
      }
    ];
  };

  # Chain with an empty `rules` list emits only the chain-add command.
  testRenderChainEmptyRules =
    pr
      (dsl.ruleset [
        (dsl.table "inet" "t" {
          chains.c = {
            rules = [ ];
          };
        })
      ])
      {
        nftables = [
          {
            add = {
              table = {
                family = "inet";
                name = "t";
              };
            };
          }
          {
            add = {
              chain = {
                family = "inet";
                table = "t";
                name = "c";
              };
            };
          }
        ];
      };

  # =========================================================================
  # Complex scenarios — multi-feature rulesets resembling real firewalls
  # =========================================================================

  # Two independent tables in one atomic submission.
  testRenderMultiTable =
    pr
      (dsl.ruleset [
        dsl.flush
        (dsl.table "inet" "filter" {
          chains.input = {
            type = "filter";
            hook = "input";
            prio = 0;
            policy = "drop";
            rules = [
              [
                (dsl.inSet dsl.fields.ct.state [ "established" ])
                dsl.accept
              ]
            ];
          };
        })
        (dsl.table "ip" "nat" {
          chains.postrouting = {
            type = "nat";
            hook = "postrouting";
            prio = 100;
            policy = "accept";
            rules = [ [ (dsl.masquerade { }) ] ];
          };
        })
      ])
      {
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
          {
            add = {
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
          }
          {
            add = {
              rule = {
                family = "inet";
                table = "filter";
                chain = "input";
                expr = [
                  {
                    match = {
                      left = {
                        ct = {
                          key = "state";
                        };
                      };
                      right = {
                        set = [ "established" ];
                      };
                      op = "==";
                    };
                  }
                  { accept = null; }
                ];
              };
            };
          }
          {
            add = {
              table = {
                family = "ip";
                name = "nat";
              };
            };
          }
          {
            add = {
              chain = {
                family = "ip";
                table = "nat";
                name = "postrouting";
                type = "nat";
                hook = "postrouting";
                prio = 100;
                policy = "accept";
              };
            };
          }
          {
            add = {
              rule = {
                family = "ip";
                table = "nat";
                chain = "postrouting";
                expr = [ { masquerade = { }; } ];
              };
            };
          }
        ];
      };

  # Netdev-family ingress chain with a `dev` list.
  testRenderNetdevIngress =
    pr
      (dsl.ruleset [
        (dsl.table "netdev" "guard" {
          chains.ingress = {
            type = "filter";
            hook = "ingress";
            prio = -500;
            dev = [
              "eth0"
              "eth1"
            ];
            policy = "drop";
            rules = [
              [
                (dsl.eq dsl.fields.ip.saddr "@blocklist")
                dsl.drop
              ]
            ];
          };
        })
      ])
      {
        nftables = [
          {
            add = {
              table = {
                family = "netdev";
                name = "guard";
              };
            };
          }
          {
            add = {
              chain = {
                family = "netdev";
                table = "guard";
                name = "ingress";
                type = "filter";
                hook = "ingress";
                prio = -500;
                dev = [
                  "eth0"
                  "eth1"
                ];
                policy = "drop";
              };
            };
          }
          {
            add = {
              rule = {
                family = "netdev";
                table = "guard";
                chain = "ingress";
                expr = [
                  {
                    match = {
                      left = {
                        payload = {
                          protocol = "ip";
                          field = "saddr";
                        };
                      };
                      right = "@blocklist";
                      op = "==";
                    };
                  }
                  { drop = null; }
                ];
              };
            };
          }
        ];
      };

  # vmap dispatching to different chains by interface. Exercises the
  # chains-before-objects emission order: the map's verdict elements
  # reference chains `wan` and `lan`, which nftables requires to already
  # exist in the transaction when the map is added.
  testRenderVmapDispatch =
    pr
      (dsl.ruleset [
        (dsl.table "inet" "t" {
          maps.iif_dispatch = {
            type = "ifname";
            map = "verdict";
            elements = [
              [
                "eth0"
                (dsl.jump "wan")
              ]
              [
                "eth1"
                (dsl.jump "lan")
              ]
            ];
          };
          chains.wan = {
            rules = [ [ dsl.accept ] ];
          };
          chains.lan = {
            rules = [ [ dsl.accept ] ];
          };
          chains.input = {
            type = "filter";
            hook = "input";
            prio = 0;
            policy = "drop";
            rules = [ [ (dsl.vmap dsl.fields.meta.iifname "@iif_dispatch") ] ];
          };
        })
      ])
      {
        nftables = [
          {
            add = {
              table = {
                family = "inet";
                name = "t";
              };
            };
          }
          # Chain-adds come first — alphabetical.
          {
            add = {
              chain = {
                family = "inet";
                table = "t";
                name = "input";
                type = "filter";
                hook = "input";
                prio = 0;
                policy = "drop";
              };
            };
          }
          {
            add = {
              chain = {
                family = "inet";
                table = "t";
                name = "lan";
              };
            };
          }
          {
            add = {
              chain = {
                family = "inet";
                table = "t";
                name = "wan";
              };
            };
          }
          # Object-adds next — `wan`/`lan` already exist so verdict elements resolve.
          {
            add = {
              map = {
                family = "inet";
                table = "t";
                name = "iif_dispatch";
                type = "ifname";
                map = "verdict";
                elem = [
                  [
                    "eth0"
                    {
                      jump = {
                        target = "wan";
                      };
                    }
                  ]
                  [
                    "eth1"
                    {
                      jump = {
                        target = "lan";
                      };
                    }
                  ]
                ];
              };
            };
          }
          # Rule-adds last — alphabetical by chain, source order within chain.
          {
            add = {
              rule = {
                family = "inet";
                table = "t";
                chain = "input";
                expr = [
                  {
                    vmap = {
                      key = {
                        meta = {
                          key = "iifname";
                        };
                      };
                      data = "@iif_dispatch";
                    };
                  }
                ];
              };
            };
          }
          {
            add = {
              rule = {
                family = "inet";
                table = "t";
                chain = "lan";
                expr = [ { accept = null; } ];
              };
            };
          }
          {
            add = {
              rule = {
                family = "inet";
                table = "t";
                chain = "wan";
                expr = [ { accept = null; } ];
              };
            };
          }
        ];
      };

  # Flowtable + flow-offload rule: accelerate established connections.
  testRenderFlowOffload =
    pr
      (dsl.ruleset [
        (dsl.table "inet" "t" {
          flowtables.ft = {
            hook = "ingress";
            prio = 0;
            dev = [
              "eth0"
              "eth1"
            ];
          };
          chains.forward = {
            type = "filter";
            hook = "forward";
            prio = 0;
            rules = [
              [
                (dsl.inSet dsl.fields.ct.state [
                  "established"
                  "related"
                ])
                (dsl.flow { flowtable = "@ft"; })
              ]
            ];
          };
        })
      ])
      {
        nftables = [
          {
            add = {
              table = {
                family = "inet";
                name = "t";
              };
            };
          }
          {
            add = {
              chain = {
                family = "inet";
                table = "t";
                name = "forward";
                type = "filter";
                hook = "forward";
                prio = 0;
              };
            };
          }
          {
            add = {
              flowtable = {
                family = "inet";
                table = "t";
                name = "ft";
                hook = "ingress";
                prio = 0;
                dev = [
                  "eth0"
                  "eth1"
                ];
              };
            };
          }
          {
            add = {
              rule = {
                family = "inet";
                table = "t";
                chain = "forward";
                expr = [
                  {
                    match = {
                      left = {
                        ct = {
                          key = "state";
                        };
                      };
                      right = {
                        set = [
                          "established"
                          "related"
                        ];
                      };
                      op = "==";
                    };
                  }
                  {
                    flow = {
                      op = "add";
                      flowtable = "@ft";
                    };
                  }
                ];
              };
            };
          }
        ];
      };

  # Concatenated-key port-forward: (ip daddr . tcp dport) → (ipv4_addr . inet_service).
  # Both the key and value sides are tuple types; elements must wrap each
  # side in `{ concat: [...] }` and `map` must be a list of datatypes (the
  # dot-separated string form is not accepted by the nftables JSON parser).
  testRenderConcatenatedPortForward =
    pr
      (dsl.ruleset [
        (dsl.table "ip" "nat" {
          maps.port_forward = {
            type = [
              "ipv4_addr"
              "inet_service"
            ];
            map = [
              "ipv4_addr"
              "inet_service"
            ];
            flags = [ "interval" ];
            elements = [
              [
                (dsl.expr.concat [
                  "203.0.113.1"
                  80
                ])
                (dsl.expr.concat [
                  "10.0.0.10"
                  8080
                ])
              ]
              [
                (dsl.expr.concat [
                  "203.0.113.1"
                  443
                ])
                (dsl.expr.concat [
                  "10.0.0.10"
                  8443
                ])
              ]
            ];
          };
          chains.prerouting = {
            type = "nat";
            hook = "prerouting";
            prio = -100;
            policy = "accept";
            rules = [
              [
                (dsl.dnat {
                  family = "ip";
                  addr = dsl.expr.map {
                    key = dsl.expr.concat [
                      dsl.fields.ip.daddr
                      dsl.fields.tcp.dport
                    ];
                    data = "@port_forward";
                  };
                })
              ]
            ];
          };
        })
      ])
      {
        nftables = [
          {
            add = {
              table = {
                family = "ip";
                name = "nat";
              };
            };
          }
          {
            add = {
              chain = {
                family = "ip";
                table = "nat";
                name = "prerouting";
                type = "nat";
                hook = "prerouting";
                prio = -100;
                policy = "accept";
              };
            };
          }
          {
            add = {
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
                elem = [
                  [
                    {
                      concat = [
                        "203.0.113.1"
                        80
                      ];
                    }
                    {
                      concat = [
                        "10.0.0.10"
                        8080
                      ];
                    }
                  ]
                  [
                    {
                      concat = [
                        "203.0.113.1"
                        443
                      ];
                    }
                    {
                      concat = [
                        "10.0.0.10"
                        8443
                      ];
                    }
                  ]
                ];
              };
            };
          }
          {
            add = {
              rule = {
                family = "ip";
                table = "nat";
                chain = "prerouting";
                expr = [
                  {
                    dnat = {
                      family = "ip";
                      addr = {
                        map = {
                          key = {
                            concat = [
                              {
                                payload = {
                                  protocol = "ip";
                                  field = "daddr";
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
                          data = "@port_forward";
                        };
                      };
                    };
                  }
                ];
              };
            };
          }
        ];
      };

  # Rule with anonymous set in match (no @name indirection).
  testRenderInlineSetMatch =
    pr
      (dsl.ruleset [
        (dsl.table "inet" "t" {
          chains.input = {
            rules = [
              [
                (dsl.inSet dsl.fields.tcp.dport [
                  22
                  80
                  443
                ])
                dsl.accept
              ]
            ];
          };
        })
      ])
      {
        nftables = [
          {
            add = {
              table = {
                family = "inet";
                name = "t";
              };
            };
          }
          {
            add = {
              chain = {
                family = "inet";
                table = "t";
                name = "input";
              };
            };
          }
          {
            add = {
              rule = {
                family = "inet";
                table = "t";
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
                      right = {
                        set = [
                          22
                          80
                          443
                        ];
                      };
                      op = "==";
                    };
                  }
                  { accept = null; }
                ];
              };
            };
          }
        ];
      };

  # Full base-chain coverage: all five inet hooks in one table.
  testRenderAllInetHooks =
    pr
      (dsl.ruleset [
        (dsl.table "inet" "t" {
          chains.prerouting = {
            type = "filter";
            hook = "prerouting";
            prio = 0;
            rules = [ [ dsl.accept ] ];
          };
          chains.input = {
            type = "filter";
            hook = "input";
            prio = 0;
            rules = [ [ dsl.accept ] ];
          };
          chains.forward = {
            type = "filter";
            hook = "forward";
            prio = 0;
            rules = [ [ dsl.accept ] ];
          };
          chains.output = {
            type = "filter";
            hook = "output";
            prio = 0;
            rules = [ [ dsl.accept ] ];
          };
          chains.postrouting = {
            type = "filter";
            hook = "postrouting";
            prio = 0;
            rules = [ [ dsl.accept ] ];
          };
        })
      ])
      {
        # Expected order: alphabetical chain-adds, then alphabetical rule-adds.
        nftables = [
          {
            add = {
              table = {
                family = "inet";
                name = "t";
              };
            };
          }
          {
            add = {
              chain = {
                family = "inet";
                table = "t";
                name = "forward";
                type = "filter";
                hook = "forward";
                prio = 0;
              };
            };
          }
          {
            add = {
              chain = {
                family = "inet";
                table = "t";
                name = "input";
                type = "filter";
                hook = "input";
                prio = 0;
              };
            };
          }
          {
            add = {
              chain = {
                family = "inet";
                table = "t";
                name = "output";
                type = "filter";
                hook = "output";
                prio = 0;
              };
            };
          }
          {
            add = {
              chain = {
                family = "inet";
                table = "t";
                name = "postrouting";
                type = "filter";
                hook = "postrouting";
                prio = 0;
              };
            };
          }
          {
            add = {
              chain = {
                family = "inet";
                table = "t";
                name = "prerouting";
                type = "filter";
                hook = "prerouting";
                prio = 0;
              };
            };
          }
          {
            add = {
              rule = {
                family = "inet";
                table = "t";
                chain = "forward";
                expr = [ { accept = null; } ];
              };
            };
          }
          {
            add = {
              rule = {
                family = "inet";
                table = "t";
                chain = "input";
                expr = [ { accept = null; } ];
              };
            };
          }
          {
            add = {
              rule = {
                family = "inet";
                table = "t";
                chain = "output";
                expr = [ { accept = null; } ];
              };
            };
          }
          {
            add = {
              rule = {
                family = "inet";
                table = "t";
                chain = "postrouting";
                expr = [ { accept = null; } ];
              };
            };
          }
          {
            add = {
              rule = {
                family = "inet";
                table = "t";
                chain = "prerouting";
                expr = [ { accept = null; } ];
              };
            };
          }
        ];
      };

  # Realistic multi-statement rule: log + rate-limit + reject with icmpx code.
  testRenderLogRejectRule =
    pr
      (dsl.ruleset [
        (dsl.table "inet" "t" {
          chains.input = {
            type = "filter";
            hook = "input";
            prio = 0;
            policy = "drop";
            rules = [
              [
                (dsl.log {
                  prefix = "DROP: ";
                  level = "info";
                })
                (dsl.limit {
                  rate = 5;
                  per = "second";
                  burst = 10;
                })
                (dsl.reject.icmpx "admin-prohibited")
              ]
            ];
          };
        })
      ])
      {
        nftables = [
          {
            add = {
              table = {
                family = "inet";
                name = "t";
              };
            };
          }
          {
            add = {
              chain = {
                family = "inet";
                table = "t";
                name = "input";
                type = "filter";
                hook = "input";
                prio = 0;
                policy = "drop";
              };
            };
          }
          {
            add = {
              rule = {
                family = "inet";
                table = "t";
                chain = "input";
                expr = [
                  {
                    log = {
                      prefix = "DROP: ";
                      level = "info";
                    };
                  }
                  {
                    limit = {
                      rate = 5;
                      per = "second";
                      burst = 10;
                    };
                  }
                  {
                    reject = {
                      type = "icmpx";
                      expr = "admin-prohibited";
                    };
                  }
                ];
              };
            };
          }
        ];
      };

  # =========================================================================
  # End-to-end: DSL example is schema-valid and renders non-empty JSON
  # =========================================================================
  # Byte-parity with basic-firewall.nix is not meaningful because the DSL
  # renderer emits chains alphabetically (input, postrouting, prerouting)
  # and object kinds alphabetically, while the raw example uses a different
  # order. Both submissions are semantically identical to nftables.

  testDslExampleValidates = {
    expr = builtins.isString (
      roundtrip nftlib.types.ruleset (import ../examples/basic-firewall-dsl.nix { inherit nftlib; })
    );
    expected = true;
  };

  # Larger example exercising: two tables, three set flag combinations
  # (interval, interval+timeout, dynamic+timeout), named counters + limits
  # referenced by name, flowtable + flow statement, verdict map dispatch,
  # five base chains plus two regular sub-chains, concat-key port-forward
  # via map lookup in DNAT, masquerade. Schema-validates.
  testDslHomeRouterValidates = {
    expr = builtins.isString (
      roundtrip nftlib.types.ruleset (import ../examples/home-router-dsl.nix { inherit nftlib; })
    );
    expected = true;
  };

  # =========================================================================
  # Non-add commands: create / delete / destroy / list / rename / reset,
  # plus replace / insert (rule-only) and the flush variants.
  # =========================================================================

  testCmdCreateTable =
    pc
      (dsl.create.table {
        family = "ip";
        name = "t";
      })
      {
        create = {
          table = {
            family = "ip";
            name = "t";
          };
        };
      };
  testCmdCreateCounter =
    pc
      (dsl.create.counter {
        family = "ip";
        table = "t";
        name = "c";
      })
      {
        create = {
          counter = {
            family = "ip";
            table = "t";
            name = "c";
          };
        };
      };
  testCmdCreateCtHelper =
    pc
      (dsl.create.ctHelper {
        family = "ip";
        table = "t";
        name = "h";
        type = "ftp";
        protocol = "tcp";
      })
      {
        create = {
          "ct helper" = {
            family = "ip";
            table = "t";
            name = "h";
            type = "ftp";
            protocol = "tcp";
          };
        };
      };

  # Note: the schema's `setObjectBody` / `mapObjectBody` / `limitObjectBody`
  # etc. require certain fields (`type`, `rate`/`per`, …) that nftables
  # doesn't actually need for delete/destroy by name. Tests here provide
  # full bodies to satisfy the schema; see lib/schema/objects.nix.
  testCmdDeleteSet =
    pc
      (dsl.delete.set {
        family = "inet";
        table = "t";
        name = "blocked";
        type = "ipv4_addr";
      })
      {
        delete = {
          set = {
            family = "inet";
            table = "t";
            name = "blocked";
            type = "ipv4_addr";
          };
        };
      };
  testCmdDeleteChain =
    pc
      (dsl.delete.chain {
        family = "ip";
        table = "t";
        name = "c";
      })
      {
        delete = {
          chain = {
            family = "ip";
            table = "t";
            name = "c";
          };
        };
      };

  testCmdDestroyTable =
    pc
      (dsl.destroy.table {
        family = "ip";
        name = "old";
      })
      {
        destroy = {
          table = {
            family = "ip";
            name = "old";
          };
        };
      };
  testCmdDestroyQuota =
    pc
      (dsl.destroy.quota {
        family = "ip";
        table = "t";
        name = "q";
      })
      {
        destroy = {
          quota = {
            family = "ip";
            table = "t";
            name = "q";
          };
        };
      };

  testCmdListTable =
    pc
      (dsl.list.table {
        family = "inet";
        name = "filter";
      })
      {
        list = {
          table = {
            family = "inet";
            name = "filter";
          };
        };
      };
  testCmdListMetainfo =
    pc
      (dsl.list.metainfo {
        version = "1.1.6";
        release_name = "Commodore Bullmoose";
        json_schema_version = 1;
      })
      {
        list = {
          metainfo = {
            version = "1.1.6";
            release_name = "Commodore Bullmoose";
            json_schema_version = 1;
          };
        };
      };

  # rename wraps its chain body in an inner `chain` tag, matching the
  # nftables JSON parser. Namespaced for API symmetry with create/delete.
  testCmdRenameChain =
    pc
      (dsl.rename.chain {
        family = "ip";
        table = "t";
        name = "old";
        newname = "new";
      })
      {
        rename = {
          chain = {
            family = "ip";
            table = "t";
            name = "old";
            newname = "new";
          };
        };
      };

  # reset has two forms under one name: statement (via __functor) and
  # per-object-kind command sub-attrs.
  testCmdResetStatement = ps (dsl.reset (dsl.expr.tcpOption { name = "sack-perm"; })) {
    reset = {
      "tcp option" = {
        name = "sack-perm";
      };
    };
  };
  testCmdResetCounter =
    pc
      (dsl.reset.counter {
        family = "ip";
        table = "t";
        name = "c";
      })
      {
        reset = {
          counter = {
            family = "ip";
            table = "t";
            name = "c";
          };
        };
      };
  testCmdResetRule =
    pc
      (dsl.reset.rule {
        family = "ip";
        table = "t";
        chain = "c";
        handle = 42;
        expr = [ { accept = null; } ];
      })
      {
        reset = {
          rule = {
            family = "ip";
            table = "t";
            chain = "c";
            handle = 42;
            expr = [ { accept = null; } ];
          };
        };
      };

  # replace / insert wrap the rule body in an inner `rule` tag — matches
  # what the nftables JSON parser expects.
  testCmdReplace =
    pc
      (dsl.replace {
        family = "ip";
        table = "t";
        chain = "c";
        handle = 42;
        expr = [ { accept = null; } ];
      })
      {
        replace = {
          rule = {
            family = "ip";
            table = "t";
            chain = "c";
            handle = 42;
            expr = [ { accept = null; } ];
          };
        };
      };
  testCmdInsert =
    pc
      (dsl.insert {
        family = "ip";
        table = "t";
        chain = "c";
        index = 0;
        expr = [ { drop = null; } ];
      })
      {
        insert = {
          rule = {
            family = "ip";
            table = "t";
            chain = "c";
            index = 0;
            expr = [ { drop = null; } ];
          };
        };
      };

  # Flush variants — body-taking siblings (bare `flush` stays a value).
  # Note: `set`/`map` bodies still require `type` (and `map`) per the
  # shared schema, even for flush-by-name.
  testCmdFlushBare = pc dsl.flush {
    flush = {
      ruleset = null;
    };
  };
  testCmdFlushRuleset = pc (dsl.flushRuleset { family = "ip"; }) {
    flush = {
      ruleset = {
        family = "ip";
      };
    };
  };
  testCmdFlushTable =
    pc
      (dsl.flushTable {
        family = "inet";
        name = "filter";
      })
      {
        flush = {
          table = {
            family = "inet";
            name = "filter";
          };
        };
      };
  testCmdFlushChain =
    pc
      (dsl.flushChain {
        family = "inet";
        table = "t";
        name = "input";
      })
      {
        flush = {
          chain = {
            family = "inet";
            table = "t";
            name = "input";
          };
        };
      };
  testCmdFlushSet =
    pc
      (dsl.flushSet {
        family = "inet";
        table = "t";
        name = "trusted";
        type = "ipv4_addr";
      })
      {
        flush = {
          set = {
            family = "inet";
            table = "t";
            name = "trusted";
            type = "ipv4_addr";
          };
        };
      };
  testCmdFlushMap =
    pc
      (dsl.flushMap {
        family = "ip";
        table = "nat";
        name = "port_forward";
        type = "inet_service";
        map = "inet_service";
      })
      {
        flush = {
          map = {
            family = "ip";
            table = "nat";
            name = "port_forward";
            type = "inet_service";
            map = "inet_service";
          };
        };
      };
  # `flushFlowtable` is intentionally omitted from both DSL and schema —
  # the nftables parser rejects `flush flowtable` with "Unknown object
  # passed to flush command". See lib/dsl/structure/ruleset.nix for the
  # rationale.

  testCmdFlushMeter =
    pc
      (dsl.flushMeter {
        family = "inet";
        table = "filter";
        name = "rate_meter";
      })
      {
        flush = {
          meter = {
            family = "inet";
            table = "filter";
            name = "rate_meter";
          };
        };
      };

  testCmdListMeter =
    pc
      (dsl.list.meter {
        family = "inet";
        table = "filter";
        name = "rate_meter";
      })
      {
        list = {
          meter = {
            family = "inet";
            table = "filter";
            name = "rate_meter";
          };
        };
      };

  # Full ruleset integration: several new command kinds mixed together.
  testCmdRulesetIntegration =
    pr
      (dsl.ruleset [
        dsl.flush
        (dsl.create.table {
          family = "ip";
          name = "t";
        })
        (dsl.rename.chain {
          family = "ip";
          table = "t";
          name = "oldchain";
          newname = "newchain";
        })
        (dsl.replace {
          family = "ip";
          table = "t";
          chain = "c";
          handle = 7;
          expr = [ { accept = null; } ];
        })
        (dsl.reset.counter {
          family = "ip";
          table = "t";
          name = "c";
        })
        (dsl.destroy.set {
          family = "ip";
          table = "t";
          name = "stale";
          type = "ipv4_addr";
        })
      ])
      {
        nftables = [
          {
            flush = {
              ruleset = null;
            };
          }
          {
            create = {
              table = {
                family = "ip";
                name = "t";
              };
            };
          }
          {
            rename = {
              chain = {
                family = "ip";
                table = "t";
                name = "oldchain";
                newname = "newchain";
              };
            };
          }
          {
            replace = {
              rule = {
                family = "ip";
                table = "t";
                chain = "c";
                handle = 7;
                expr = [ { accept = null; } ];
              };
            };
          }
          {
            reset = {
              counter = {
                family = "ip";
                table = "t";
                name = "c";
              };
            };
          }
          {
            destroy = {
              set = {
                family = "ip";
                table = "t";
                name = "stale";
                type = "ipv4_addr";
              };
            };
          }
        ];
      };
}
