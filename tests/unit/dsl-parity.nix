{
  fixtures,
  helpers,
  lib,
  nftlib,
  ...
}:

# Parity tests for the `dsl` layer. Each test asserts that a DSL value
# renders to the same JSON as a hand-written attrset, going through the same
# evalModules type-check. That proves the DSL is pure sugar: the field
# trees, operators, variant namespaces, and declarative table structure all
# collapse to attrsets the schema already accepts.

let
  inherit (helpers) roundtrip;
  inherit (nftlib) dsl toJson;

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
  testFieldIcmpv6Mtu = pe dsl.fields.icmpv6.mtu {
    payload = {
      protocol = "icmpv6";
      field = "mtu";
    };
  };
  testFieldIcmpv6ParamProblem = pe dsl.fields.icmpv6.paramProblem {
    payload = {
      protocol = "icmpv6";
      field = "parameter-problem";
    };
  };
  testFieldUdpliteCsumcov = pe dsl.fields.udplite.csumcov {
    payload = {
      protocol = "udplite";
      field = "csumcov";
    };
  };
  testFieldArpSaddrEther = pe dsl.fields.arp.saddrEther {
    payload = {
      protocol = "arp";
      field = "saddr ether";
    };
  };
  testFieldArpSaddrIp = pe dsl.fields.arp.saddrIp {
    payload = {
      protocol = "arp";
      field = "saddr ip";
    };
  };
  testFieldArpDaddrEther = pe dsl.fields.arp.daddrEther {
    payload = {
      protocol = "arp";
      field = "daddr ether";
    };
  };
  testFieldArpDaddrIp = pe dsl.fields.arp.daddrIp {
    payload = {
      protocol = "arp";
      field = "daddr ip";
    };
  };
  # Leaves nft has no field or key for.
  testFieldLeavesNftLacks = {
    expr = lib.filter (path: lib.hasAttrByPath path dsl.fields) [
      [
        "arp"
        "saddr"
      ]
      [
        "arp"
        "daddr"
      ]
      [
        "ct"
        "count"
      ]
      [
        "icmpv6"
        "packetTooBig"
      ]
      [
        "udplite"
        "cksumcov"
      ]
    ];
    expected = [ ];
  };
  # Keys nft loads only with a refinement a leaf can't carry: a fib result
  # needs `saddr` or `daddr` among its flags, and these ct and ipsec keys
  # need a `dir`. They are built with `expr.fib`, `expr.ct`, and
  # `expr.ipsec`.
  testFieldLeavesNftRejectsBare = {
    expr = lib.filter (path: lib.hasAttrByPath path dsl.fields) (
      map (lib.splitString ".") [
        "ct.daddr"
        "ct.protoDst"
        "ct.protoSrc"
        "ct.saddr"
        "fib.check"
        "fib.oif"
        "fib.oifname"
        "fib.type"
        "ipsec.daddr"
        "ipsec.reqid"
        "ipsec.saddr"
        "ipsec.spi"
      ]
    );
    expected = [ ];
  };
  # Every leaf name is camelCase (ADR 0009), with no JSON spelling beside
  # it: `ip.fragOff`, not `ip.frag-off`.
  testFieldLeavesAreCamelCase = {
    expr = lib.concatLists (
      lib.mapAttrsToList (
        group: leaves:
        map (leaf: "${group}.${leaf}") (
          builtins.filter (leaf: builtins.match "[a-z][A-Za-z0-9]*" leaf == null) (builtins.attrNames leaves)
        )
      ) dsl.fields
    );
    expected = [ ];
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

  # -- Field trees — meta / ct / rt / socket / osf / tunnelMeta ------------

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
  testFieldTunnelMetaId = pe dsl.fields.tunnelMeta.id {
    tunnel = {
      key = "id";
    };
  };

  # =========================================================================
  # Escape hatches
  # =========================================================================

  testPayloadEscape = pe (dsl.expr.payload "tcp" "dport") {
    payload = {
      protocol = "tcp";
      field = "dport";
    };
  };

  testPayloadRaw =
    pe
      (dsl.expr.payloadRaw {
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
      (dsl.expr.payloadTunnel {
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

  # Named-set reference: the name with or without its `@` becomes the
  # reference string `"@<name>"`, the shape `expr.mapRef` returns and nft
  # lists.
  testExprSetRef = ps (dsl.eq dsl.fields.ip.saddr (dsl.expr.setRef "trusted_v4")) {
    match = {
      op = "==";
      left.payload = {
        protocol = "ip";
        field = "saddr";
      };
      right = "@trusted_v4";
    };
  };
  testExprSetRefIdempotent = {
    expr = map dsl.expr.setRef [ "@trusted_v4" ];
    expected = [ "@trusted_v4" ];
  };

  # `expr.set <bare-string>` is a footgun (silently rendered to invalid
  # nftables); the constructor throws and points at `setRef`.
  testExprSetStringRejected = {
    expr = dsl.expr.set "trusted_v4";
    expectedError.msg = "expr\\.set: a bare string";
  };

  # `expr.set` on an actual list still works — anonymous-set path unchanged.
  testExprSetListStillWorks = pe (dsl.expr.set [ "1.2.3.4" ]) {
    set = [ "1.2.3.4" ];
  };

  testExprMap = pe (dsl.expr.map dsl.fields.tcp.dport "@pf") {
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

  # A named map reference is the `"@<name>"` string a map lookup or a
  # verdict map takes as its data, with or without the `@` given.
  testExprMapRef = pe (dsl.expr.map dsl.fields.tcp.dport (dsl.expr.mapRef "pf")) {
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
  # A map lookup's data names a map: a bare name gets its `@`, which nft's
  # JSON parser needs (it reads `"pf"` as a hostname).
  testExprMapBareName = pe (dsl.expr.map dsl.fields.tcp.dport "pf") {
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
  testExprMapRefIdempotent = {
    expr = map dsl.expr.mapRef [
      "pf"
      "@pf"
    ];
    expected = [
      "@pf"
      "@pf"
    ];
  };
  testExprMapRefRejectsNonString = {
    expr = dsl.expr.mapRef 42;
    expectedError.msg = "expr\\.mapRef: expected a name string";
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
        offset = 100;
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
          offset = 100;
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

  testExprMeta = pe (dsl.expr.meta "mark") {
    meta = {
      key = "mark";
    };
  };

  testExprSocket = pe (dsl.expr.socket "mark") {
    socket = {
      key = "mark";
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
        spnum = 2;
      })
      {
        ipsec = {
          key = "saddr";
          family = "ip";
          dir = "in";
          spnum = 2;
        };
      };

  testExprElem =
    pe
      (dsl.expr.elem {
        val = "10.0.0.1";
        timeout = 60;
        expires = 45;
        comment = "seen";
      })
      {
        elem = {
          val = "10.0.0.1";
          timeout = 60;
          expires = 45;
          comment = "seen";
        };
      };

  # Unset options don't appear in the rendered shape: the DSL `compact`
  # helper drops null-valued attrs before wrapping.
  testExprElemOmitsUnsetOptions = {
    expr = toJson (
      dsl.expr.elem {
        val = "1.2.3.4";
        timeout = 60;
      }
    );
    expected = ''{"elem":{"timeout":60,"val":"1.2.3.4"}}'';
  };

  # nft's JSON parser ignores element statements, so `expr.elem` takes
  # none.
  testExprElemTakesNoStatement = {
    expr = dsl.expr.elem {
      val = "1.2.3.4";
      stmt = [ { counter = null; } ];
    };
    expectedError.msg = "unexpected argument 'stmt'";
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
  testOpNe = ps (dsl.ne dsl.fields.meta.mark 2) {
    match = {
      left.meta.key = "mark";
      right = 2;
      op = "!=";
    };
  };
  testOpLt = ps (dsl.lt dsl.fields.meta.mark 2) {
    match = {
      left.meta.key = "mark";
      right = 2;
      op = "<";
    };
  };
  testOpGt = ps (dsl.gt dsl.fields.meta.mark 2) {
    match = {
      left.meta.key = "mark";
      right = 2;
      op = ">";
    };
  };
  testOpLe = ps (dsl.le dsl.fields.meta.mark 2) {
    match = {
      left.meta.key = "mark";
      right = 2;
      op = "<=";
    };
  };
  testOpGe = ps (dsl.ge dsl.fields.meta.mark 2) {
    match = {
      left.meta.key = "mark";
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
  # nft parses an inline counter only with both fields, so the empty and
  # one-field forms throw and point to `counter.auto`.
  testCounterEmptyBodyThrows = {
    expr = dsl.counter { };
    expectedError.msg = "counter: .*packets.*bytes.*counter\\.auto";
  };
  testCounterPacketsOnlyThrows = {
    expr = dsl.counter { packets = 5; };
    expectedError.msg = "counter: .*packets.*bytes.*counter\\.auto";
  };
  testCounterBytesOnlyThrows = {
    expr = dsl.counter { bytes = 5; };
    expectedError.msg = "counter: .*packets.*bytes.*counter\\.auto";
  };

  # `x { }` is the empty form, so no statement builder carries a `.plain`
  # alias for it.
  testNoPlainVariants = {
    expr = builtins.filter (name: dsl.${name} ? plain) [
      "log"
      "masquerade"
      "queue"
      "redirect"
      "reject"
    ];
    expected = [ ];
  };
  testCounterRef = ps (dsl.counter.ref "pkts") { counter = "pkts"; };

  # reject — base, empty body, .icmp, .icmpv6, .icmpx, .tcpReset
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
  testRejectEmptyBody = ps (dsl.reject { }) { reject = { }; };
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

  # log — base, empty body, camelCase rename
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
  testLogEmptyBody = ps (dsl.log { }) { log = { }; };
  # nft takes a log prefix of up to 127 bytes.
  testLogPrefixMaxLength =
    let
      prefix = lib.concatStrings (lib.replicate 127 "a");
    in
    ps (dsl.log { inherit prefix; }) { log = { inherit prefix; }; };
  testLogQueueThreshold = ps (dsl.log { queueThreshold = 50; }) {
    log = {
      "queue-threshold" = 50;
    };
  };
  testLogGroupSnaplen =
    ps
      (dsl.log {
        group = 2;
        snaplen = 64;
      })
      {
        log = {
          group = 2;
          snaplen = 64;
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
  testLimitUnitsCamelCase =
    ps
      (dsl.limit {
        rate = 10;
        per = "second";
        rateUnit = "kbytes";
        burst = 5;
        burstUnit = "bytes";
      })
      {
        limit = {
          rate = 10;
          per = "second";
          rate_unit = "kbytes";
          burst = 5;
          burst_unit = "bytes";
        };
      };
  # `inv` matches over the rate.
  testLimitInv =
    ps
      (dsl.limit {
        rate = 10;
        per = "second";
        inv = true;
      })
      {
        limit = {
          rate = 10;
          per = "second";
          inv = true;
        };
      };
  testLimitRef = ps (dsl.limit.ref "lim") { limit = "lim"; };
  testQuotaBase =
    ps
      (dsl.quota {
        val = 1000;
        valUnit = "mbytes";
        used = 10;
        usedUnit = "kbytes";
      })
      {
        quota = {
          val = 1000;
          val_unit = "mbytes";
          used = 10;
          used_unit = "kbytes";
        };
      };
  # `inv` matches once the quota is used up.
  testQuotaInv =
    ps
      (dsl.quota {
        val = 1000;
        inv = true;
      })
      {
        quota = {
          val = 1000;
          inv = true;
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
  testSnatFlags =
    ps
      (dsl.snat {
        addr = "192.0.2.1";
        family = "ip";
        flags = [
          "random"
          "persistent"
        ];
      })
      {
        snat = {
          addr = "192.0.2.1";
          family = "ip";
          flags = [
            "random"
            "persistent"
          ];
        };
      };
  testSnatTypeFlags =
    ps
      (dsl.snat {
        addr = "192.0.2.1";
        family = "ip";
        typeFlags = [ "interval" ];
      })
      {
        snat = {
          addr = "192.0.2.1";
          family = "ip";
          type_flags = [ "interval" ];
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
  testMasqueradeEmptyBody = ps (dsl.masquerade { }) { masquerade = { }; };
  testRedirectBase = ps (dsl.redirect { port = 8080; }) {
    redirect = {
      port = 8080;
    };
  };
  testRedirectEmptyBody = ps (dsl.redirect { }) { redirect = { }; };
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
  testQueueEmptyBody = ps (dsl.queue { }) { queue = { }; };

  # ct set/count statements
  testCtHelper = ps (dsl.ctHelper.ref "ftp") { "ct helper" = "ftp"; };
  testCtTimeout = ps (dsl.ctTimeout.ref "fast_tcp") { "ct timeout" = "fast_tcp"; };
  testCtExpectation = ps (dsl.ctExpectation.ref "e1") { "ct expectation" = "e1"; };
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

  testCtCountRef = ps (dsl.ctCount.ref "c1") { "ct count" = "c1"; };
  # `.ref` also takes a map expression that selects the object by key.
  testCtCountRefMap = ps (dsl.ctCount.ref (dsl.expr.map { meta.key = "mark"; } "@limits")) {
    "ct count".map = {
      key.meta.key = "mark";
      data = "@limits";
    };
  };

  # A stateful object reference takes the name with or without its `@` and
  # emits the bare name, which nft's JSON parser looks up: `{ counter =
  # "@pkts"; }` fails with "No such file or directory".
  testCounterRefAtName = ps (dsl.counter.ref "@pkts") { counter = "pkts"; };
  testQuotaRefAtName = ps (dsl.quota.ref "@q1") { quota = "q1"; };
  testLimitRefAtName = ps (dsl.limit.ref "@lim") { limit = "lim"; };
  testSynproxyRefAtName = ps (dsl.synproxy.ref "@sp1") { synproxy = "sp1"; };
  testCtCountRefAtName = ps (dsl.ctCount.ref "@c1") { "ct count" = "c1"; };
  testCtHelperAtName = ps (dsl.ctHelper.ref "@ftp") { "ct helper" = "ftp"; };
  testCtTimeoutAtName = ps (dsl.ctTimeout.ref "@fast_tcp") { "ct timeout" = "fast_tcp"; };
  testCtExpectationAtName = ps (dsl.ctExpectation.ref "@e1") { "ct expectation" = "e1"; };
  testSecmarkAtName = ps (dsl.secmark.ref "@my_secmark") { secmark = "my_secmark"; };
  testTunnelStmtAtName = ps (dsl.tunnel.ref "@my_tunnel") { tunnel = "my_tunnel"; };

  # A reference is a name or a map expression; anything else throws,
  # naming the builder.
  testObjectReferencesRejectOtherValues = {
    expr = dsl.counter.ref 42;
    expectedError.msg = "nix-nftypes: dsl\\.counter\\.ref: expected an object name or a map expression, got int";
  };
  testObjectReferencesRejectAtAlone = {
    expr = dsl.ctHelper.ref "@";
    expectedError.msg = "nix-nftypes: dsl\\.ctHelper\\.ref: expected an object name";
  };

  # Every stateful statement that names an object does so through
  # `.ref`; one with no inline form throws when called, pointing there.
  testObjectReferenceStatementsUseRef = {
    expr = builtins.filter (name: !(dsl.${name} ? ref)) [
      "counter"
      "ctCount"
      "ctExpectation"
      "ctHelper"
      "ctTimeout"
      "limit"
      "quota"
      "secmark"
      "synproxy"
      "tunnel"
    ];
    expected = [ ];
  };
  testCtHelperWithoutRefThrows = {
    expr = dsl.ctHelper "ftp";
    expectedError.msg = "nix-nftypes: dsl\\.ctHelper: .*ctHelper\\.ref";
  };

  # flow / meter / vmap
  testFlow = ps (dsl.flow { flowtable = "@ft"; }) {
    flow = {
      op = "add";
      flowtable = "@ft";
    };
  };
  # A set, map or flow statement takes its reference with or without
  # the `@`, like `expr.setRef`.
  testFlowBareName = ps (dsl.flow { flowtable = "ft"; }) {
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
  testVmapBareName = ps (dsl.vmap dsl.fields.meta.iifname "v") {
    vmap = {
      key = {
        meta = {
          key = "iifname";
        };
      };
      data = "@v";
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
  # `stmt` holds statements that run per element, such as a counter.
  testSetStmtStatements =
    ps
      (dsl.setStmt {
        op = "update";
        elem = dsl.fields.ip.saddr;
        set = "@blocked";
        stmt = [ dsl.counter.auto ];
      })
      {
        set = {
          op = "update";
          elem = {
            payload = {
              protocol = "ip";
              field = "saddr";
            };
          };
          set = "@blocked";
          stmt = [ { counter = null; } ];
        };
      };
  testMapStmtStatements =
    ps
      (dsl.mapStmt {
        op = "update";
        elem = dsl.fields.ip.saddr;
        data = 42;
        map = "@cache";
        stmt = [ dsl.counter.auto ];
      })
      {
        map = {
          op = "update";
          elem = {
            payload = {
              protocol = "ip";
              field = "saddr";
            };
          };
          data = 42;
          map = "@cache";
          stmt = [ { counter = null; } ];
        };
      };
  testSetStmtBareName =
    ps
      (dsl.setStmt {
        op = "add";
        elem = "10.0.0.1";
        set = "blocked";
      })
      {
        set = {
          op = "add";
          elem = "10.0.0.1";
          set = "@blocked";
        };
      };
  testMapStmtBareName =
    ps
      (dsl.mapStmt {
        op = "update";
        elem = "10.0.0.1";
        data = 42;
        map = "cache";
      })
      {
        map = {
          op = "update";
          elem = "10.0.0.1";
          data = 42;
          map = "@cache";
        };
      };
  testStatementReferencesRejectNonString = {
    expr = dsl.setStmt {
      op = "add";
      elem = "10.0.0.1";
      set = dsl.expr.set [ "blocked" ];
    };
    expectedError.msg = "setStmt: expected a name string, got set";
  };
  testSecmark = ps (dsl.secmark.ref "my_secmark") { secmark = "my_secmark"; };
  testTunnelStmt = ps (dsl.tunnel.ref "my_tunnel") { tunnel = "my_tunnel"; };
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
        (dsl.flush.ruleset { })
        (dsl.table "inet" "t" {
          handle = 5;
          flags = [ "dormant" ];
          comment = "demo";
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
                name = "t";
                handle = 5;
                flags = [ "dormant" ];
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

  # A standalone element command depends on its set. The tree expander must
  # emit the set before the element even though `elements` sorts before `sets`.
  testRenderStandaloneElementsAfterSet =
    pr
      (dsl.ruleset [
        (dsl.table "inet" "t" {
          sets.blocked = {
            type = "ipv4_addr";
          };
          elements.blocked = {
            elements = [ "192.0.2.1" ];
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
                name = "blocked";
                type = "ipv4_addr";
              };
            };
          }
          {
            add = {
              element = {
                family = "inet";
                table = "t";
                name = "blocked";
                elem = [ "192.0.2.1" ];
              };
            };
          }
        ];
      };

  # Set with camelCase-aliased autoMerge (→ "auto-merge").
  testRenderSetAutoMerge =
    pr
      (dsl.ruleset [
        (dsl.table "inet" "t" {
          sets.ranges = {
            type = "ipv4_addr";
            flags = [ "interval" ];
            autoMerge = true;
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
                name = "ranges";
                type = "ipv4_addr";
                flags = [ "interval" ];
                "auto-merge" = true;
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
            flags = [ "timeout" ];
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
                flags = [ "timeout" ];
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

  # Rule attrset form (with a comment).
  testRenderRuleAttrset =
    pr
      (dsl.ruleset [
        (dsl.table "inet" "t" {
          chains.c = {
            rules = [
              {
                expr = [ dsl.accept ];
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
                comment = "the rule";
              };
            };
          }
        ];
      };

  # Mixing raw commands with table nodes.
  testRenderMixRawAndTable =
    pr
      (dsl.ruleset [
        (dsl.flush.ruleset { })
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
          ctCounts.cc = {
            val = 5;
            inv = true;
          };
          limits.lim = {
            rate = 10;
            per = "second";
            rateUnit = "kbytes";
            burst = 5;
            burstUnit = "bytes";
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
              limit = {
                family = "inet";
                table = "t";
                name = "lim";
                rate = 10;
                per = "second";
                rate_unit = "kbytes";
                burst = 5;
                burst_unit = "bytes";
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
          {
            add = {
              "ct count" = {
                family = "inet";
                table = "t";
                name = "cc";
                val = 5;
                inv = true;
              };
            };
          }
        ];
      };

  # Expansion adds stateful objects before sets and maps, whose elements
  # can name them (an object map), and standalone elements last. A map of
  # quotas added before its quotas fails to load as JSON or imperative text.
  testExpansionOrdersObjectKinds = {
    expr =
      map
        (
          command:
          let
            kind = builtins.head (builtins.attrNames command.add);
          in
          "${kind} ${command.add.${kind}.name or command.add.${kind}.chain}"
        )
        (builtins.fromJSON (
          toJson (
            dsl.ruleset [
              (dsl.table "inet" "t" {
                chains.input.rules = [ [ dsl.accept ] ];
                counters.c = { };
                ctCounts.cc.val = 5;
                ctExpectations.ce = {
                  protocol = "tcp";
                  l3proto = "ip";
                  dport = 21;
                  timeout = 1000;
                  size = 1;
                };
                ctHelpers.ch = {
                  type = "ftp";
                  protocol = "tcp";
                };
                ctTimeouts.ct = {
                  protocol = "tcp";
                  policy.established = 300;
                };
                elements.s.elem = [ "192.0.2.2" ];
                flowtables.f = {
                  hook = "ingress";
                  prio = 0;
                };
                limits.l = {
                  rate = 10;
                  per = "second";
                };
                maps.m = {
                  type = "ipv4_addr";
                  map = "quota";
                  elements = [
                    [
                      "192.0.2.1"
                      "q"
                    ]
                  ];
                };
                quotas.q.bytes = 1000;
                secmarks.sm.context = "u:r:t:s0";
                sets.s.type = "ipv4_addr";
                synproxies.sp = {
                  mss = 1460;
                  wscale = 7;
                };
              })
            ]
          )
        )).nftables;
    expected = [
      "table t"
      "chain input"
      "counter c"
      "quota q"
      "limit l"
      "ct helper ch"
      "ct timeout ct"
      "ct expectation ce"
      "secmark sm"
      "synproxy sp"
      "ct count cc"
      "flowtable f"
      "map m"
      "set s"
      "element s"
      "rule input"
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
        (dsl.flush.ruleset { })
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
        [ [ [ (dsl.flush.ruleset { }) ] ] ]
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

  # Invalid children (wrong type) must throw. `toJson` forces evaluation:
  # the renderer builds a lazy list and the throw wouldn't fire until a
  # consumer walks it.
  testRenderRejectString = {
    expr = toJson (dsl.ruleset [ "not-a-command" ]);
    expectedError.msg = "dsl\\.ruleset: invalid child";
  };

  testRenderRejectInt = {
    expr = toJson (dsl.ruleset [ 42 ]);
    expectedError.msg = "dsl\\.ruleset: invalid child";
  };

  testRenderRejectBool = {
    expr = toJson (dsl.ruleset [ true ]);
    expectedError.msg = "dsl\\.ruleset: invalid child";
  };

  testRenderRejectNull = {
    expr = toJson (dsl.ruleset [ null ]);
    expectedError.msg = "dsl\\.ruleset: invalid child";
  };

  # Invalid child nested inside a list is detected too (recursion reaches it).
  testRenderRejectNestedInvalid = {
    expr = toJson (dsl.ruleset [ [ "bad" ] ]);
    expectedError.msg = "dsl\\.ruleset: invalid child";
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
        (dsl.flush.ruleset { })
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
          chains = {
            wan = {
              rules = [ [ dsl.accept ] ];
            };
            lan = {
              rules = [ [ dsl.accept ] ];
            };
            input = {
              type = "filter";
              hook = "input";
              prio = 0;
              policy = "drop";
              rules = [ [ (dsl.vmap dsl.fields.meta.iifname "@iif_dispatch") ] ];
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
          # Object-adds next — `wan`/`lan` already exist so verdict elements
          # resolve.
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

  # Concatenated-key port-forward: (ip daddr . tcp dport) →
  # (ipv4_addr . inet_service). Both the key and value sides are tuple
  # types; elements must wrap each side in `{ concat: [...] }` and `map`
  # must be a list of datatypes (the dot-separated string form is not
  # accepted by the nftables JSON parser).
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
                  addr = dsl.expr.map (dsl.expr.concat [
                    dsl.fields.ip.daddr
                    dsl.fields.tcp.dport
                  ]) "@port_forward";
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
          chains = {
            prerouting = {
              type = "filter";
              hook = "prerouting";
              prio = 0;
              rules = [ [ dsl.accept ] ];
            };
            input = {
              type = "filter";
              hook = "input";
              prio = 0;
              rules = [ [ dsl.accept ] ];
            };
            forward = {
              type = "filter";
              hook = "forward";
              prio = 0;
              rules = [ [ dsl.accept ] ];
            };
            output = {
              type = "filter";
              hook = "output";
              prio = 0;
              rules = [ [ dsl.accept ] ];
            };
            postrouting = {
              type = "filter";
              hook = "postrouting";
              prio = 0;
              rules = [ [ dsl.accept ] ];
            };
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
  # and object kinds in expansion order, while the raw example uses a
  # different order. Both submissions are semantically identical to nftables.

  testDslExampleValidates = {
    expr = builtins.isString (roundtrip nftlib.types.ruleset fixtures.examples.basicFirewallDsl);
    expected = true;
  };

  # Larger example exercising: two tables, three set flag combinations
  # (interval, interval+timeout, dynamic+timeout), named counters + limits
  # referenced by name, flowtable + flow statement, verdict map dispatch,
  # five base chains plus two regular sub-chains, concat-key port-forward
  # via map lookup in DNAT, masquerade. Schema-validates.
  testDslHomeRouterValidates = {
    expr = builtins.isString (roundtrip nftlib.types.ruleset fixtures.examples.homeRouterDsl);
    expected = true;
  };

  # The Integration cases load the examples from their children, in block
  # form too; those children must build the examples as shipped. (A
  # Boolean: the parse check would send an attrset expectation to nft.)
  testExampleChildrenBuildTheExamples = {
    expr =
      lib.mapAttrs (_: nftlib.dsl.ruleset) fixtures.exampleChildren == {
        inherit (fixtures.examples) basicFirewallDsl homeRouterDsl;
      };
    expected = true;
  };

  # =========================================================================
  # Non-add commands: create / delete / destroy / list / rename / reset,
  # plus replace / insert (rule-only) and the flush variants.
  # =========================================================================

  # `add.<kind>` covers every add-object kind; `add.rule` is the standalone
  # rule outside a table tree, typically with an explicit index.
  testCmdAddRule =
    pc
      (dsl.add.rule {
        family = "ip";
        table = "t";
        chain = "c";
        expr = [ dsl.accept ];
        index = 1;
      })
      {
        add = {
          rule = {
            family = "ip";
            table = "t";
            chain = "c";
            expr = [ { accept = null; } ];
            index = 1;
          };
        };
      };
  testCmdCreateLimitUnitsCamelCase =
    pc
      (dsl.create.limit {
        family = "inet";
        table = "t";
        name = "fast";
        rate = 10;
        per = "second";
        rateUnit = "kbytes";
        burst = 5;
        burstUnit = "bytes";
      })
      {
        create = {
          limit = {
            family = "inet";
            table = "t";
            name = "fast";
            rate = 10;
            per = "second";
            rate_unit = "kbytes";
            burst = 5;
            burst_unit = "bytes";
          };
        };
      };
  testCmdAddTable =
    pc
      (dsl.add.table {
        family = "inet";
        name = "filter";
      })
      {
        add = {
          table = {
            family = "inet";
            name = "filter";
          };
        };
      };
  testCmdAddSetRenamesElements =
    pc
      (dsl.add.set {
        family = "inet";
        table = "t";
        name = "trusted";
        type = "ipv4_addr";
        elements = [ "192.0.2.1" ];
      })
      {
        add = {
          set = {
            family = "inet";
            table = "t";
            name = "trusted";
            type = "ipv4_addr";
            elem = [ "192.0.2.1" ];
          };
        };
      };

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

  testCmdCreateCtHelperInet =
    pc
      (dsl.create.ctHelper {
        family = "inet";
        table = "t";
        name = "h";
        type = "ftp";
        protocol = "tcp";
        l3proto = "inet";
      })
      {
        create = {
          "ct helper" = {
            family = "inet";
            table = "t";
            name = "h";
            type = "ftp";
            protocol = "tcp";
            l3proto = "inet";
          };
        };
      };

  testCmdAddSetComment =
    pc
      (dsl.add.set {
        family = "inet";
        table = "t";
        name = "s";
        type = "ipv4_addr";
        comment = "blocked hosts";
      })
      {
        add = {
          set = {
            family = "inet";
            table = "t";
            name = "s";
            type = "ipv4_addr";
            comment = "blocked hosts";
          };
        };
      };

  testCmdAddMapComment =
    pc
      (dsl.add.map {
        family = "inet";
        table = "t";
        name = "m";
        type = "ipv4_addr";
        map = "verdict";
        comment = "per-host verdicts";
      })
      {
        add = {
          map = {
            family = "inet";
            table = "t";
            name = "m";
            type = "ipv4_addr";
            map = "verdict";
            comment = "per-host verdicts";
          };
        };
      };

  # Delete and destroy select by name: nft ignores a set's or map's
  # datatypes, a limit's rate, and a flowtable's hook on delete.
  testCmdDeleteSet =
    pc
      (dsl.delete.set {
        family = "inet";
        table = "t";
        name = "blocked";
      })
      {
        delete = {
          set = {
            family = "inet";
            table = "t";
            name = "blocked";
          };
        };
      };
  testCmdDeleteMap =
    pc
      (dsl.delete.map {
        family = "inet";
        table = "t";
        name = "ports";
      })
      {
        delete = {
          map = {
            family = "inet";
            table = "t";
            name = "ports";
          };
        };
      };
  testCmdDeleteLimit =
    pc
      (dsl.delete.limit {
        family = "inet";
        table = "t";
        name = "lim";
      })
      {
        delete = {
          limit = {
            family = "inet";
            table = "t";
            name = "lim";
          };
        };
      };
  testCmdDestroyFlowtable =
    pc
      (dsl.destroy.flowtable {
        family = "inet";
        table = "t";
        name = "ft";
      })
      {
        destroy = {
          flowtable = {
            family = "inet";
            table = "t";
            name = "ft";
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

  testCmdCreateCtCount =
    pc
      (dsl.create.ctCount {
        family = "ip";
        table = "t";
        name = "conns";
        val = 10;
        inv = true;
      })
      {
        create = {
          "ct count" = {
            family = "ip";
            table = "t";
            name = "conns";
            val = 10;
            inv = true;
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
  /*
    Each verb namespace offers only the kinds nft runs as written (ADR 0009),
    measured on nft 1.1.6 and 1.1.7. nft rejects `list` of a rule, element,
    flowtable, synproxy, metainfo, or ct count and the JSON `reset rule`. It
    mishandles delete, destroy, and list of a ct timeout or ct expectation,
    and 1.1.7 crashes on delete and destroy of a ct count. nft crashes on
    delete, destroy, and list of a tunnel, and JSON loads a tunnel's ports
    wrongly, so no namespace offers a tunnel; see
    tests/fixtures/nft-misbehaviour.nix.
  */
  testVerbNamespaceKinds = {
    expr =
      lib.concatMap
        (
          verb:
          map (kind: "${verb}.${kind}") (
            builtins.filter (name: name != "__functor") (builtins.attrNames dsl.${verb})
          )
        )
        [
          "delete"
          "destroy"
          "list"
          "reset"
        ];
    expected = [
      "delete.chain"
      "delete.counter"
      "delete.ctHelper"
      "delete.element"
      "delete.flowtable"
      "delete.limit"
      "delete.map"
      "delete.quota"
      "delete.rule"
      "delete.secmark"
      "delete.set"
      "delete.synproxy"
      "delete.table"
      "destroy.chain"
      "destroy.counter"
      "destroy.ctHelper"
      "destroy.element"
      "destroy.flowtable"
      "destroy.limit"
      "destroy.map"
      "destroy.quota"
      "destroy.rule"
      "destroy.secmark"
      "destroy.set"
      "destroy.synproxy"
      "destroy.table"
      "list.chain"
      "list.counter"
      "list.ctHelper"
      "list.limit"
      "list.map"
      "list.meter"
      "list.quota"
      "list.secmark"
      "list.set"
      "list.table"
      "reset.counter"
      "reset.element"
      "reset.map"
      "reset.quota"
      "reset.set"
    ];
  };

  # A verb with one object kind is a namespace like every other verb, so
  # its builder is named for the kind nft names: `insert rule`.
  testSingleKindVerbNamespaces = {
    expr = lib.concatMap (verb: map (kind: "${verb}.${kind}") (builtins.attrNames dsl.${verb})) [
      "insert"
      "rename"
      "replace"
    ];
    expected = [
      "insert.rule"
      "rename.chain"
      "replace.rule"
    ];
  };

  /*
    delete, destroy, list, flush, and reset select an object by family,
    table, and name, and demand no field nft ignores for the verb: each
    builder takes that selector alone. A rule is selected by its chain and
    handle, an element by its value, a table by family and name, and
    `flush.ruleset { }` flushes every family.
  */
  testSelectingVerbsTakeOnlyTheSelector =
    let
      scope = {
        family = "inet";
        table = "t";
      };
      selectorOf =
        kind:
        {
          element = scope // {
            name = "s";
            elem = [ "10.0.0.1" ];
          };
          rule = scope // {
            chain = "c";
            handle = 5;
          };
          ruleset = { };
          table = {
            family = "inet";
            name = "t";
          };
        }
        .${kind} or (scope // { name = "x"; });
      builds =
        verb: kind:
        (builtins.tryEval (builtins.deepSeq (toJson (dsl.${verb}.${kind} (selectorOf kind))) true)).success;
    in
    {
      expr =
        lib.concatMap
          (
            verb:
            map (kind: "${verb}.${kind}") (
              builtins.filter (kind: kind != "__functor" && !(builds verb kind)) (builtins.attrNames dsl.${verb})
            )
          )
          [
            "delete"
            "destroy"
            "flush"
            "list"
            "reset"
          ];
      expected = [ ];
    };

  # nft deletes a rule by handle, and with handle 0 (or none, through text)
  # deletes every rule in the chain, so delete and destroy require a
  # positive handle (measured on nft 1.1.6 and 1.1.7).
  testCmdDeleteRuleRequiresHandle = {
    expr = toJson (
      dsl.delete.rule {
        family = "inet";
        table = "t";
        chain = "c";
      }
    );
    expectedError.msg = "dsl\\.delete\\.rule\\.handle' was accessed but has no value defined";
  };
  testCmdDestroyRuleRejectsHandleZero = {
    expr = toJson (
      dsl.destroy.rule {
        family = "inet";
        table = "t";
        chain = "c";
        handle = 0;
      }
    );
    expectedError.msg = "dsl\\.destroy\\.rule\\.handle' is not of type `positive integer";
  };
  testSchemaRejectsDeleteRuleHandleZero = {
    expr = helpers.validates nftlib.types.command {
      delete.rule = {
        family = "inet";
        table = "t";
        chain = "c";
        handle = 0;
      };
    };
    expected = false;
  };

  # No namespace or table-tree kind produces a tunnel object: JSON loads its
  # ports wrongly and text has no spelling of it.
  testNoTunnelBuilders = {
    expr = builtins.filter (verb: dsl.${verb} ? tunnel) [
      "add"
      "create"
      "delete"
      "destroy"
      "list"
    ];
    expected = [ ];
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
  # replace / insert wrap the rule body in an inner `rule` tag — matches
  # what the nftables JSON parser expects.
  # reset of a set, map or element zeroes the stateful data of its elements.
  testCmdResetSet =
    pc
      (dsl.reset.set {
        family = "inet";
        table = "t";
        name = "s";
        type = "ipv4_addr";
      })
      {
        reset = {
          set = {
            family = "inet";
            table = "t";
            name = "s";
            type = "ipv4_addr";
          };
        };
      };
  testCmdResetMap =
    pc
      (dsl.reset.map {
        family = "inet";
        table = "t";
        name = "m";
        type = "ipv4_addr";
        map = "mark";
      })
      {
        reset = {
          map = {
            family = "inet";
            table = "t";
            name = "m";
            type = "ipv4_addr";
            map = "mark";
          };
        };
      };
  testCmdResetElement =
    pc
      (dsl.reset.element {
        family = "inet";
        table = "t";
        name = "s";
        elements = [ "10.0.0.1" ];
      })
      {
        reset = {
          element = {
            family = "inet";
            table = "t";
            name = "s";
            elem = [ "10.0.0.1" ];
          };
        };
      };

  testCmdReplace =
    pc
      (dsl.replace.rule {
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
      (dsl.insert.rule {
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

  # Flush variants — one `flush.<kind>` builder per flushable kind, like
  # the other command namespaces. Note: `set`/`map` bodies still require
  # `type` (and `map`) per the shared schema, even for flush-by-name.
  testCmdFlushRulesetEmptyBody = pc (dsl.flush.ruleset { }) {
    flush = {
      ruleset = null;
    };
  };
  testCmdFlushRuleset = pc (dsl.flush.ruleset { family = "ip"; }) {
    flush = {
      ruleset = {
        family = "ip";
      };
    };
  };
  testCmdFlushTable =
    pc
      (dsl.flush.table {
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
      (dsl.flush.chain {
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
      (dsl.flush.set {
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
      (dsl.flush.map {
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
  # `flush.flowtable` is intentionally omitted from both DSL and schema —
  # the nftables parser rejects `flush flowtable` with "Unknown object
  # passed to flush command". See lib/dsl/structure/ruleset.nix for the
  # rationale.

  testCmdFlushMeter =
    pc
      (dsl.flush.meter {
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
  # The reset comes last, the only place nft runs it.
  testCmdRulesetIntegration =
    pr
      (dsl.ruleset [
        (dsl.create.table {
          family = "ip";
          name = "u";
        })
        (dsl.rename.chain {
          family = "ip";
          table = "t";
          name = "oldchain";
          newname = "newchain";
        })
        (dsl.replace.rule {
          family = "ip";
          table = "t";
          chain = "c";
          handle = 7;
          expr = [ { accept = null; } ];
        })
        (dsl.destroy.set {
          family = "ip";
          table = "t";
          name = "stale";
          type = "ipv4_addr";
        })
        (dsl.reset.counter {
          family = "ip";
          table = "t";
          name = "c";
        })
      ])
      {
        nftables = [
          {
            create = {
              table = {
                family = "ip";
                name = "u";
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
            destroy = {
              set = {
                family = "ip";
                table = "t";
                name = "stale";
                type = "ipv4_addr";
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
        ];
      };
}
