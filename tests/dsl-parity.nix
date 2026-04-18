{ lib, nftlib }:

# Parity tests for the DSL layer. For each combinator/builder, the DSL
# output and a hand-written attrset must render to identical JSON — proving
# the DSL is pure sugar. The example-parity test is the end-to-end witness.

let
  inherit (nftlib) toJSON;
  inherit (nftlib.dsl) expr stmt;
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

  # DSL value and hand-written value must render to identical JSON.
  parity = t: dslValue: handwritten: {
    expr = roundtrip t dslValue;
    expected = roundtrip t handwritten;
  };

  # Shortcut for expression-context parity.
  pe = parity nftlib.expression;
  # Shortcut for statement-context parity.
  ps = parity nftlib.statement;
  # Shortcut for top-level ruleset parity.
  pr = parity nftlib.ruleset;
in
{
  # ======================================================================
  # Expression combinators
  # ======================================================================

  testDslExprConcat = pe (expr.concat [
    (expr.payload "ip" "saddr")
    (expr.payload "tcp" "dport")
  ]) {
    concat = [
      { payload = { protocol = "ip"; field = "saddr"; }; }
      { payload = { protocol = "tcp"; field = "dport"; }; }
    ];
  };

  testDslExprSet = pe (expr.set [
    22
    80
    443
  ]) { set = [ 22 80 443 ]; };

  testDslExprMap = pe (expr.map {
    key = expr.payload "tcp" "dport";
    data = "@port_forward";
  }) {
    map = {
      key = { payload = { protocol = "tcp"; field = "dport"; }; };
      data = "@port_forward";
    };
  };

  testDslExprPrefix = pe (expr.prefix "10.0.0.0" 8) {
    prefix = { addr = "10.0.0.0"; len = 8; };
  };

  testDslExprRange = pe (expr.range 1024 65535) { range = [ 1024 65535 ]; };

  testDslExprPayloadNamed = pe (expr.payload "tcp" "dport") {
    payload = { protocol = "tcp"; field = "dport"; };
  };

  testDslExprPayloadRaw = pe (expr.payloadRaw {
    base = "nh";
    offset = 72;
    len = 16;
  }) { payload = { base = "nh"; offset = 72; len = 16; }; };

  testDslExprPayloadTunnel = pe (expr.payloadTunnel {
    tunnel = "vxlan";
    protocol = "ip";
    field = "daddr";
  }) { payload = { tunnel = "vxlan"; protocol = "ip"; field = "daddr"; }; };

  testDslExprExthdr = pe (expr.exthdr { name = "frag"; field = "nexthdr"; }) {
    exthdr = { name = "frag"; field = "nexthdr"; };
  };

  testDslExprTcpOption = pe (expr.tcpOption { name = "sack-perm"; }) {
    "tcp option" = { name = "sack-perm"; };
  };

  testDslExprTcpOptionRaw = pe (expr.tcpOptionRaw {
    base = 2;
    offset = 16;
    len = 16;
  }) { "tcp option" = { base = 2; offset = 16; len = 16; }; };

  testDslExprIpOption = pe (expr.ipOption { name = "lsrr"; field = "length"; }) {
    "ip option" = { name = "lsrr"; field = "length"; };
  };

  testDslExprSctpChunk = pe (expr.sctpChunk { name = "data"; field = "tsn"; }) {
    "sctp chunk" = { name = "data"; field = "tsn"; };
  };

  testDslExprDccpOption = pe (expr.dccpOption 42) { "dccp option" = { type = 42; }; };

  testDslExprMeta = pe (expr.meta "iifname") { meta = { key = "iifname"; }; };

  testDslExprRt = pe (expr.rt { key = "mtu"; family = "ip"; }) {
    rt = { key = "mtu"; family = "ip"; };
  };

  testDslExprCt = pe (expr.ct {
    key = "saddr";
    dir = "original";
    family = "ip";
  }) { ct = { key = "saddr"; dir = "original"; family = "ip"; }; };

  testDslExprNumgen = pe (expr.numgen {
    mode = "inc";
    mod = 4;
    offset = 100;
  }) { numgen = { mode = "inc"; mod = 4; offset = 100; }; };

  testDslExprJhash = pe (expr.jhash {
    mod = 256;
    expr = expr.payload "ip" "saddr";
    seed = 42;
  }) {
    jhash = {
      mod = 256;
      expr = { payload = { protocol = "ip"; field = "saddr"; }; };
      seed = 42;
    };
  };

  testDslExprSymhash = pe (expr.symhash { mod = 8; offset = 1; }) {
    symhash = { mod = 8; offset = 1; };
  };

  testDslExprFib = pe (expr.fib {
    result = "oif";
    flags = [ "saddr" "mark" ];
  }) { fib = { result = "oif"; flags = [ "saddr" "mark" ]; }; };

  testDslExprSocket = pe (expr.socket "transparent") { socket = { key = "transparent"; }; };

  testDslExprOsf = pe (expr.osf { key = "name"; ttl = "loose"; }) {
    osf = { key = "name"; ttl = "loose"; };
  };

  testDslExprIpsec = pe (expr.ipsec {
    key = "saddr";
    family = "ip";
    dir = "in";
  }) { ipsec = { key = "saddr"; family = "ip"; dir = "in"; }; };

  testDslExprTunnelMeta = pe (expr.tunnelMeta "id") { tunnel = { key = "id"; }; };

  testDslExprElem = pe (expr.elem { val = "10.0.0.1"; timeout = 60; }) {
    elem = { val = "10.0.0.1"; timeout = 60; };
  };

  testDslExprVerdictAccept = pe expr.accept { accept = null; };
  testDslExprVerdictDrop = pe expr.drop { drop = null; };
  testDslExprVerdictContinue = pe expr.continue { continue = null; };
  testDslExprVerdictReturn = pe expr.return { return = null; };
  testDslExprVerdictJump = pe (expr.jump "inbound") { jump = { target = "inbound"; }; };
  testDslExprVerdictGoto = pe (expr.goto "elsewhere") { goto = { target = "elsewhere"; }; };

  testDslExprBitor = pe (expr.bitor (expr.meta "mark") 255) {
    "|" = [ { meta = { key = "mark"; }; } 255 ];
  };
  testDslExprBitxor = pe (expr.bitxor 1 2) { "^" = [ 1 2 ]; };
  testDslExprBitand = pe (expr.bitand (expr.meta "mark") 255) {
    "&" = [ { meta = { key = "mark"; }; } 255 ];
  };
  testDslExprLshift = pe (expr.lshift 1 4) { "<<" = [ 1 4 ]; };
  testDslExprRshift = pe (expr.rshift 16 4) { ">>" = [ 16 4 ]; };

  # ======================================================================
  # Statement combinators
  # ======================================================================

  testDslStmtAccept = ps stmt.accept { accept = null; };
  testDslStmtDrop = ps stmt.drop { drop = null; };
  testDslStmtContinue = ps stmt.continue { continue = null; };
  testDslStmtReturn = ps stmt.return { return = null; };
  testDslStmtNotrack = ps stmt.notrack { notrack = null; };
  testDslStmtJump = ps (stmt.jump "other") { jump = { target = "other"; }; };
  testDslStmtGoto = ps (stmt.goto "next") { goto = { target = "next"; }; };

  testDslStmtMatchEq = ps
    (stmt.matchEq (expr.payload "tcp" "dport") 22)
    {
      match = {
        left = { payload = { protocol = "tcp"; field = "dport"; }; };
        right = 22;
        op = "==";
      };
    };
  testDslStmtMatchNe = ps (stmt.matchNe 1 2) { match = { left = 1; right = 2; op = "!="; }; };
  testDslStmtMatchLt = ps (stmt.matchLt 1 2) { match = { left = 1; right = 2; op = "<"; }; };
  testDslStmtMatchGt = ps (stmt.matchGt 1 2) { match = { left = 1; right = 2; op = ">"; }; };
  testDslStmtMatchLe = ps (stmt.matchLe 1 2) { match = { left = 1; right = 2; op = "<="; }; };
  testDslStmtMatchGe = ps (stmt.matchGe 1 2) { match = { left = 1; right = 2; op = ">="; }; };
  testDslStmtMatchIn = ps (stmt.matchIn (expr.ct { key = "state"; }) (expr.set [ "established" ])) {
    match = {
      left = { ct = { key = "state"; }; };
      right = { set = [ "established" ]; };
      op = "in";
    };
  };

  testDslStmtCounterNull = ps stmt.counterNull { counter = null; };
  testDslStmtCounterRef = ps (stmt.counterRef "pkts") { counter = "pkts"; };
  testDslStmtCounter = ps (stmt.counter { packets = 0; bytes = 0; }) {
    counter = { packets = 0; bytes = 0; };
  };

  testDslStmtQuota = ps (stmt.quota { val = 1000; val_unit = "mbytes"; }) {
    quota = { val = 1000; val_unit = "mbytes"; };
  };
  testDslStmtQuotaRef = ps (stmt.quotaRef "q1") { quota = "q1"; };

  testDslStmtLimit = ps (stmt.limit {
    rate = 10;
    per = "minute";
    burst = 5;
  }) { limit = { rate = 10; per = "minute"; burst = 5; }; };
  testDslStmtLimitRef = ps (stmt.limitRef "lim") { limit = "lim"; };

  testDslStmtMangle = ps (stmt.mangle (expr.meta "mark") 42) {
    mangle = { key = { meta = { key = "mark"; }; }; value = 42; };
  };

  testDslStmtSnat = ps (stmt.snat { addr = "192.0.2.1"; family = "ip"; }) {
    snat = { addr = "192.0.2.1"; family = "ip"; };
  };
  testDslStmtDnat = ps (stmt.dnat {
    addr = "10.0.0.1";
    family = "ip";
    port = 8080;
  }) { dnat = { addr = "10.0.0.1"; family = "ip"; port = 8080; }; };
  testDslStmtMasquerade = ps (stmt.masquerade { flags = [ "random" ]; }) {
    masquerade = { flags = [ "random" ]; };
  };
  testDslStmtMasqueradePlain = ps stmt.masqueradePlain { masquerade = { }; };
  testDslStmtRedirect = ps (stmt.redirect { port = 8080; }) {
    redirect = { port = 8080; };
  };
  testDslStmtRedirectPlain = ps stmt.redirectPlain { redirect = { }; };
  testDslStmtFwd = ps (stmt.fwd { dev = "eth0"; }) { fwd = { dev = "eth0"; }; };
  testDslStmtDup = ps (stmt.dup { addr = "10.0.0.1"; dev = "eth0"; }) {
    dup = { addr = "10.0.0.1"; dev = "eth0"; };
  };

  testDslStmtReject = ps (stmt.reject { type = "icmp"; expr = "host-unreachable"; }) {
    reject = { type = "icmp"; expr = "host-unreachable"; };
  };
  testDslStmtRejectPlain = ps stmt.rejectPlain { reject = { }; };
  testDslStmtRejectIcmp = ps (stmt.rejectIcmp "net-unreachable") {
    reject = { type = "icmp"; expr = "net-unreachable"; };
  };
  testDslStmtRejectIcmpv6 = ps (stmt.rejectIcmpv6 "no-route") {
    reject = { type = "icmpv6"; expr = "no-route"; };
  };
  testDslStmtRejectIcmpx = ps (stmt.rejectIcmpx "admin-prohibited") {
    reject = { type = "icmpx"; expr = "admin-prohibited"; };
  };
  testDslStmtRejectTcpReset = ps stmt.rejectTcpReset { reject = { type = "tcp reset"; }; };

  testDslStmtSetStmt = ps (stmt.setStmt {
    op = "add";
    elem = "10.0.0.1";
    set = "@blocked";
  }) { set = { op = "add"; elem = "10.0.0.1"; set = "@blocked"; }; };

  testDslStmtMapStmt = ps (stmt.mapStmt {
    op = "update";
    elem = "10.0.0.1";
    data = 42;
    map = "@cache";
  }) { map = { op = "update"; elem = "10.0.0.1"; data = 42; map = "@cache"; }; };

  testDslStmtLog = ps (stmt.log {
    prefix = "DROPPED: ";
    level = "info";
    flags = [ "tcp options" "ip options" ];
  }) { log = { prefix = "DROPPED: "; level = "info"; flags = [ "tcp options" "ip options" ]; }; };
  testDslStmtLogPlain = ps stmt.logPlain { log = { }; };

  testDslStmtCtHelperSet = ps (stmt.ctHelperSet "ftp") { "ct helper" = "ftp"; };
  testDslStmtCtTimeoutSet = ps (stmt.ctTimeoutSet "fast_tcp") { "ct timeout" = "fast_tcp"; };
  testDslStmtCtExpectationSet = ps (stmt.ctExpectationSet "e1") { "ct expectation" = "e1"; };
  testDslStmtCtCount = ps (stmt.ctCount { val = 100; inv = true; }) {
    "ct count" = { val = 100; inv = true; };
  };

  testDslStmtMeter = ps (stmt.meter {
    name = "m";
    key = expr.meta "iifname";
    stmt = stmt.counter { packets = 0; bytes = 0; };
    size = 4096;
  }) {
    meter = {
      name = "m";
      key = { meta = { key = "iifname"; }; };
      stmt = { counter = { packets = 0; bytes = 0; }; };
      size = 4096;
    };
  };

  testDslStmtQueue = ps (stmt.queue { num = 1; flags = [ "bypass" ]; }) {
    queue = { num = 1; flags = [ "bypass" ]; };
  };
  testDslStmtQueuePlain = ps stmt.queuePlain { queue = { }; };

  testDslStmtVmap = ps (stmt.vmap (expr.meta "iifname") "@v") {
    vmap = { key = { meta = { key = "iifname"; }; }; data = "@v"; };
  };

  testDslStmtXt = ps (stmt.xt "match" "connlimit") { xt = { type = "match"; name = "connlimit"; }; };

  testDslStmtLast = ps stmt.last { last = null; };
  testDslStmtLastUsed = ps (stmt.lastUsed (-1)) { last = { used = -1; }; };

  testDslStmtFlow = ps (stmt.flow { flowtable = "@ft"; }) {
    flow = { op = "add"; flowtable = "@ft"; };
  };

  testDslStmtTproxy = ps (stmt.tproxy {
    family = "ip";
    addr = "127.0.0.1";
    port = 8080;
  }) { tproxy = { family = "ip"; addr = "127.0.0.1"; port = 8080; }; };

  testDslStmtSynproxyNull = ps stmt.synproxyNull { synproxy = null; };
  testDslStmtSynproxy = ps (stmt.synproxy { mss = 1460; wscale = 7; }) {
    synproxy = { mss = 1460; wscale = 7; };
  };
  testDslStmtSynproxyRef = ps (stmt.synproxyRef "sp1") { synproxy = "sp1"; };

  testDslStmtReset = ps (stmt.reset (expr.tcpOption { name = "sack-perm"; })) {
    reset = { "tcp option" = { name = "sack-perm"; }; };
  };

  testDslStmtSecmark = ps (stmt.secmark "@my_secmark") { secmark = "@my_secmark"; };
  testDslStmtTunnel = ps (stmt.tunnel "@my_tunnel") { tunnel = "@my_tunnel"; };

  # ======================================================================
  # Builder tests (context threading)
  # ======================================================================

  testDslMkTable = pr
    (dsl.mkRuleset [ (dsl.mkTable { family = "inet"; name = "t"; } [ ]) ])
    {
      nftables = [
        { add = { table = { family = "inet"; name = "t"; }; }; }
      ];
    };

  testDslMkChain = pr
    (dsl.mkRuleset [
      (dsl.mkTable { family = "inet"; name = "t"; } [
        (dsl.mkChain {
          name = "c";
          type = "filter";
          hook = "input";
          prio = 0;
          policy = "drop";
        } [ ])
      ])
    ])
    {
      nftables = [
        { add = { table = { family = "inet"; name = "t"; }; }; }
        { add = { chain = {
          family = "inet"; table = "t"; name = "c";
          type = "filter"; hook = "input"; prio = 0; policy = "drop";
        }; }; }
      ];
    };

  testDslMkRule = pr
    (dsl.mkRuleset [
      (dsl.mkTable { family = "inet"; name = "t"; } [
        (dsl.mkChain { name = "c"; } [
          (dsl.mkRule [ stmt.accept ])
        ])
      ])
    ])
    {
      nftables = [
        { add = { table = { family = "inet"; name = "t"; }; }; }
        { add = { chain = { family = "inet"; table = "t"; name = "c"; }; }; }
        { add = { rule = {
          family = "inet"; table = "t"; chain = "c";
          expr = [ { accept = null; } ];
        }; }; }
      ];
    };

  testDslMkSet = pr
    (dsl.mkRuleset [
      (dsl.mkTable { family = "inet"; name = "t"; } [
        (dsl.mkSet {
          name = "trusted";
          type = "ipv4_addr";
          flags = [ "interval" ];
          elem = [ (expr.prefix "10.0.0.0" 8) ];
        })
      ])
    ])
    {
      nftables = [
        { add = { table = { family = "inet"; name = "t"; }; }; }
        { add = { set = {
          family = "inet"; table = "t"; name = "trusted";
          type = "ipv4_addr"; flags = [ "interval" ];
          elem = [ { prefix = { addr = "10.0.0.0"; len = 8; }; } ];
        }; }; }
      ];
    };

  testDslMkMap = pr
    (dsl.mkRuleset [
      (dsl.mkTable { family = "inet"; name = "t"; } [
        (dsl.mkMap {
          name = "pf";
          type = "inet_service";
          map = "inet_service";
          elem = [ [ 80 8080 ] ];
        })
      ])
    ])
    {
      nftables = [
        { add = { table = { family = "inet"; name = "t"; }; }; }
        { add = { map = {
          family = "inet"; table = "t"; name = "pf";
          type = "inet_service"; map = "inet_service";
          elem = [ [ 80 8080 ] ];
        }; }; }
      ];
    };

  testDslMkElement = pr
    (dsl.mkRuleset [
      (dsl.mkTable { family = "inet"; name = "t"; } [
        (dsl.mkElement { name = "blocked"; elem = [ "1.2.3.4" ]; })
      ])
    ])
    {
      nftables = [
        { add = { table = { family = "inet"; name = "t"; }; }; }
        { add = { element = {
          family = "inet"; table = "t"; name = "blocked";
          elem = [ "1.2.3.4" ];
        }; }; }
      ];
    };

  testDslMkCounter = pr
    (dsl.mkRuleset [
      (dsl.mkTable { family = "ip"; name = "t"; } [
        (dsl.mkCounter { name = "hits"; packets = 0; bytes = 0; })
      ])
    ])
    {
      nftables = [
        { add = { table = { family = "ip"; name = "t"; }; }; }
        { add = { counter = {
          family = "ip"; table = "t"; name = "hits";
          packets = 0; bytes = 0;
        }; }; }
      ];
    };

  testDslMkQuota = pr
    (dsl.mkRuleset [
      (dsl.mkTable { family = "ip"; name = "t"; } [
        (dsl.mkQuota { name = "q"; bytes = 1000; })
      ])
    ])
    {
      nftables = [
        { add = { table = { family = "ip"; name = "t"; }; }; }
        { add = { quota = { family = "ip"; table = "t"; name = "q"; bytes = 1000; }; }; }
      ];
    };

  testDslMkLimitObject = pr
    (dsl.mkRuleset [
      (dsl.mkTable { family = "ip"; name = "t"; } [
        (dsl.mkLimitObject { name = "lim"; rate = 10; per = "second"; })
      ])
    ])
    {
      nftables = [
        { add = { table = { family = "ip"; name = "t"; }; }; }
        { add = { limit = {
          family = "ip"; table = "t"; name = "lim"; rate = 10; per = "second";
        }; }; }
      ];
    };

  testDslMkCTHelper = pr
    (dsl.mkRuleset [
      (dsl.mkTable { family = "inet"; name = "t"; } [
        (dsl.mkCTHelper { name = "h"; type = "ftp"; protocol = "tcp"; })
      ])
    ])
    {
      nftables = [
        { add = { table = { family = "inet"; name = "t"; }; }; }
        { add = { "ct helper" = {
          family = "inet"; table = "t"; name = "h";
          type = "ftp"; protocol = "tcp";
        }; }; }
      ];
    };

  testDslMkCTTimeout = pr
    (dsl.mkRuleset [
      (dsl.mkTable { family = "ip"; name = "t"; } [
        (dsl.mkCTTimeout {
          name = "fast_tcp";
          protocol = "tcp";
          l3proto = "ip";
          policy = { established = 300; };
        })
      ])
    ])
    {
      nftables = [
        { add = { table = { family = "ip"; name = "t"; }; }; }
        { add = { "ct timeout" = {
          family = "ip"; table = "t"; name = "fast_tcp";
          protocol = "tcp"; l3proto = "ip";
          policy = { established = 300; };
        }; }; }
      ];
    };

  testDslMkCTExpectation = pr
    (dsl.mkRuleset [
      (dsl.mkTable { family = "ip"; name = "t"; } [
        (dsl.mkCTExpectation {
          name = "e";
          protocol = "tcp";
          l3proto = "ip";
          dport = 8080;
        })
      ])
    ])
    {
      nftables = [
        { add = { table = { family = "ip"; name = "t"; }; }; }
        { add = { "ct expectation" = {
          family = "ip"; table = "t"; name = "e";
          protocol = "tcp"; l3proto = "ip"; dport = 8080;
        }; }; }
      ];
    };

  testDslMkSecmark = pr
    (dsl.mkRuleset [
      (dsl.mkTable { family = "inet"; name = "t"; } [
        (dsl.mkSecmark { name = "s"; context = "u:r:t:s0"; })
      ])
    ])
    {
      nftables = [
        { add = { table = { family = "inet"; name = "t"; }; }; }
        { add = { secmark = {
          family = "inet"; table = "t"; name = "s";
          context = "u:r:t:s0";
        }; }; }
      ];
    };

  testDslMkSynproxy = pr
    (dsl.mkRuleset [
      (dsl.mkTable { family = "inet"; name = "t"; } [
        (dsl.mkSynproxy { name = "sp1"; mss = 1460; wscale = 7; flags = [ "timestamp" ]; })
      ])
    ])
    {
      nftables = [
        { add = { table = { family = "inet"; name = "t"; }; }; }
        { add = { synproxy = {
          family = "inet"; table = "t"; name = "sp1";
          mss = 1460; wscale = 7; flags = [ "timestamp" ];
        }; }; }
      ];
    };

  testDslMkTunnel = pr
    (dsl.mkRuleset [
      (dsl.mkTable { family = "inet"; name = "t"; } [
        (dsl.mkTunnel {
          name = "v";
          id = 42;
          "src-ipv4" = "10.0.0.1";
          "dst-ipv4" = "10.0.0.2";
          type = "vxlan";
          tunnel = { gbp = 100; };
        })
      ])
    ])
    {
      nftables = [
        { add = { table = { family = "inet"; name = "t"; }; }; }
        { add = { tunnel = {
          family = "inet"; table = "t"; name = "v";
          id = 42;
          "src-ipv4" = "10.0.0.1";
          "dst-ipv4" = "10.0.0.2";
          type = "vxlan";
          tunnel = { gbp = 100; };
        }; }; }
      ];
    };

  testDslMkFlowtable = pr
    (dsl.mkRuleset [
      (dsl.mkTable { family = "inet"; name = "t"; } [
        (dsl.mkFlowtable { name = "ft"; hook = "ingress"; prio = 0; dev = [ "eth0" ]; })
      ])
    ])
    {
      nftables = [
        { add = { table = { family = "inet"; name = "t"; }; }; }
        { add = { flowtable = {
          family = "inet"; table = "t"; name = "ft";
          hook = "ingress"; prio = 0; dev = [ "eth0" ];
        }; }; }
      ];
    };

  # ======================================================================
  # Mixing raw + DSL commands (both must pass through ruleset validation)
  # ======================================================================

  testDslMixRawAndDsl = pr
    (dsl.mkRuleset [
      dsl.flushRuleset
      { add = { table = { family = "ip"; name = "x"; }; }; }
    ])
    {
      nftables = [
        { flush = { ruleset = null; }; }
        { add = { table = { family = "ip"; name = "x"; }; }; }
      ];
    };

  # ======================================================================
  # End-to-end: DSL example renders byte-identical JSON to hand-written one
  # ======================================================================

  testDslExampleParity = {
    expr = toJSON (import ../examples/basic-firewall-dsl.nix { inherit nftlib; });
    expected = toJSON (import ../examples/basic-firewall.nix { inherit nftlib; });
  };
}
