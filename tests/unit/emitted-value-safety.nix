{
  helpers,
  lib,
  nftlib,
  ...
}:

/*
  Every value the text renderer writes bare, enum, closed-set and integer
  fields included. The schema types these fields, but raw attrsets bypass
  it, so the renderer checks each value it emits (ADR 0004): an integer,
  or a string that passes the bare-token check. A raw chain `policy` of
  `drop; }` plus a newline and an `add chain` command used to load that
  extra chain with `policy accept`.

  Each case puts an injection string in one field of a raw command and
  expects the Refusal that names the field.
*/
let
  inherit (nftlib) toText toTextPretty;
  inherit (helpers) refusals;

  injection = "x; }\nadd chain inet t pwned { type filter hook input priority -10; policy accept; }\n#";

  one = cmd: { nftables = [ cmd ]; };

  scope = {
    family = "inet";
    table = "t";
  };

  rule =
    statement:
    one {
      add.rule = scope // {
        chain = "c";
        expr = [ statement ];
      };
    };

  # A match whose left side is `left`.
  matchOn =
    left:
    rule {
      match = {
        inherit left;
        op = "==";
        right = 1;
      };
    };

  add = kind: body: one { add.${kind} = scope // { name = "o"; } // body; };

  set = body: add "set" ({ type = "ipv4_addr"; } // body);

  chain =
    body:
    add "chain" (
      {
        type = "filter";
        hook = "input";
        prio = 0;
      }
      // body
    );

  ctExpectation =
    body:
    add "ct expectation" (
      {
        protocol = "tcp";
        dport = 21;
        timeout = 1000;
        size = 1;
      }
      // body
    );

  # Field label → a raw ruleset carrying `injection` in that field.
  cases = {
    # Expressions
    "payload base" = matchOn {
      payload = {
        base = injection;
        offset = 0;
        len = 8;
      };
    };
    "payload offset" = matchOn {
      payload = {
        base = "nh";
        offset = injection;
        len = 8;
      };
    };
    "dccp option type" = matchOn { "dccp option".type = injection; };
    "tcp option len" = matchOn {
      "tcp option" = {
        base = 1;
        offset = 0;
        len = injection;
      };
    };
    "meta key" = matchOn { meta.key = injection; };
    "rt key" = matchOn { rt.key = injection; };
    "rt family" = matchOn {
      rt = {
        key = "nexthop";
        family = injection;
      };
    };
    "ct dir" = matchOn {
      ct = {
        key = "saddr";
        dir = injection;
      };
    };
    "numgen mode" = matchOn {
      numgen = {
        mode = injection;
        mod = 2;
      };
    };
    "numgen mod" = matchOn {
      numgen = {
        mode = "inc";
        mod = injection;
      };
    };
    "jhash mod" = matchOn {
      jhash = {
        expr.meta.key = "mark";
        mod = injection;
      };
    };
    "symhash mod" = matchOn { symhash.mod = injection; };
    "fib flags" = matchOn {
      fib = {
        flags = [ injection ];
        result = "oif";
      };
    };
    "fib result" = matchOn {
      fib = {
        flags = [ "daddr" ];
        result = injection;
      };
    };
    "socket key" = matchOn { socket.key = injection; };
    "osf key" = matchOn { osf.key = injection; };
    "osf ttl" = matchOn {
      osf = {
        key = "name";
        ttl = injection;
      };
    };
    "ipsec dir" = matchOn {
      ipsec = {
        key = "saddr";
        dir = injection;
        family = "ip";
      };
    };
    "ipsec family" = matchOn {
      ipsec = {
        key = "saddr";
        dir = "in";
        family = injection;
      };
    };
    "ipsec key" = matchOn {
      ipsec = {
        key = injection;
        dir = "in";
      };
    };
    "tunnel key" = matchOn { tunnel.key = injection; };
    "prefix len" = rule {
      match = {
        left.payload = {
          protocol = "ip";
          field = "saddr";
        };
        op = "==";
        right.prefix = {
          addr = "10.0.0.0";
          len = injection;
        };
      };
    };
    "element timeout" = set {
      elem = [
        {
          elem = {
            val = "10.0.0.1";
            timeout = injection;
          };
        }
      ];
    };

    # Statements
    "match op" = rule {
      match = {
        left.meta.key = "mark";
        op = injection;
        right = 1;
      };
    };
    "counter packets" = rule {
      counter = {
        packets = injection;
        bytes = 0;
      };
    };
    "quota val" = rule { quota.val = injection; };
    "reject type" = rule { reject.type = injection; };
    "set op" = rule {
      set = {
        op = injection;
        elem.meta.key = "mark";
        set = "@s";
      };
    };
    "map op" = rule {
      map = {
        op = injection;
        elem.meta.key = "mark";
        data = 1;
        map = "@m";
      };
    };
    "log level" = rule { log.level = injection; };
    "log group" = rule { log.group = injection; };
    "meter size" = rule {
      meter = {
        name = "m";
        key.meta.key = "mark";
        stmt.counter = null;
        size = injection;
      };
    };
    "queue flags" = rule {
      queue = {
        num = 1;
        flags = [ injection ];
      };
    };
    "ct count val" = rule { "ct count".val = injection; };
    "xt type" = rule {
      xt = {
        type = injection;
        name = "x";
      };
    };
    "last used" = rule { last.used = injection; };
    "flow op" = rule {
      flow = {
        op = injection;
        flowtable = "@f";
      };
    };
    "tproxy family" = rule {
      tproxy = {
        family = injection;
        port = 80;
      };
    };
    "synproxy mss" = rule {
      synproxy = {
        mss = injection;
        wscale = 7;
      };
    };
    "synproxy flags" = rule {
      synproxy = {
        mss = 1460;
        wscale = 7;
        flags = [ injection ];
      };
    };
    "limit rate" = rule {
      limit = {
        rate = injection;
        per = "second";
      };
    };
    "limit per" = rule {
      limit = {
        rate = 1;
        per = injection;
      };
    };
    "limit burst" = rule {
      limit = {
        rate = 1;
        per = "second";
        burst = injection;
      };
    };

    # Objects and commands
    family = one {
      add.table = {
        family = injection;
        name = "t";
      };
    };
    "table flags" = one {
      add.table = {
        family = "inet";
        name = "t";
        flags = [ injection ];
      };
    };
    "chain type" = chain { type = injection; };
    "chain hook" = chain { hook = injection; };
    "chain policy" = chain { policy = injection; };
    "rule handle" = one {
      replace.rule = scope // {
        chain = "c";
        handle = injection;
        expr = [ { accept = null; } ];
      };
    };
    "rule index" = one {
      insert.rule = scope // {
        chain = "c";
        index = injection;
        expr = [ { accept = null; } ];
      };
    };
    "set flags" = set { flags = [ injection ]; };
    "set policy" = set { policy = injection; };
    "set size" = set { size = injection; };
    "set timeout" = set { timeout = injection; };
    "set gc-interval" = set { "gc-interval" = injection; };
    "flowtable hook" = add "flowtable" {
      hook = injection;
      prio = 0;
    };
    "counter object packets" = add "counter" { packets = injection; };
    "quota object bytes" = add "quota" { bytes = injection; };
    "ct count object val" = add "ct count" { val = injection; };
    "ct helper protocol" = add "ct helper" {
      type = "ftp";
      protocol = injection;
    };
    "ct helper l3proto" = add "ct helper" {
      type = "ftp";
      protocol = "tcp";
      l3proto = injection;
    };
    "ct timeout protocol" = add "ct timeout" { protocol = injection; };
    "ct timeout policy value" = add "ct timeout" {
      protocol = "tcp";
      policy.established = injection;
    };
    "ct expectation protocol" = ctExpectation { protocol = injection; };
    "ct expectation dport" = ctExpectation { dport = injection; };
    "ct expectation l3proto" = ctExpectation { l3proto = injection; };
    "synproxy object wscale" = add "synproxy" {
      mss = 1460;
      wscale = injection;
    };
    "ruleset family" = one { flush.ruleset.family = injection; };
    "rename family" = one {
      rename.chain = scope // {
        family = injection;
        name = "c";
        newname = "d";
      };
    };
  };

  testName = field: lib.replaceStrings [ " " "-" ] [ "_" "_" ] field;

  refusalTests = lib.concatMapAttrs (field: ruleset: {
    "testRefuses_${testName field}" = {
      expr = toText ruleset;
      expectedError.msg = refusals.bareToken field;
    };
    "testPrettyRefuses_${testName field}" = {
      expr = toTextPretty ruleset;
      expectedError.msg = refusals.bareToken field;
    };
  }) cases;

  # Validated values render unchanged; the parity suites pin the rest.
  acceptanceTests = {
    testChainPolicyRendersBare = {
      expr = toText (chain {
        policy = "drop";
      });
      expected = "add chain inet t o { type filter hook input priority 0; policy drop; }";
    };
    testRejectTcpResetRendersTwoWords = {
      expr = toText (rule {
        reject = {
          type = "tcp reset";
        };
      });
      expected = "add rule inet t c reject with tcp reset";
    };
  };
in
refusalTests // acceptanceTests
