/*
  Inputs of the parse check. It sends to the package set's nft every
  pinned text string in the text and block parity suites, every expected
  JSON value in the DSL parity suite, and every Field leaf in a minimal
  rule. The inputs are enumerated from the suites and from `dsl.fields`,
  so a new pin or leaf is checked without editing the probe.

  `checks.<name>` is `{ subject; json; state; stateJson; }`. The probe
  really loads `state` (nft text, or JSON when `stateJson` is set): the
  tables, chains, named objects and rule handles the subject refers to.
  Then `nft -c` (with `-j` when `json` is set) must accept `subject`.

  `expectedRejections.<name>` lists the checks nft rejects today, each
  asserted to still fail with `error` in its output:
  - a pending entry names the open ticket under #24 that fixes it
    (`ticket`), and the fix removes the entry;
  - a Known difference names its `reason`.
  `rejectedBefore` limits an entry to nft versions older than it, and
  `kernelFrom` to kernels at least that new; elsewhere the check must pass.
*/
{
  dsl,
  lib,
  nftlib,
  paritySuites,
}:
let
  jsonTag = value: lib.head (builtins.attrNames value);

  # ---- Rule contexts --------------------------------------------------

  inputChain = {
    type = "filter";
    hook = "input";
    prio = 0;
  };

  /*
    A rule context: the family and chain of the table `t` that holds the
    checked statement, the statements the rule needs before it, and, for
    an expression, `statement`, which builds the checked statement from
    it.
  */
  defaultRuleContext = {
    family = "inet";
    chain = inputChain;
    before = [ ];
    statement = matchWith 1;
  };

  matchWith = right: left: {
    match = {
      inherit left right;
      op = "==";
    };
  };

  # The commands that hold `statements` in a rule of `ruleContext`.
  ruleCommands =
    ruleContext: statements:
    let
      scope = {
        inherit (ruleContext) family;
        table = "t";
      };
    in
    [
      {
        add.table = {
          inherit (ruleContext) family;
          name = "t";
        };
      }
      { add.chain = scope // ruleContext.chain // { name = "c"; }; }
      {
        add.rule = scope // {
          chain = "c";
          expr = ruleContext.before ++ statements;
        };
      }
    ];

  l4proto = protocol: matchWith protocol { meta.key = "l4proto"; };

  natChain = hook: prio: {
    family = "ip";
    chain = {
      type = "nat";
      inherit hook prio;
    };
  };

  netdevIngress = {
    family = "netdev";
    chain = inputChain // {
      hook = "ingress";
      dev = "eth0";
    };
  };

  # Rule contexts for statements, by tag.
  statementContexts = {
    dnat = natChain "prerouting" (-100) // {
      before = [ (l4proto "tcp") ];
    };
    dup.family = "ip";
    flow.chain = inputChain // {
      hook = "forward";
    };
    fwd = netdevIngress;
    masquerade = natChain "postrouting" 100;
    redirect = natChain "prerouting" (-100) // {
      before = [ (l4proto "tcp") ];
    };
    snat = natChain "postrouting" 100;
    tproxy = {
      family = "ip";
      chain = inputChain // {
        hook = "prerouting";
        prio = -150;
      };
      before = [ (l4proto "tcp") ];
    };
  };

  /*
    Rule contexts for expressions, by shape: `<tag>`, then
    `<tag>.<key>` (`<key>` is a ct, meta, rt, socket, osf, ipsec or
    tunnel key, or a fib result), or `payload.<protocol>` and
    `payload.<protocol>.<field>`. The more specific shape wins. Field
    leaves and DSL parity expressions share them. A context places an
    expression, with the table family and the value it is compared to,
    but never changes it: a leaf check sends the leaf as written.
  */
  expressionContexts =
    let
      # Keys nft only sets, never matches.
      setOnly = value: expression: dsl.mangle expression value;
      bridge.family = "bridge";
      ip4Address.statement = matchWith "192.0.2.1";
      ip4TableAddress = ip4Address // {
        family = "ip";
      };
      ip6Address.statement = matchWith "2001:db8::1";
      ip6TableAddress = ip6Address // {
        family = "ip6";
      };
    in
    {
      "ct.event".statement = setOnly "new";
      # A ct address key without a family in its name takes the table's;
      # nft refuses one in an inet table ("use ip saddr or ip6 saddr
      # instead").
      "ct.saddr" = ip4TableAddress;
      "ct.daddr" = ip4TableAddress;
      "ct.ip saddr" = ip4TableAddress;
      "ct.ip daddr" = ip4TableAddress;
      "ct.ip6 saddr" = ip6TableAddress;
      "ct.ip6 daddr" = ip6TableAddress;
      "ct.proto-src".family = "ip";
      "ct.proto-dst".family = "ip";
      # A secmark is copied between the packet and its connection.
      "ct.secmark".statement = dsl.mangle { meta.key = "secmark"; };
      "ipsec.saddr" = ip4Address;
      # nft types a map lookup's values from where they go; compared with
      # a constant they have no type ("Implicit map expression without
      # known datatype" for an anonymous map), so the lookup sets the mark.
      map.statement = dsl.mangle { meta.key = "mark"; };
      "meta.broute" = bridge // {
        chain = inputChain // {
          hook = "prerouting";
        };
        statement = setOnly 1;
      };
      "meta.ibrhwaddr" = bridge;
      "meta.ibrname" = bridge;
      "meta.ibrpvid" = bridge;
      "meta.ibrvproto" = bridge;
      "meta.nftrace".statement = setOnly 1;
      "meta.obrname" = bridge;
      "meta.secmark".statement = dsl.mangle { ct.key = "secmark"; };
      "payload.arp".family = "arp";
      # A neighbour discovery message's target and destination addresses.
      "payload.icmpv6.daddr" = ip6Address;
      "payload.icmpv6.taddr" = ip6Address;
      "payload.ip6.daddr" = ip6Address;
      "payload.ip6.saddr" = ip6Address;
      prefix.statement =
        right:
        matchWith right {
          payload = {
            protocol = "ip";
            field = "saddr";
          };
        };
      range.statement =
        right:
        matchWith right {
          payload = {
            protocol = "tcp";
            field = "dport";
          };
        };
      # An inet table leaves the nexthop's address family open.
      "rt.nexthop" = ip4TableAddress;
      # Tunnel metadata exists only on netdev ingress.
      tunnel = netdevIngress;
    };

  shapesOf =
    expression:
    let
      tag = jsonTag expression;
      body = expression.${tag};
      qualifiers =
        if tag == "payload" then
          lib.optionals (body ? protocol) [
            body.protocol
            "${body.protocol}.${body.field or ""}"
          ]
        else
          builtins.filter lib.isString [ (body.key or body.result or null) ];
    in
    [ tag ] ++ lib.optionals (lib.isAttrs body) (map (qualifier: "${tag}.${qualifier}") qualifiers);

  expressionRuleContext =
    expression:
    lib.foldl' (context: shape: context // expressionContexts.${shape} or { }) defaultRuleContext (
      shapesOf expression
    );

  # ---- Field leaves ---------------------------------------------------

  leafChecks = lib.concatMapAttrs (
    group:
    lib.concatMapAttrs (
      leaf: expression:
      let
        ruleContext = expressionRuleContext expression;
        ruleset.nftables = ruleCommands ruleContext [ (ruleContext.statement expression) ];
      in
      {
        "leaf.json.${group}.${leaf}" = {
          subject = nftlib.toJson ruleset;
          json = true;
        };
        "leaf.text.${group}.${leaf}".subject = nftlib.toTextPretty ruleset;
      }
    )
  ) dsl.fields;

  # ---- State ----------------------------------------------------------

  # A table, and `chain` in it with rules up to `handle`; a chain takes
  # handle 1 in a new table, and each rule the next.
  rulesThroughHandle =
    scope: handle:
    let
      chain = "${scope.family} ${scope.table} ${scope.chain}";
      rules = lib.replicate (handle - 1) "add rule ${chain} accept\n";
    in
    ''
      add table ${scope.family} ${scope.table}
      add chain ${chain}
      ${lib.concatStrings rules}'';

  ipTc = {
    family = "ip";
    table = "t";
    chain = "c";
  };

  # Named objects `a` and `b` of one kind in `ip t`.
  objectPair = declaration: ''
    add table ip t
    add ${declaration "a"}
    add ${declaration "b"}
  '';

  # Per-check context, by check name: `state` (or `jsonState`, a JSON
  # ruleset) for the prior state the subject refers to, and rule-context
  # overrides for DSL parity statements and expressions.
  ownContexts = {
    "dslParity.testCmdAddElementRename".state = ''
      add table inet t
      add set inet t blocked { type ipv4_addr; }
    '';
    "dslParity.testCmdAddRule".state = rulesThroughHandle ipTc 4;
    "dslParity.testCmdDeleteLimit".state = ''
      add table inet t
      add limit inet t lim { rate 10/second; }
    '';
    "dslParity.testCmdDeleteMap".state = ''
      add table inet t
      add map inet t ports { type inet_service : inet_service; }
    '';
    "dslParity.testCmdDeleteSet".state = ''
      add table inet t
      add set inet t blocked { type ipv4_addr; }
    '';
    "dslParity.testCmdFlushMap".state = ''
      add table ip nat
      add map ip nat port_forward { type inet_service : inet_service; }
    '';
    "dslParity.testCmdFlushMeter".state = meterState;
    "dslParity.testCmdFlushSet".state = ''
      add table inet t
      add set inet t trusted { type ipv4_addr; }
    '';
    "dslParity.testCmdInsert".state = "add rule ip t c accept\n";
    "dslParity.testCmdListMeter".state = meterState;
    "dslParity.testCmdReplace".state = rulesThroughHandle ipTc 42;
    "dslParity.testCmdResetElement".state = resetState;
    "dslParity.testCmdResetMap".state = resetState;
    "dslParity.testCmdResetSet".state = resetState;
    "dslParity.testCmdRulesetIntegration".state = rulesThroughHandle ipTc 7 + ''
      add chain ip t oldchain
      add counter ip t c
    '';
    "dslParity.testCounterRef".state = ''
      add table inet t
      add counter inet t pkts
    '';
    "dslParity.testCtCountRef".state = ''
      add table inet t
      add ct count inet t c1 { over 5; }
    '';
    "dslParity.testCtCountRefMap".jsonState.nftables = [
      {
        add.table = {
          family = "inet";
          name = "t";
        };
      }
      {
        add.map = {
          family = "inet";
          table = "t";
          name = "limits";
          type = "mark";
          map = "ct count";
        };
      }
    ];
    "dslParity.testCtExpectation".state = ''
      add table inet t
      add ct expectation inet t e1 {
        protocol tcp; dport 21; timeout 1s; size 1; l3proto ip;
      }
    '';
    "dslParity.testCtHelper".state = ''
      add table inet t
      add ct helper inet t ftp { type "ftp" protocol tcp; }
    '';
    "dslParity.testCtTimeout".state = ''
      add table inet t
      add ct timeout inet t fast_tcp {
        protocol tcp; policy = { established: 100 };
      }
    '';
    # Constant binary operations fold on the right of a match.
    "dslParity.testExprBitXor".statement = right: matchWith right { meta.key = "mark"; };
    "dslParity.testExprConcat".statement = matchWith {
      set = [
        {
          concat = [
            "10.0.0.1"
            22
          ];
        }
      ];
    };
    # Elements belong to a set.
    "dslParity.testExprElem" = elementContext;
    "dslParity.testExprElemOmitsUnsetOptions" = elementContext;
    "dslParity.testExprMap".state = ''
      add table inet t
      add map inet t pf { type inet_service : mark; }
    '';
    # Its `family` selects the nexthop's address family, which an ip table
    # would contradict.
    "dslParity.testExprRtRefined" = {
      family = "inet";
      statement = matchWith "2001:db8::1";
    };
    "dslParity.testExprSet".statement =
      right:
      matchWith right {
        payload = {
          protocol = "tcp";
          field = "dport";
        };
      };
    "dslParity.testExprSetListStillWorks".statement = ipSaddrIn;
    "dslParity.testExprSetRef".state = trustedV4.state;
    "dslParity.testExprShiftLeft".statement = right: matchWith right { meta.key = "length"; };
    "dslParity.testExprShiftRight".statement = right: matchWith right { meta.key = "length"; };
    "dslParity.testFlow".state = ''
      add table inet t
      add flowtable inet t ft { hook ingress priority 0; devices = { eth0 }; }
    '';
    "dslParity.testFlowBareName".state = ''
      add table inet t
      add flowtable inet t ft { hook ingress priority 0; devices = { eth0 }; }
    '';
    "dslParity.testLimitRef".state = ''
      add table inet t
      add limit inet t lim { rate 1/second; }
    '';
    "dslParity.testMapStmt".state = ''
      add table inet t
      add map inet t cache { type ipv4_addr : mark; flags dynamic; }
    '';
    "dslParity.testMapStmtBareName".state = ''
      add table inet t
      add map inet t cache { type ipv4_addr : mark; flags dynamic; }
    '';
    "dslParity.testMapStmtStatements".state = ''
      add table inet t
      add map inet t cache { type ipv4_addr : mark; flags dynamic; }
    '';
    "dslParity.testOpInSetRef".state = ''
      add table inet t
      add set inet t trusted { type ipv4_addr; }
    '';
    # Inner-header matches follow the tunnel's outer match.
    "dslParity.testPayloadTunnel" = {
      before = [
        (matchWith 4789 {
          payload = {
            protocol = "udp";
            field = "dport";
          };
        })
      ];
      statement = matchWith "192.0.2.1";
    };
    "dslParity.testQuotaRef".state = ''
      add table inet t
      add quota inet t q1 { 1000 bytes; }
    '';
    "dslParity.testRenderNetdevIngress".state = ''
      add table netdev guard
      add set netdev guard blocklist { type ipv4_addr; }
    '';
    "dslParity.testRenderRuleAttrset".state = rulesThroughHandle {
      family = "inet";
      table = "t";
      chain = "c";
    } 42;
    "dslParity.testSecmark".state = ''
      add table inet t
      add secmark inet t my_secmark {
        "system_u:object_r:ssh_server_packet_t:s0"
      }
    '';
    "dslParity.testSetStmt".state = ''
      add table inet t
      add set inet t blocked { type ipv4_addr; }
    '';
    "dslParity.testSetStmtBareName".state = ''
      add table inet t
      add set inet t blocked { type ipv4_addr; }
    '';
    "dslParity.testSetStmtStatements".state = ''
      add table inet t
      add set inet t blocked { type ipv4_addr; flags dynamic; }
    '';
    "dslParity.testSynproxyRef".state = ''
      add table inet t
      add synproxy inet t sp1 { mss 1460 wscale 7; }
    '';
    "dslParity.testTunnelStmt" = netdevIngress // {
      state = ''
        add table netdev t
        add tunnel netdev t my_tunnel {
          id 42; ip saddr 192.0.2.1; ip daddr 192.0.2.2;
        }
      '';
    };
    "dslParity.testVerdictGotoStmt".state = chainState "elsewhere";
    "dslParity.testVerdictJumpExpr".state = chainState "vmap-target";
    "dslParity.testVerdictJumpStmt".state = chainState "inbound";
    "dslParity.testVmap".state = ''
      add table inet t
      add map inet t v { type ifname : verdict; }
    '';
    "textParity.testCmdFlushMeter".state = meterState;
    "textParity.testConcatMatchesNamedSet".state = ''
      add set inet t allowed { type ifname . ipv4_addr; }
    '';
    "textParity.testCtAssignmentQuoted".state = ''
      add ct helper ip t ftp-helper { type "ftp" protocol tcp; }
    '';
    "textParity.testCtCountNamedReference".state = ''
      add ct count ip t c1 { over 5; }
    '';
    "textParity.testDeleteByHandle".state = rulesThroughHandle ipTc 42;
    # The kernel numbers a namespace's tables, and each table's objects,
    # from 1 in the order they are added.
    "textParity.testDeleteNamedObjectsByHandle.0".state = ''
      add table ip t
      add table ip gone
    '';
    "textParity.testDeleteNamedObjectsByHandle.1".state = ''
      add chain ip t c
    '';
    "textParity.testDeleteNamedObjectsByHandle.2".state = ''
      add counter inet t a
      add counter inet t b
      add counter inet t c
    '';
    "textParity.testDeleteNamedObjectsByHandle.3".state = ''
      add counter inet t a
      add counter inet t b
      add counter inet t c
      add flowtable inet t ft { hook ingress priority 0; devices = { eth0 }; }
    '';
    "textParity.testTunnelStatement".state = ''
      add tunnel netdev t vxlan0 {
        id 42; ip saddr 192.0.2.1; ip daddr 192.0.2.2;
      }
    '';
    "textParity.testElement".state = ''
      add table inet main
      add set inet main trusted { type ipv4_addr; }
    '';
    "textParity.testElementNullStatementOmitted".state = ''
      add table ip t
      add set ip t s { type ipv4_addr; }
    '';
    "textParity.testMapLookup".state = ''
      add map ip t port_forward { type inet_service : inet_service; }
    '';
    "textParity.testMatchSetRef".state = ''
      add set inet t trusted { type ifname; }
    '';
    "textParity.testSlashReferenceBare".state = ''
      add set ip t a/b { type ipv4_addr; }
    '';
    "textParity.testFlowNamedReference".state = ''
      add flowtable inet t ft { hook ingress priority 0; devices = { eth0 }; }
    '';
    "textParity.testMapStatementNamedReference".state = ''
      add map ip t cache { type ipv4_addr : mark; flags dynamic; }
    '';
    "textParity.testReplaceRule".state = rulesThroughHandle ipTc 7;
    "textParity.testInsertRuleByHandle".state = rulesThroughHandle ipTc 7;
    "textParity.testListedRuleDropsHandle".state = rulesThroughHandle ipTc 1;
    "textParity.testSetStatementNamedReference".state = ''
      add set ip t blocked { type ipv4_addr; flags dynamic; }
    '';
    "textParity.testStatefulMapReferences.0".state = objectPair (name: "counter ip t ${name}");
    "textParity.testStatefulMapReferences.1".state = objectPair (
      name: "quota ip t ${name} { 1000 bytes; }"
    );
    "textParity.testStatefulMapReferences.2".state = objectPair (
      name: "limit ip t ${name} { rate 1/second; }"
    );
    "textParity.testStatefulMapReferences.3".state = objectPair (
      name: "ct count ip t ${name} { over 5; }"
    );
    "textParity.testStatefulMapReferences.4".state = objectPair (
      name: "synproxy ip t ${name} { mss 1460 wscale 7; }"
    );
  };

  # Checks that load the same objects as another check.
  sharedContexts = {
    "dslParity.testCounterRefAtName" = "dslParity.testCounterRef";
    "dslParity.testCtCountRefAtName" = "dslParity.testCtCountRef";
    "dslParity.testCtExpectationAtName" = "dslParity.testCtExpectation";
    "dslParity.testCtHelperAtName" = "dslParity.testCtHelper";
    "dslParity.testCtTimeoutAtName" = "dslParity.testCtTimeout";
    "dslParity.testExprMapBareName" = "dslParity.testExprMap";
    "dslParity.testLimitRefAtName" = "dslParity.testLimitRef";
    "dslParity.testQuotaRefAtName" = "dslParity.testQuotaRef";
    "dslParity.testSecmarkAtName" = "dslParity.testSecmark";
    "dslParity.testSynproxyRefAtName" = "dslParity.testSynproxyRef";
    "dslParity.testTunnelStmtAtName" = "dslParity.testTunnelStmt";
    "dslParity.testVmapBareName" = "dslParity.testVmap";
  };

  checkContexts = ownContexts // lib.mapAttrs (_: other: ownContexts.${other}) sharedContexts;

  resetState = ''
    add table inet t
    add set inet t s { type ipv4_addr; elements = { 10.0.0.1 }; }
    add map inet t m { type ipv4_addr : mark; elements = { 10.0.0.1 : 1 }; }
  '';

  meterState = ''
    add table inet filter
    add set inet filter rate_meter { type ipv4_addr; flags dynamic; }
  '';

  chainState = name: ''
    add table inet t
    add chain inet t ${name}
  '';

  ipSaddrIn =
    right:
    matchWith right {
      payload = {
        protocol = "ip";
        field = "saddr";
      };
    };

  trustedV4 = {
    state = ''
      add table inet t
      add set inet t trusted_v4 { type ipv4_addr; }
    '';
    statement = ipSaddrIn;
  };

  elementContext = {
    state = ''
      add table inet t
      add set inet t s { type ipv4_addr; flags timeout; }
    '';
    commands = element: [
      {
        add.element = {
          family = "inet";
          table = "t";
          name = "s";
          elem = [ element ];
        };
      }
    ];
  };

  # ---- Parity pins ----------------------------------------------------

  # Each parity test's expected values by check name.
  expectedValues =
    suite: flatten:
    lib.concatMapAttrs (
      test: case: lib.optionalAttrs (case ? expected) (flatten "${suite}.${test}" case.expected)
    ) paritySuites.${suite};

  # A test that expects an attrset or list of strings yields one pin per
  # entry.
  textValues =
    name: expected:
    if lib.isString expected then
      { ${name} = expected; }
    else if lib.isList expected then
      lib.listToAttrs (lib.imap0 (index: lib.nameValuePair "${name}.${toString index}") expected)
    else
      lib.mapAttrs' (key: lib.nameValuePair "${name}.${key}") expected;

  # Commands that act on an object that must already exist.
  existingVerbs = [
    "delete"
    "flush"
    "list"
    "rename"
    "replace"
    "reset"
  ];

  # The tables and chains a command refers to. `name` is the object's own
  # name, for a table or chain command that needs it to exist, or the
  # chain, for a rule. A command that selects its object by handle has no
  # `name`, and the check's context loads the object.
  scopeState =
    {
      verb,
      kind,
      family,
      table ? null,
      name ? null,
    }:
    let
      existing = builtins.elem verb existingVerbs && name != null;
    in
    if kind == "table" then
      lib.optional existing "add table ${family} ${name}"
    else
      [ "add table ${family} ${table}" ]
      ++ lib.optional (
        kind == "rule" || kind == "chain" && existing
      ) "add chain ${family} ${table} ${name}";

  # `<verb> <kind> <family> <table> [<name>]` on one imperative line.
  commandLine = builtins.match "(add|create|insert|replace|delete|destroy|flush|reset|rename|list) (table|rule|chain|set|map|element|flowtable|counter|quota|limit|ct count|ct helper|ct timeout|ct expectation|synproxy|tunnel|secmark) ([a-z0-9]+) ([^ ]+)( ([^ ]+))?.*";

  stateLines = lines: lib.concatMapStrings (line: "${line}\n") (lib.unique lines);

  # A line's object name, or null where `handle` selects the object.
  nameWord = word: if word == "handle" then null else word;

  # The tables and chains the imperative lines of `text` refer to.
  derivedState =
    text:
    lib.pipe text [
      (lib.splitString "\n")
      (map commandLine)
      (builtins.filter (fields: fields != null))
      (lib.concatMap (
        fields:
        let
          kind = builtins.elemAt fields 1;
          family = builtins.elemAt fields 2;
          fourth = builtins.elemAt fields 3;
          fifth = builtins.elemAt fields 5;
        in
        scopeState (
          {
            verb = builtins.elemAt fields 0;
            inherit family kind;
          }
          // (
            if kind == "table" then
              { name = nameWord fourth; }
            else
              {
                table = fourth;
                name = nameWord fifth;
              }
          )
        )
      ))
      stateLines
    ];

  textChecks = lib.mapAttrs (name: subject: {
    inherit subject;
    state = derivedState subject + checkContexts.${name}.state or "";
  }) (expectedValues "textParity" textValues);

  # Block pins are the contents of a `table inet t { … }` wrapper.
  blockChecks = lib.mapAttrs (name: pin: {
    subject = "table inet t {\n${pin}}\n";
    state = checkContexts.${name}.state or "";
  }) (expectedValues "textBlockParity" textValues);

  # ---- DSL parity JSON values -----------------------------------------

  commandVerbs = [
    "add"
    "create"
    "delete"
    "destroy"
    "flush"
    "insert"
    "list"
    "rename"
    "replace"
    "reset"
  ];

  tagsOf = import ../helpers/tags-of.nix;
  statementTags = tagsOf nftlib.types.statement;
  expressionTags = tagsOf nftlib.types.expression;

  # Whether a tagged value is a command. `reset` is also a statement, whose
  # body is a tagged expression, such as a set; a reset command's object
  # names its family.
  isCommand =
    value:
    let
      tag = jsonTag value;
    in
    builtins.elem tag commandVerbs && (tag != "reset" || isResetCommand value.reset);

  isResetCommand =
    body:
    let
      object = body.${jsonTag body};
    in
    lib.isAttrs object && object ? family;

  # Whether a tagged value is a statement. A tag both unions share is a
  # statement when it's a verdict, when its body has an `op` (set and map
  # statements), or when it's a tunnel reference.
  isStatement =
    value:
    let
      tag = jsonTag value;
      body = value.${tag};
    in
    builtins.elem tag statementTags
    && (
      !(builtins.elem tag expressionTags)
      || body == null
      || body ? target
      || body ? op
      || (tag == "tunnel" && lib.isString body)
    );

  # The tables and chains a command value refers to.
  commandState =
    command:
    let
      verb = jsonTag command;
      kind = jsonTag command.${verb};
      body = command.${verb}.${kind};
    in
    stateLines (
      lib.optionals (body ? table || kind == "table") (scopeState {
        inherit verb kind;
        inherit (body) family;
        table = body.table or null;
        name = if kind == "rule" then body.chain else body.name or null;
      })
    );

  # The ruleset that loads one expected DSL parity value.
  jsonSubject =
    name: value:
    let
      overrides = removeAttrs (checkContexts.${name} or { }) [
        "jsonState"
        "state"
      ];
      ruleContext =
        (
          if isStatement value then
            defaultRuleContext // statementContexts.${jsonTag value} or { }
          else
            expressionRuleContext value
        )
        // overrides;
    in
    if value ? nftables then
      value
    else if isCommand value then
      { nftables = [ value ]; }
    else if ruleContext ? commands then
      { nftables = ruleContext.commands value; }
    else if isStatement value then
      { nftables = ruleCommands ruleContext [ value ]; }
    else
      { nftables = ruleCommands ruleContext [ (ruleContext.statement value) ]; };

  # Expected values that are nft JSON objects, decoded.
  jsonValues =
    name: expected:
    let
      value = if lib.isString expected then builtins.fromJSON expected else expected;
    in
    lib.optionalAttrs (lib.isAttrs value) { ${name} = value; };

  jsonChecks = lib.mapAttrs (
    name: value:
    let
      context = checkContexts.${name} or { };
    in
    {
      subject = builtins.toJSON (jsonSubject name value);
      json = true;
    }
    // (
      if context ? jsonState then
        {
          state = builtins.toJSON context.jsonState;
          stateJson = true;
        }
      else
        { state = lib.optionalString (isCommand value) (commandState value) + context.state or ""; }
    )
  ) (expectedValues "dslParity" jsonValues);

  # ---- Expected rejections --------------------------------------------

  noCtCountObject = {
    reason = "nft 1.1.6 has no ct count object (ADR 0010)";
    rejectedBefore = "1.1.7";
  };

  noSelinux = {
    reason = "a secmark object needs SELinux, which the test kernel lacks";
    error = "No such file or directory";
  };
in
{
  contexts = checkContexts;

  checks = lib.mapAttrs (
    _: check:
    {
      json = false;
      state = "";
      stateJson = false;
    }
    // check
  ) (leafChecks // textChecks // blockChecks // jsonChecks);

  expectedRejections = {
    "dslParity.testCmdCreateCtCount" = noCtCountObject // {
      error = "Unknown object passed to add command";
    };
    "dslParity.testCtCountRef" = noCtCountObject // {
      error = "syntax error, unexpected count";
    };
    "dslParity.testCtCountRefAtName" = noCtCountObject // {
      error = "syntax error, unexpected count";
    };
    "dslParity.testCtCountRefMap" = noCtCountObject // {
      error = "Invalid datatype 'ct count'";
    };
    "dslParity.testDccpOption" = {
      reason = "Linux 6.16 removed DCCP, and with it DCCP option matching";
      kernelFrom = "6.16";
      error = "Operation not supported";
    };
    # nft 1.1.6 stops at the ct count object.
    "dslParity.testRenderAllObjectKinds" = noSelinux // {
      error = [
        "Unknown object passed to add command"
        "No such file or directory"
      ];
    };
    "dslParity.testMapStmtStatements" = {
      reason = "nft 1.1.6's JSON parser crashes on a map statement's per-element statements";
      rejectedBefore = "1.1.7";
      error = "Segmentation fault";
    };
    "dslParity.testSecmark" = noSelinux;
    "dslParity.testSecmarkAtName" = noSelinux;
    # The kernel, not the parser, refuses it: the brace form failed with
    # "syntax error, unexpected '{'".
    "textParity.testCreateSecmarkIsPositional" = noSelinux;
    "textParity.testCtCountNamedReference" = noCtCountObject // {
      error = "syntax error, unexpected count";
    };
    "textParity.testCtCountObjectOver" = noCtCountObject // {
      error = "syntax error, unexpected count";
    };
    "textParity.testCtCountObjectUntil" = noCtCountObject // {
      error = "syntax error, unexpected count";
    };
    "textParity.testStatefulMapReferences.3" = noCtCountObject // {
      error = "syntax error, unexpected count";
    };
  };
}
