/*
  The public surface, pinned as literal name lists: the top level, `types`
  and its per-variant namespaces, `enums`, `compatibility`, and the DSL's
  top level and `expr`. Removing, renaming or adding an export fails here
  until the list follows. The verb namespaces and `dsl.fields` are pinned
  in dsl-parity and parse-check-inputs.

  docs/api.md names every top-level, `dsl`, `dsl.expr`, and
  `compatibility` export, and the `testApiDocs*` tests fail on a name it
  leaves out. It documents bodies and enums by pattern, so their names are
  not checked there.
*/
{ lib, nftlib, ... }:
let
  inherit (nftlib) dsl types;

  # The text of every code span and code block in docs/api.md. A run of
  # backticks opens code, and only a run of the same length closes it, so
  # the backticks inside a code block or a double-backtick span stay code.
  apiDocCode =
    (lib.foldl'
      (
        state: part:
        if builtins.isList part then
          let
            run = builtins.head part;
          in
          if state.fence == 0 then
            state // { fence = builtins.stringLength run; }
          else if builtins.stringLength run == state.fence then
            state // { fence = 0; }
          else
            state // { code = state.code ++ [ run ]; }
        else if state.fence > 0 then
          state // { code = state.code ++ [ part ]; }
        else
          state
      )
      {
        fence = 0;
        code = [ ];
      }
      (builtins.split "(`+)" (builtins.readFile ../../docs/api.md))
    ).code;

  # Every leading part of each dotted path in the doc's code, as a set:
  # `dsl.expr.ct { … }` gives `dsl`, `dsl.expr`, and `dsl.expr.ct`.
  apiDocPaths = lib.pipe apiDocCode [
    (lib.concatMap (builtins.split "[^A-Za-z0-9_.]+"))
    (builtins.filter (token: builtins.isString token && token != ""))
    (lib.concatMap (
      token:
      let
        segments = lib.splitString "." token;
      in
      lib.genList (count: lib.concatStringsSep "." (lib.take (count + 1) segments)) (
        builtins.length segments
      )
    ))
    (map (path: lib.nameValuePair path true))
    builtins.listToAttrs
  ];

  # `unmentionedIn qualifiers names`: the names the doc's code never writes
  # after one of the qualifiers, such as `""` for the name alone or `dsl.`
  # for `dsl.ruleset`.
  unmentionedIn =
    qualifiers:
    builtins.filter (name: !builtins.any (qualifier: apiDocPaths ? "${qualifier}${name}") qualifiers);
in
{
  testApiDocsNameTopLevelExports = {
    expr = unmentionedIn [
      ""
      "nftlib."
    ] (builtins.attrNames nftlib);
    expected = [ ];
  };

  testApiDocsNameDslExports = {
    expr = unmentionedIn [
      ""
      "dsl."
      "nftlib.dsl."
    ] (builtins.attrNames dsl);
    expected = [ ];
  };

  # An `expr` name, such as `set` or `ct`, is also a statement's or a
  # field's, so the doc names it as `expr.<name>`.
  testApiDocsNameDslExprExports = {
    expr = unmentionedIn [
      "expr."
      "dsl.expr."
      "nftlib.dsl.expr."
    ] (builtins.attrNames dsl.expr);
    expected = [ ];
  };

  testApiDocsNameCompatibilityExports = {
    expr = unmentionedIn [
      ""
      "compatibility."
      "nftlib.compatibility."
    ] (builtins.attrNames nftlib.compatibility);
    expected = [ ];
  };

  testTopLevelExports = {
    expr = builtins.attrNames nftlib;
    expected = [
      "compatibility"
      "dsl"
      "enums"
      "toJson"
      "toText"
      "toTextBlock"
      "toTextBlockPretty"
      "toTextPretty"
      "types"
      "validate"
    ];
  };

  testTypesExports = {
    expr = builtins.attrNames types;
    expected = [
      "addObject"
      "byteUnit"
      "chainPolicy"
      "chainType"
      "command"
      "comment"
      "createObject"
      "ctDirection"
      "ctKey"
      "ctL3Protocol"
      "deleteObject"
      "destroyObject"
      "expression"
      "expressionBodies"
      "expressionOf"
      "family"
      "fibFlag"
      "fibResult"
      "flowOperator"
      "flowtableHook"
      "flushObject"
      "hook"
      "ifname"
      "insertObject"
      "ipFamily"
      "ipsecDirection"
      "ipsecKey"
      "limitRateUnit"
      "listObject"
      "logFlag"
      "logLevel"
      "logPrefix"
      "matchOperator"
      "metaKey"
      "namedReference"
      "natFlag"
      "natTypeFlag"
      "nullLiteral"
      "numgenMode"
      "objectBodies"
      "osfKey"
      "osfTtl"
      "payloadBase"
      "portNumber"
      "prefixLength"
      "queueFlag"
      "readBackObject"
      "rejectType"
      "renameObject"
      "replaceObject"
      "resetObject"
      "rtKey"
      "ruleset"
      "setFlag"
      "setOperator"
      "setPolicy"
      "socketKey"
      "statement"
      "statementBodies"
      "statementOf"
      "synproxyFlag"
      "tableFlag"
      "tcpUdpProtocol"
      "timeUnit"
      "tunnelErspanDirection"
      "tunnelKey"
      "tunnelType"
      "xtType"
    ];
  };

  testExpressionBodyExports = {
    expr = builtins.attrNames types.expressionBodies;
    expected = [
      "binaryOperationBody"
      "concatBody"
      "ctBody"
      "dccpOptionBody"
      "elemBody"
      "elemReadBackBody"
      "exthdrBody"
      "fibBody"
      "ipOptionBody"
      "ipsecBody"
      "jhashBody"
      "mapBody"
      "metaBody"
      "numgenBody"
      "osfBody"
      "payloadBody"
      "payloadNamedBody"
      "payloadRawBody"
      "payloadTunnelBody"
      "prefixBody"
      "rangeBody"
      "rtBody"
      "sctpChunkBody"
      "setBody"
      "socketBody"
      "symhashBody"
      "tcpOptionBody"
      "tcpOptionNamedBody"
      "tcpOptionRawBody"
      "tunnelBody"
      "verdictTargetBody"
    ];
  };

  testStatementBodyExports = {
    expr = builtins.attrNames types.statementBodies;
    expected = [
      "counterBody"
      "ctCountBody"
      "dupBody"
      "flowBody"
      "fwdBody"
      "lastBody"
      "limitBody"
      "logBody"
      "mangleBody"
      "mapBody"
      "masqueradeBody"
      "matchBody"
      "meterBody"
      "natBody"
      "objectReferenceBody"
      "queueBody"
      "quotaBody"
      "rejectBody"
      "resetBody"
      "setBody"
      "synproxyBody"
      "tproxyBody"
      "verdictTargetBody"
      "vmapBody"
      "xtBody"
    ];
  };

  testObjectBodyExports = {
    expr = builtins.attrNames types.objectBodies;
    expected = [
      "addRuleBody"
      "chainBody"
      "counterBody"
      "ctCountBody"
      "ctExpectationBody"
      "ctHelperBody"
      "ctTimeoutBody"
      "deleteChainBody"
      "deleteCounterBody"
      "deleteFlowtableBody"
      "deleteLimitBody"
      "deleteMapBody"
      "deleteQuotaBody"
      "deleteSecmarkBody"
      "deleteSetBody"
      "deleteSynproxyBody"
      "deleteTableBody"
      "elementBody"
      "flowtableBody"
      "insertRuleBody"
      "limitBody"
      "mapBody"
      "metainfoBody"
      "meterBody"
      "quotaBody"
      "renameChainBody"
      "replaceRuleBody"
      "secmarkBody"
      "selectChainBody"
      "selectCounterBody"
      "selectCtHelperBody"
      "selectElementBody"
      "selectFlowtableBody"
      "selectLimitBody"
      "selectMapBody"
      "selectMeterBody"
      "selectQuotaBody"
      "selectRuleBody"
      "selectRulesetBody"
      "selectSecmarkBody"
      "selectSetBody"
      "selectSynproxyBody"
      "selectTableBody"
      "setBody"
      "synproxyBody"
      "tableBody"
      "tunnelBody"
      "tunnelEncapsulationBody"
      "tunnelErspanV1Body"
      "tunnelErspanV2Body"
      "tunnelGeneveOptionBody"
      "tunnelVxlanBody"
    ];
  };

  testEnumExports = {
    expr = builtins.attrNames nftlib.enums;
    expected = [
      "byteUnit"
      "chainPolicy"
      "chainType"
      "ctDirection"
      "ctKey"
      "ctL3Protocol"
      "family"
      "fibFlag"
      "fibResult"
      "flowOperator"
      "flowtableHook"
      "hook"
      "ipFamily"
      "ipsecDirection"
      "ipsecKey"
      "limitRateUnit"
      "logFlag"
      "logLevel"
      "matchOperator"
      "metaKey"
      "natFlag"
      "natTypeFlag"
      "numgenMode"
      "osfKey"
      "osfTtl"
      "payloadBase"
      "payloadFieldsByProtocol"
      "queueFlag"
      "rejectType"
      "rtKey"
      "setFlag"
      "setOperator"
      "setPolicy"
      "socketKey"
      "synproxyFlag"
      "tableFlag"
      "tcpUdpProtocol"
      "timeUnit"
      "tunnelErspanDirection"
      "tunnelKey"
      "tunnelType"
      "xtType"
    ];
  };

  testCompatibilityExports = {
    expr = builtins.attrNames nftlib.compatibility;
    expected = [
      "familiesByChainType"
      "hooksByChainType"
      "hooksByFamily"
      "prioritiesByFamily"
      "priorityName"
      "priorityValue"
      "validChainPlacement"
    ];
  };

  testDslExports = {
    expr = builtins.attrNames dsl;
    expected = [
      "accept"
      "add"
      "continue"
      "counter"
      "create"
      "ctCount"
      "ctExpectation"
      "ctHelper"
      "ctTimeout"
      "delete"
      "destroy"
      "dnat"
      "drop"
      "dup"
      "eq"
      "expr"
      "fields"
      "flow"
      "flush"
      "fwd"
      "ge"
      "goto"
      "gt"
      "hasAnyFlag"
      "inSet"
      "insert"
      "jump"
      "last"
      "le"
      "limit"
      "list"
      "log"
      "lt"
      "mangle"
      "mapStmt"
      "masquerade"
      "meter"
      "ne"
      "notInSet"
      "notrack"
      "queue"
      "quota"
      "redirect"
      "reject"
      "rename"
      "replace"
      "reset"
      "resetStmt"
      "return"
      "ruleset"
      "secmark"
      "setStmt"
      "snat"
      "synproxy"
      "table"
      "tproxy"
      "tunnel"
      "vmap"
    ];
  };

  testDslExprExports = {
    expr = builtins.attrNames dsl.expr;
    expected = [
      "bitAnd"
      "bitOr"
      "bitXor"
      "concat"
      "ct"
      "dccpOption"
      "elem"
      "exthdr"
      "fib"
      "ipOption"
      "ipsec"
      "jhash"
      "map"
      "numgen"
      "osf"
      "payload"
      "payloadRaw"
      "payloadTunnel"
      "prefix"
      "range"
      "rt"
      "sctpChunk"
      "set"
      "setRef"
      "shiftLeft"
      "shiftRight"
      "symhash"
      "tcpOption"
      "tcpOptionRaw"
    ];
  };
}
