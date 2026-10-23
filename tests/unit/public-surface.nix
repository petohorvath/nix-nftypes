/*
  The public surface docs/api.md documents, pinned as literal name lists:
  the top level, `types` and its per-variant namespaces, `enums`,
  `compatibility`, and the DSL's top level, `expr` and `match`. Removing,
  renaming or adding an export fails here until the list (and api.md)
  follows. The verb namespaces and `dsl.fields` are pinned in dsl-parity
  and parse-check-inputs.
*/
{ nftlib, ... }:
let
  inherit (nftlib) dsl types;
in
{
  testTopLevelExports = {
    expr = builtins.attrNames nftlib;
    expected = [
      "cleanValue"
      "compatibility"
      "dsl"
      "enums"
      "toJson"
      "toNix"
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
      "chainType"
      "command"
      "createObject"
      "ctDirection"
      "ctL3Proto"
      "deleteObject"
      "expression"
      "expressionOf"
      "expressions"
      "family"
      "fibFlag"
      "fibResult"
      "flowOp"
      "flushObject"
      "hook"
      "ifname"
      "insertObject"
      "ipFamily"
      "limitUnit"
      "listObject"
      "logFlag"
      "logLevel"
      "logPrefix"
      "metaKey"
      "namedReference"
      "natFlag"
      "natTypeFlag"
      "nftQuotedString"
      "ngMode"
      "nullLiteral"
      "objects"
      "operator"
      "osfKey"
      "osfTtl"
      "payloadBase"
      "perUnit"
      "policy"
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
      "setOp"
      "setPolicy"
      "socketKey"
      "statement"
      "statementOf"
      "statements"
      "synproxyFlag"
      "tableFlag"
      "taggedExpression"
      "tcpUdpProto"
      "tunnelKey"
      "tunnelType"
      "xfrmDir"
      "xfrmKey"
      "xtType"
    ];
  };

  testExpressionBodyExports = {
    expr = builtins.attrNames types.expressions;
    expected = [
      "binaryOpBody"
      "concatBody"
      "ctBody"
      "dccpOptionBody"
      "elemBody"
      "exthdrBody"
      "fibBody"
      "ipOptionBody"
      "ipsecBody"
      "jhashBody"
      "mapBody"
      "metaBody"
      "namedPayloadBody"
      "namedTcpOptionBody"
      "numgenBody"
      "osfBody"
      "payloadBody"
      "prefixBody"
      "rangeBody"
      "rawPayloadBody"
      "rawTcpOptionBody"
      "rtBody"
      "sctpChunkBody"
      "setBody"
      "socketBody"
      "symhashBody"
      "tcpOptionBody"
      "tunnelBody"
      "tunnelPayloadBody"
      "verdictTargetBody"
    ];
  };

  testStatementBodyExports = {
    expr = builtins.attrNames types.statements;
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
      "queueBody"
      "quotaBody"
      "rejectBody"
      "resetBody"
      "setBody"
      "synproxyBody"
      "tproxyBody"
      "vmapBody"
      "xtBody"
    ];
  };

  testObjectBodyExports = {
    expr = builtins.attrNames types.objects;
    expected = [
      "addRuleBody"
      "chainBody"
      "counterBody"
      "ctCountBody"
      "ctExpectationBody"
      "ctHelperBody"
      "ctTimeoutBody"
      "elementBody"
      "flowtableBody"
      "flushRulesetBody"
      "limitBody"
      "mapBody"
      "metainfoBody"
      "meterBody"
      "quotaBody"
      "renameChainBody"
      "replaceRuleBody"
      "ruleBody"
      "secmarkBody"
      "selectFlowtableBody"
      "selectLimitBody"
      "selectMapBody"
      "selectRuleBody"
      "selectSetBody"
      "selectSynproxyBody"
      "setBody"
      "synproxyBody"
      "tableBody"
      "tunnelBody"
      "tunnelErspanV1Body"
      "tunnelErspanV2Body"
      "tunnelGeneveOptionBody"
      "tunnelNestedBody"
      "tunnelVxlanBody"
    ];
  };

  testEnumExports = {
    expr = builtins.attrNames nftlib.enums;
    expected = [
      "chainType"
      "ctDirection"
      "ctL3Proto"
      "family"
      "fibFlag"
      "fibResult"
      "flowOp"
      "hook"
      "ipFamily"
      "limitUnit"
      "logFlag"
      "logLevel"
      "metaKey"
      "natFlag"
      "natTypeFlag"
      "ngMode"
      "operator"
      "osfKey"
      "osfTtl"
      "payloadBase"
      "perUnit"
      "policy"
      "queueFlag"
      "rejectType"
      "rtKey"
      "setFlag"
      "setOp"
      "setPolicy"
      "socketKey"
      "synproxyFlag"
      "tableFlag"
      "tcpUdpProto"
      "tunnelKey"
      "tunnelType"
      "xfrmDir"
      "xfrmKey"
      "xtType"
    ];
  };

  testCompatibilityExports = {
    expr = builtins.attrNames nftlib.compatibility;
    expected = [
      "chainTypeFor"
      "familiesByChainType"
      "hooksByChainType"
      "hooksByFamily"
      "hooksWithOifname"
      "priorityIntsByFamily"
      "priorityNameOf"
      "resolvePriority"
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
      "match"
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
      "xt"
    ];
  };

  testDslExprExports = {
    expr = builtins.attrNames dsl.expr;
    expected = [
      "bitand"
      "bitor"
      "bitxor"
      "concat"
      "ct"
      "dccpOption"
      "elem"
      "exthdr"
      "fib"
      "ipOption"
      "ipsec"
      "jhash"
      "lshift"
      "map"
      "mapRef"
      "numgen"
      "osf"
      "payload"
      "payloadRaw"
      "payloadTunnel"
      "prefix"
      "range"
      "rshift"
      "rt"
      "sctpChunk"
      "set"
      "setRef"
      "symhash"
      "tcpOption"
      "tcpOptionRaw"
    ];
  };

  testDslMatchExports = {
    expr = builtins.attrNames dsl.match;
    expected = [ "raw" ];
  };

  # toNix is a diagnostic formatter: cleaned (no unset nulls, no markers,
  # tagged nulls kept) and one binding per line.
  testToNixPrintsCleanedValueOneBindingPerLine = {
    expr = nftlib.toNix {
      nftables = [
        {
          add.table = {
            family = "inet";
            name = "t";
            comment = null;
            _type = "marker";
          };
        }
        {
          add.rule = {
            family = "inet";
            table = "t";
            chain = "c";
            expr = [ { accept = null; } ];
          };
        }
      ];
    };
    expected = ''
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
              rule = {
                chain = "c";
                expr = [
                  {
                    accept = null;
                  }
                ];
                family = "inet";
                table = "t";
              };
            };
          }
        ];
      }'';
  };
}
