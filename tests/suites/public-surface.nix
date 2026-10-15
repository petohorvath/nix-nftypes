/*
  The public surface docs/api.md documents, pinned as literal name lists:
  the top level, `types` and its per-variant namespaces, `enums`,
  `compatibility`, and the DSL's top level, `expr` and `match`. Removing,
  renaming or adding an export fails here until the list (and api.md)
  follows. The verb namespaces and `dsl.fields` are pinned in dsl-parity
  and parse-check-inputs.
*/
{ helpers, nftlib, ... }:
let
  inherit (nftlib) dsl types;
in
{
  testTopLevelExports = {
    expr = builtins.attrNames nftlib;
    expected = [
      "chainTypeFor"
      "cleanValue"
      "compatibility"
      "dsl"
      "enums"
      "priorityNameOf"
      "resolvePriority"
      "toJson"
      "toNix"
      "toText"
      "toTextBlock"
      "toTextBlockPretty"
      "toTextPretty"
      "types"
      "validChainPlacement"
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
      "ipFamily"
      "limitUnit"
      "listObject"
      "logFlag"
      "logLevel"
      "logPrefix"
      "matchStatement"
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
      "tunnelExprBody"
      "tunnelPayloadBody"
      "verdictTargetBody"
    ];
  };

  testStatementBodyExports = {
    expr = builtins.attrNames types.statements;
    expected = [
      "counterRefOrBody"
      "ctCountBody"
      "ctCountRefOrBody"
      "dupBody"
      "flowBody"
      "fwdBody"
      "lastBody"
      "limitRefOrBody"
      "logBody"
      "mangleBody"
      "mapStatementBody"
      "masqueradeBody"
      "matchBody"
      "meterBody"
      "natBody"
      "queueBody"
      "quotaRefOrBody"
      "rejectBody"
      "resetBody"
      "setStatementBody"
      "synproxyAnonBody"
      "synproxyStatementBody"
      "tproxyBody"
      "vmapBody"
      "xtBody"
    ];
  };

  testObjectBodyExports = {
    expr = builtins.attrNames types.objects;
    expected = [
      "addRuleBody"
      "chain"
      "chainBody"
      "counter"
      "counterObjectBody"
      "ctCount"
      "ctCountObjectBody"
      "ctExpectation"
      "ctExpectationObjectBody"
      "ctHelper"
      "ctHelperObjectBody"
      "ctTimeout"
      "ctTimeoutObjectBody"
      "element"
      "elementBody"
      "flowtable"
      "flowtableBody"
      "limit"
      "limitObjectBody"
      "map"
      "mapObjectBody"
      "metainfo"
      "metainfoBody"
      "meterObjectBody"
      "quota"
      "quotaObjectBody"
      "renameChainBody"
      "replaceRuleBody"
      "rule"
      "ruleBody"
      "ruleset"
      "rulesetBody"
      "secmark"
      "secmarkObjectBody"
      "selectFlowtableBody"
      "selectLimitBody"
      "selectMapBody"
      "selectRuleBody"
      "selectSetBody"
      "selectSynproxyBody"
      "set"
      "setObjectBody"
      "synproxy"
      "synproxyObjectBody"
      "table"
      "tableBody"
      "tunnel"
      "tunnelErspanV1Nested"
      "tunnelErspanV2Nested"
      "tunnelGeneveOpt"
      "tunnelNestedBody"
      "tunnelObjectBody"
      "tunnelVxlanNested"
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
      "familiesByChainType"
      "hooksByChainType"
      "hooksByFamily"
      "hooksWithOifname"
      "priorityIntsBridge"
      "priorityIntsByFamily"
      "priorityIntsDefault"
    ];
  };

  # The DSL's flat namespace merges its layers; a name two layers define
  # throws instead of one layer silently shadowing the other.
  testDslLayerCollisionThrows = {
    expr = helpers.internals.dslMergeDisjoint {
      ops.match = 1;
      verdicts = {
        accept = 2;
        match = 3;
      };
    };
    expectedError.msg = "nix-nftypes: dsl: `match' is defined by both ops and verdicts";
  };

  testDslLayersMerge = {
    expr = helpers.internals.dslMergeDisjoint {
      ops.eq = 1;
      verdicts.accept = 2;
    };
    expected = {
      eq = 1;
      accept = 2;
    };
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
      "inSet"
      "insert"
      "jump"
      "last"
      "lastUsed"
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
      "payload"
      "payloadRaw"
      "payloadTunnel"
      "queue"
      "quota"
      "redirect"
      "reject"
      "rename"
      "replace"
      "reset"
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
      "within"
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
      "meta"
      "numgen"
      "osf"
      "prefix"
      "range"
      "rshift"
      "rt"
      "sctpChunk"
      "set"
      "setRef"
      "socket"
      "symhash"
      "tcpOption"
      "tcpOptionRaw"
    ];
  };

  testDslMatchExports = {
    expr = builtins.attrNames dsl.match;
    expected = [
      "eq"
      "ge"
      "gt"
      "in_"
      "le"
      "lt"
      "ne"
      "raw"
    ];
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
