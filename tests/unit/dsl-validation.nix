{
  helpers,
  internal,
  lib,
  nftlib,
  ...
}:

# DSL-level validation tests. Each case constructs a DSL value with a
# clearly-invalid field and asserts that evaluation throws — proving the
# DSL surface routes user input through the matching schema submodule
# instead of letting type errors leak into the rendered JSON (where
# `nft -j -f` silently drops broken sections).
#
# Where the message matters, a case asserts it with `expectedError.msg`:
# the error must name the offending path (e.g. "chains.c.prio"), not just
# report that something is wrong.

let
  inherit (helpers) capitalise commandJson;
  inherit (nftlib) dsl toJson;

  # Force a DSL value in full, as rendering it would.
  force = value: builtins.deepSeq value value;

  # Ownership is a property of table trees, shared by command and block
  # output. Use valid but conflicting values so schema type errors cannot
  # mask a missing scope check. The sibling exists in the rule-chain case:
  # redirecting a rule to another declared chain must still be rejected.
  scopeConflicts = {
    tableFamily.family = "ip";
    tableName.name = "other";
    chainFamily.chains.input.family = "ip";
    chainTable.chains.input.table = "other";
    chainName.chains.input.name = "other";
    objectFamily.counters.hits.family = "ip";
    objectTable.counters.hits.table = "other";
    objectName.counters.hits.name = "other";
    ruleFamily.chains.input.rules = [
      {
        family = "ip";
        statements = [ dsl.accept ];
      }
    ];
    ruleTable.chains.input.rules = [
      {
        table = "other";
        statements = [ dsl.accept ];
      }
    ];
    ruleChain.chains = {
      input.rules = [
        {
          chain = "output";
          statements = [ dsl.accept ];
        }
      ];
      output = { };
    };
  };
  # Each conflict's error must name the conflicting field's tree path.
  scopeConflictPaths = {
    tableFamily = "family";
    tableName = "name";
    chainFamily = "chains.input.family";
    chainTable = "chains.input.table";
    chainName = "chains.input.name";
    objectFamily = "counters.hits.family";
    objectTable = "counters.hits.table";
    objectName = "counters.hits.name";
    ruleFamily = "chains.input.rules.0.family";
    ruleTable = "chains.input.rules.0.table";
    ruleChain = "chains.input.rules.0.chain";
  };
  tableRenderers = {
    json = node: toJson (dsl.ruleset [ node ]);
    text = node: nftlib.toText (dsl.ruleset [ node ]);
    textPretty = node: nftlib.toTextPretty (dsl.ruleset [ node ]);
    block = nftlib.toTextBlock;
    blockPretty = nftlib.toTextBlockPretty;
  };
  scopeTests = lib.concatMapAttrs (
    name: body:
    lib.mapAttrs' (
      form: render:
      lib.nameValuePair "testTreeScope_${name}_${form}" {
        expr = render (dsl.table "inet" "fw" body);
        expectedError.msg = "nix-nftypes: dsl\\.table inet\\.fw: ${
          lib.escapeRegex scopeConflictPaths.${name}
        }: must match its table-tree scope";
      }
    ) tableRenderers
  ) scopeConflicts;

  /*
    Inputs the DSL used to drop or misread without an error. Each must throw
    an error that names its field (`msg`, a regex), and the throw must be
    one `builtins.tryEval` catches: an import of a module path, for one,
    aborts evaluation instead.
  */
  droppedInputs = {
    tableBodyFamily = {
      value = dsl.ruleset [ (dsl.table "inet" "t" { family = "ip"; }) ];
      msg = "nix-nftypes: dsl\\.table inet\\.t: family: must match its table-tree scope \"inet\", got \"ip\"";
    };
    inSetBareString = {
      value = dsl.inSet dsl.fields.ip.saddr "blocked";
      msg = "inSet: .*\"blocked\".*expr\\.setRef";
    };
    notInSetBareString = {
      value = dsl.notInSet dsl.fields.ip.saddr "blocked";
      msg = "notInSet: .*\"blocked\".*expr\\.setRef";
    };
    swappedMatch = {
      value = dsl.eq 22 dsl.fields.tcp.dport;
      msg = "dsl\\.eq\\.right' is not of type `match right side.*did you swap the left and right sides";
    };
    swappedMangle = {
      value = dsl.mangle 42 dsl.fields.meta.mark;
      msg = "dsl\\.mangle\\.key";
    };
    # A list is nft's flag combination: `ct state == established|related`
    # loads and never matches, and `tcp dport == 22,80` fails to load.
    eqList = {
      value = dsl.eq dsl.fields.ct.state [
        "established"
        "related"
      ];
      msg = "^nix-nftypes: dsl\\.eq: the right side is a list.*`inSet`.*`hasAnyFlag`.*`expr\\.bitOr`";
    };
  }
  // lib.genAttrs' [ "ne" "lt" "gt" "le" "ge" ] (op: {
    name = "${op}List";
    value = {
      value = dsl.${op} dsl.fields.tcp.dport [
        22
        80
      ];
      msg = "^nix-nftypes: dsl\\.${op}: the right side is a list";
    };
  })
  // {
    treeSetGcIntervalJsonSpelling = {
      value = dsl.ruleset [
        (dsl.table "inet" "t" {
          sets.s = {
            type = "ipv4_addr";
            "gc-interval" = 60;
          };
        })
      ];
      msg = "nix-nftypes: dsl\\.table inet\\.t: sets\\.s\\.gc-interval: is the JSON spelling; write `gcInterval`";
    };
    treeSetElemJsonSpelling = {
      value = dsl.ruleset [
        (dsl.table "inet" "t" {
          sets.s = {
            type = "ipv4_addr";
            elem = [ "192.0.2.1" ];
          };
        })
      ];
      msg = "sets\\.s\\.elem: is the JSON spelling; write `elements`";
    };
    addElementElemJsonSpelling = {
      value = dsl.add.element {
        family = "inet";
        table = "t";
        name = "s";
        elem = [ "192.0.2.1" ];
      };
      msg = "nix-nftypes: dsl\\.add\\.element: elem: is the JSON spelling; write `elements`";
    };
    addMapElemJsonSpelling = {
      value = dsl.add.map {
        family = "inet";
        table = "t";
        name = "m";
        type = "ipv4_addr";
        dataType = "mark";
        elem = [ ];
      };
      msg = "nix-nftypes: dsl\\.add\\.map: elem: is the JSON spelling; write `elements`";
    };
    limitJsonSpelling = {
      value = dsl.add.rule {
        family = "inet";
        table = "t";
        chain = "c";
        statements = [
          (dsl.limit {
            rate = 10;
            per = "second";
            rate_unit = "packets";
          })
        ];
      };
      msg = "nix-nftypes: dsl\\.limit: rate_unit: is the JSON spelling; write `rateUnit`";
    };
    logJsonSpelling = {
      value = dsl.add.rule {
        family = "inet";
        table = "t";
        chain = "c";
        statements = [ (dsl.log { "queue-threshold" = 1; }) ];
      };
      msg = "nix-nftypes: dsl\\.log: queue-threshold: is the JSON spelling; write `queueThreshold`";
    };
    quotaJsonSpelling = {
      value = dsl.add.rule {
        family = "inet";
        table = "t";
        chain = "c";
        statements = [
          (dsl.quota {
            val = 1;
            used_unit = "bytes";
          })
        ];
      };
      msg = "nix-nftypes: dsl\\.quota: used_unit: is the JSON spelling; write `usedUnit`";
    };
    snatJsonSpelling = {
      value = dsl.add.rule {
        family = "inet";
        table = "t";
        chain = "c";
        statements = [ (dsl.snat { type_flags = [ "prefix" ]; }) ];
      };
      msg = "nix-nftypes: dsl\\.snat: type_flags: is the JSON spelling; write `typeFlags`";
    };
    addRuleExprJsonSpelling = {
      value = dsl.add.rule {
        family = "inet";
        table = "t";
        chain = "c";
        expr = [ dsl.accept ];
      };
      msg = "nix-nftypes: dsl\\.add\\.rule: expr: is the JSON spelling; write `statements`";
    };
    treeRuleExprJsonSpelling = {
      value = dsl.ruleset [
        (dsl.table "inet" "t" {
          chains.c.rules = [ { expr = [ dsl.accept ]; } ];
        })
      ];
      msg = "nix-nftypes: dsl\\.table inet\\.t: chains\\.c\\.rules\\.0\\.expr: is the JSON spelling; write `statements`";
    };
    renameChainNewnameJsonSpelling = {
      value = dsl.rename.chain {
        family = "inet";
        table = "t";
        name = "old";
        newname = "new";
      };
      msg = "nix-nftypes: dsl\\.rename\\.chain: newname: is the JSON spelling; write `newName`";
    };
    treeSetStmtJsonSpelling = {
      value = dsl.ruleset [
        (dsl.table "inet" "t" {
          sets.s = {
            type = "ipv4_addr";
            stmt = [ dsl.counter.auto ];
          };
        })
      ];
      msg = "sets\\.s\\.stmt: is the JSON spelling; write `statements`";
    };
    setStmtStmtJsonSpelling = {
      value = dsl.add.rule {
        family = "inet";
        table = "t";
        chain = "c";
        statements = [
          (dsl.setStmt {
            op = "add";
            element = dsl.fields.ip.saddr;
            set = "s";
            stmt = [ dsl.counter.auto ];
          })
        ];
      };
      msg = "nix-nftypes: dsl\\.setStmt: stmt: is the JSON spelling; write `statements`";
    };
    mapStmtStmtJsonSpelling = {
      value = dsl.add.rule {
        family = "inet";
        table = "t";
        chain = "c";
        statements = [
          (dsl.mapStmt {
            op = "add";
            key = dsl.fields.ip.saddr;
            data = 1;
            map = "m";
            stmt = [ dsl.counter.auto ];
          })
        ];
      };
      msg = "nix-nftypes: dsl\\.mapStmt: stmt: is the JSON spelling; write `statements`";
    };
    setStmtElemJsonSpelling = {
      value = dsl.add.rule {
        family = "inet";
        table = "t";
        chain = "c";
        statements = [
          (dsl.setStmt {
            op = "add";
            elem = dsl.fields.ip.saddr;
            set = "s";
          })
        ];
      };
      msg = "nix-nftypes: dsl\\.setStmt: elem: is the JSON spelling; write `element`";
    };
    mapStmtElemJsonSpelling = {
      value = dsl.add.rule {
        family = "inet";
        table = "t";
        chain = "c";
        statements = [
          (dsl.mapStmt {
            op = "add";
            elem = dsl.fields.ip.saddr;
            data = 1;
            map = "m";
          })
        ];
      };
      msg = "nix-nftypes: dsl\\.mapStmt: elem: is the JSON spelling; write `key`";
    };
    addMapMapJsonSpelling = {
      value = dsl.add.map {
        family = "inet";
        table = "t";
        name = "m";
        type = "ipv4_addr";
        map = "mark";
      };
      msg = "nix-nftypes: dsl\\.add\\.map: map: is the JSON spelling; write `dataType`";
    };
    treeMapMapJsonSpelling = {
      value = dsl.ruleset [
        (dsl.table "inet" "t" {
          maps.m = {
            type = "ipv4_addr";
            map = "verdict";
          };
        })
      ];
      msg = "nix-nftypes: dsl\\.table inet\\.t: maps\\.m\\.map: is the JSON spelling; write `dataType`";
    };
    rejectExprJsonSpelling = {
      value = dsl.add.rule {
        family = "inet";
        table = "t";
        chain = "c";
        statements = [
          (dsl.reject {
            type = "icmpx";
            expr = "admin-prohibited";
          })
        ];
      };
      msg = "nix-nftypes: dsl\\.reject: expr: is the JSON spelling; write `code`";
    };
    meterStmtJsonSpelling = {
      value = dsl.add.rule {
        family = "inet";
        table = "t";
        chain = "c";
        statements = [
          (dsl.meter {
            name = "m";
            key = dsl.fields.ip.saddr;
            stmt = dsl.counter.auto;
          })
        ];
      };
      msg = "nix-nftypes: dsl\\.meter: stmt: is the JSON spelling; write `statement`";
    };
    addLimitJsonSpelling = {
      value = dsl.add.limit {
        family = "inet";
        table = "t";
        name = "l";
        rate = 10;
        per = "second";
        rate_unit = "packets";
      };
      msg = "nix-nftypes: dsl\\.add\\.limit: rate_unit: is the JSON spelling; write `rateUnit`";
    };
    tableImports = {
      value = dsl.ruleset [ (dsl.table "inet" "t" { imports = [ ]; }) ];
      msg = "nix-nftypes: dsl\\.table inet\\.t: unsupported key.*imports";
    };
    chainImports = {
      value = dsl.ruleset [ (dsl.table "inet" "t" { chains.c.imports = [ ]; }) ];
      msg = "chains\\.c\\.imports";
    };
    chainKey = {
      value = dsl.ruleset [ (dsl.table "inet" "t" { chains.c.key = "k"; }) ];
      msg = "chains\\.c\\.key";
    };
    chainFreeformType = {
      value = dsl.ruleset [
        (dsl.table "inet" "t" {
          chains.c.freeformType = lib.types.anything;
        })
      ];
      msg = "chains\\.c\\.freeformType";
    };
    ruleImports = {
      value = dsl.ruleset [
        (dsl.table "inet" "t" {
          chains.c.rules = [
            {
              imports = [ ];
              statements = [ dsl.accept ];
            }
          ];
        })
      ];
      msg = "chains\\.c\\.rules\\.\"0\"\\.imports";
    };
    counterModule = {
      value = dsl.ruleset [
        (dsl.table "inet" "t" {
          counters.c = {
            _module.check = false;
            bogus = 1;
          };
        })
      ];
      msg = "nix-nftypes: dsl\\.table inet\\.t: counters\\.c\\._module: ";
    };
    addCounterModule = {
      value = dsl.add.counter {
        family = "inet";
        table = "t";
        name = "c";
        _module.check = false;
        bogus = 1;
      };
      msg = "nix-nftypes: dsl\\.add\\.counter: _module: ";
    };
    addCounterImports = {
      value = dsl.add.counter {
        family = "inet";
        table = "t";
        name = "c";
        imports = [ ];
      };
      msg = "add\\.counter\\.imports";
    };
    createCounterName = {
      value = dsl.create.counter "c1";
      msg = "create\\.counter: expected an attribute set of fields, got a string";
    };
    createCounterPathLikeName = {
      value = dsl.create.counter "/c1";
      msg = "create\\.counter: expected an attribute set of fields, got a string";
    };
    renameChainName = {
      value = dsl.rename.chain "/c";
      msg = "rename\\.chain: expected an attribute set of fields, got a string";
    };
    flushRulesetPathLikeName = {
      value = dsl.flush.ruleset "/ip";
      msg = "flush\\.ruleset: expected an attribute set of fields, got a string";
    };
    treeCounterPathLikeName = {
      value = dsl.ruleset [ (dsl.table "inet" "t" { counters.c = "/c1"; }) ];
      msg = "counters\\.c: expected an attribute set of fields, got a string";
    };
    treeChainPathLikeName = {
      value = dsl.ruleset [ (dsl.table "inet" "t" { chains.c = "/c"; }) ];
      msg = "chains\\.c: expected an attribute set of fields, got a string";
    };
    treeRulePathLikeName = {
      value = dsl.ruleset [ (dsl.table "inet" "t" { chains.c.rules = [ "/r" ]; }) ];
      msg = "chains\\.c\\.rules\\.0: expected a list of statements .*, got a string";
    };
    treeRulePathLikeBody = {
      value = dsl.ruleset [
        (dsl.table "inet" "t" {
          chains.c.rules = [ [ { jump = "/c"; } ] ];
        })
      ];
      msg = "chains\\.c\\.rules\\.\"0\"\\.expr.*is not of type";
    };
    tablePathLikeBody = {
      value = dsl.ruleset [ (dsl.table "inet" "t" "/t") ];
      msg = "dsl\\.table inet\\.t: expected an attribute set of fields, got a string";
    };
  };
  /*
    A rule entry is a list of statements or a rule body with statements in
    `statements`. A bare statement such as `dsl.drop` expanded to a rule with no
    statement, so each entry here must throw in every form, naming the
    rule's path and showing the list form.
  */
  malformedRuleEntries = {
    inherit (dsl)
      accept
      continue
      drop
      last
      notrack
      return
      ;
    counterAuto = dsl.counter.auto;
    synproxyAuto = dsl.synproxy.auto;
    jump = dsl.jump "other";
    emptyList = [ ];
    emptyStatements.statements = [ ];
    nullStatements.statements = null;
    commentOnly.comment = "no statements";
    string = "/r";
  };
  malformedRuleEntryTests = lib.concatMapAttrs (
    name: entry:
    lib.mapAttrs' (
      form: render:
      lib.nameValuePair "testMalformedRuleEntryThrows_${name}_${form}" {
        expr = render (dsl.table "inet" "fw" { chains.input.rules = [ entry ]; });
        expectedError.msg = "chains\\.input\\.rules\\.0: .*a list of statements.*\\[ dsl\\.drop \\]";
      }
    ) tableRenderers
    // {
      "testMalformedRuleEntryCatchable_${name}" = {
        expr =
          (builtins.tryEval (
            builtins.deepSeq (toJson (
              dsl.ruleset [ (dsl.table "inet" "fw" { chains.input.rules = [ entry ]; }) ]
            )) null
          )).success;
        expected = false;
      };
    }
  ) malformedRuleEntries;

  /*
    A builder left uncalled among a rule's statements, such as the bare
    `dsl.last` that was a statement in 0.1.0, throws naming the statement's
    path. A Variant namespace with a null form points to its `.auto`.
  */
  uncalledStatements = {
    last = {
      statement = dsl.last;
      msg = "expected a statement, got the Variant namespace `last`; write `last\\.auto` for its null form, or call it with a body$";
    };
    counter = {
      statement = dsl.counter;
      msg = "expected a statement, got the Variant namespace `counter`; write `counter\\.auto` for its null form, or call it with a body$";
    };
    limit = {
      statement = dsl.limit;
      msg = "expected a statement, got a function, such as a builder not yet called; call it to build the statement$";
    };
    jump = {
      statement = dsl.jump;
      msg = "expected a statement, got a function, such as a builder not yet called; call it to build the statement$";
    };
  };
  uncalledStatementTests = lib.concatMapAttrs (
    name: case:
    lib.mapAttrs' (
      form: render:
      lib.nameValuePair "testUncalledStatementThrows_${name}_tableTree_${form}" {
        expr = render (
          dsl.table "inet" "fw" {
            chains.input.rules = [
              [
                dsl.accept
                case.statement
              ]
            ];
          }
        );
        expectedError.msg = "^nix-nftypes: dsl\\.table inet\\.fw: chains\\.input\\.rules\\.0\\.1: ${case.msg}";
      }
    ) tableRenderers
    // {
      "testUncalledStatementThrows_${name}_ruleBodyEntry" = {
        expr = toJson (
          dsl.ruleset [
            (dsl.table "inet" "fw" { chains.input.rules = [ { statements = [ case.statement ]; } ]; })
          ]
        );
        expectedError.msg = "^nix-nftypes: dsl\\.table inet\\.fw: chains\\.input\\.rules\\.0\\.statements\\.0: ${case.msg}";
      };
      "testUncalledStatementThrows_${name}_addRule" = {
        expr = toJson (
          dsl.ruleset [
            (dsl.add.rule {
              family = "inet";
              table = "t";
              chain = "c";
              statements = [ case.statement ];
            })
          ]
        );
        expectedError.msg = "^nix-nftypes: dsl\\.add\\.rule: statements\\.0: ${case.msg}";
      };
    }
  ) uncalledStatements;

  # A rule command needs its statements in `statements`: without them, `add`,
  # `insert`, and `replace` rendered a rule with no statement. Each must
  # throw in JSON and text, naming the command and showing the list form.
  ruleCommandBuilders = {
    "add.rule" = dsl.add.rule;
    "insert.rule" = dsl.insert.rule;
    "replace.rule" = body: dsl.replace.rule (body // { handle = 1; });
  };
  ruleCommandBodies = {
    noStatements = { };
    emptyStatements.statements = [ ];
    nullStatements.statements = null;
  };
  ruleCommandTests = lib.concatMapAttrs (
    verb: build:
    lib.concatMapAttrs (
      name: body:
      let
        value = dsl.ruleset [
          (build (
            {
              family = "inet";
              table = "t";
              chain = "c";
            }
            // body
          ))
        ];
      in
      lib.mapAttrs'
        (
          form: render:
          lib.nameValuePair "testRuleCommandWithoutStatementsThrows_${verb}_${name}_${form}" {
            expr = render value;
            expectedError.msg = "nix-nftypes: dsl\\.${lib.escapeRegex verb}: .*a list of statements.*statements = \\[ dsl\\.drop \\]";
          }
        )
        {
          json = toJson;
          text = nftlib.toText;
        }
    ) ruleCommandBodies
  ) ruleCommandBuilders;

  droppedInputTests = lib.concatMapAttrs (name: case: {
    "testDroppedInputThrows_${name}" = {
      expr = force case.value;
      expectedError.msg = case.msg;
    };
    "testDroppedInputCatchable_${name}" = {
      expr = (builtins.tryEval (force case.value)).success;
      expected = false;
    };
  }) droppedInputs;

  # ----- statement builders validate when called -----------------------

  expression = dsl.fields.ip.saddr;
  # An attrset that is no expression.
  notAnExpression.bogus = 1;

  # The statements with a `.ref` variant.
  referencingStatements = [
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

  /*
    Every statement builder validates its body when called, outside any
    rule, against the body `types.statement` takes for its tag. The module
    system's error names the builder and the field, as a command builder's
    does (`dsl.create.counter.bogus`). `unknown` is the builder called with
    an argument its body lacks, `bogus` unless `unknownField` names
    another, and `wrong` with a value of the wrong type in `field`. A
    builder that takes positional arguments has no unknown argument. A
    builder whose schema body takes whatever it builds, such as `flow`,
    has `msg`, its own check's error, in place of `field`.
  */
  statementBuilderCases =
    let
      withBogus = body: body // { bogus = 1; };
    in
    {
      counter = {
        unknown = dsl.counter (withBogus {
          packets = 0;
          bytes = 0;
        });
        wrong = dsl.counter {
          packets = "many";
          bytes = 0;
        };
        field = "packets";
      };
      last = {
        unknown = dsl.last (withBogus {
          used = 0;
        });
        wrong = dsl.last { used = "never"; };
        field = "used";
      };
      log = {
        unknown = dsl.log (withBogus { });
        wrong = dsl.log { level = "bogus"; };
        field = "level";
      };
      limit = {
        unknown = dsl.limit (withBogus {
          rate = 10;
          per = "second";
        });
        wrong = dsl.limit {
          rate = 10;
          per = "fortnight";
        };
        field = "per";
      };
      quota = {
        unknown = dsl.quota (withBogus {
          val = 1;
        });
        wrong = dsl.quota { val = "lots"; };
        field = "val";
      };
      snat = {
        unknown = dsl.snat (withBogus {
          addr = "192.0.2.1";
        });
        wrong = dsl.snat { addr = notAnExpression; };
        field = "addr";
      };
      dnat = {
        unknown = dsl.dnat (withBogus {
          addr = "192.0.2.1";
        });
        wrong = dsl.dnat {
          addr = "192.0.2.1";
          family = "inet";
        };
        field = "family";
      };
      masquerade = {
        unknown = dsl.masquerade { addr = "192.0.2.1"; };
        wrong = dsl.masquerade { flags = [ "bogus" ]; };
        field = "flags";
        unknownField = "addr";
      };
      redirect = {
        unknown = dsl.redirect { addr = "192.0.2.1"; };
        wrong = dsl.redirect { port = notAnExpression; };
        field = "port";
        unknownField = "addr";
      };
      fwd = {
        unknown = dsl.fwd (withBogus {
          dev = "eth0";
        });
        wrong = dsl.fwd {
          dev = "eth0";
          family = "inet";
        };
        field = "family";
      };
      dup = {
        unknown = dsl.dup (withBogus {
          addr = "192.0.2.1";
        });
        wrong = dsl.dup { addr = notAnExpression; };
        field = "addr";
      };
      tproxy = {
        unknown = dsl.tproxy (withBogus {
          port = 1;
        });
        wrong = dsl.tproxy {
          port = 1;
          family = "inet";
        };
        field = "family";
      };
      queue = {
        unknown = dsl.queue (withBogus { });
        wrong = dsl.queue { flags = [ "bogus" ]; };
        field = "flags";
      };
      reject = {
        unknown = dsl.reject (withBogus { });
        wrong = dsl.reject { type = "bogus"; };
        field = "type";
      };
      synproxy = {
        unknown = dsl.synproxy (withBogus {
          mss = 1460;
          wscale = 7;
        });
        wrong = dsl.synproxy {
          mss = "large";
          wscale = 7;
        };
        field = "mss";
      };
      ctCount = {
        unknown = dsl.ctCount (withBogus {
          val = 1;
        });
        wrong = dsl.ctCount { val = -1; };
        field = "val";
      };
      meter = {
        unknown = dsl.meter (withBogus {
          name = "m";
          key = expression;
          statement = dsl.counter.auto;
        });
        wrong = dsl.meter {
          name = 1;
          key = expression;
          statement = dsl.counter.auto;
        };
        field = "name";
      };
      setStmt = {
        unknown = dsl.setStmt (withBogus {
          op = "add";
          element = expression;
          set = "s";
        });
        wrong = dsl.setStmt {
          op = "bogus";
          element = expression;
          set = "s";
        };
        field = "op";
      };
      mapStmt = {
        unknown = dsl.mapStmt (withBogus {
          op = "add";
          key = expression;
          data = 1;
          map = "m";
        });
        wrong = dsl.mapStmt {
          op = "bogus";
          key = expression;
          data = 1;
          map = "m";
        };
        field = "op";
      };
      mangle = {
        wrong = dsl.mangle notAnExpression 1;
        field = "key";
      };
      vmap = {
        wrong = dsl.vmap notAnExpression { };
        field = "key";
      };
      # `flow` builds its `op` and its `@` reference itself.
      flow = {
        wrong = dsl.flow 1;
        msg = "nix-nftypes: dsl\\.flow: expected a name string, got int";
      };
      jump = {
        wrong = dsl.jump 1;
        field = "target";
      };
      goto = {
        wrong = dsl.goto 1;
        field = "target";
      };
      # The body is the TCP option expression itself.
      resetStmt = {
        wrong = dsl.resetStmt { "tcp option" = 1; };
        field = ''"tcp option"'';
      };
    }
    // lib.listToAttrs (
      map (
        name:
        lib.nameValuePair "${name}.ref" {
          # A raw map expression: `expr.map` would reject the key itself.
          wrong = dsl.${name}.ref {
            map = {
              key = notAnExpression;
              data = "@m";
            };
          };
          field = "value.map.key";
        }
      ) referencingStatements
    );

  statementBuilderTests = lib.concatMapAttrs (
    name: case:
    let
      # The field, or a path inside it such as a list entry's.
      option = field: "`${lib.escapeRegex "dsl.${name}.${field}"}(\\.[^']*)?'";
    in
    {
      "testStatementBuilderWrongValueThrows_${name}" = {
        expr = force case.wrong;
        expectedError.msg = case.msg or "${option case.field} is not of type";
      };
    }
    // lib.optionalAttrs (case ? unknown) {
      "testStatementBuilderUnknownArgumentThrows_${name}" = {
        expr = force case.unknown;
        expectedError.msg = "${option (case.unknownField or "bogus")} does not exist";
      };
    }
  ) statementBuilderCases;

  # ----- expression builders validate when called ----------------------

  /*
    Every `dsl.expr` builder validates its body when called, against the
    body `types.expression` takes for its tag, and the module system's
    error names the builder and the field, as a statement builder's does.
    `wrong` is the builder called with a value of the wrong type in
    `field`. A builder that takes one attrset of fields also has
    `unknown`, called with the argument `bogus` its body lacks, and
    `missing`, called without the required field `required`. A body that
    is no submodule, such as a list, is checked as the option `value`.
  */
  expressionBuilderCases =
    let
      withBogus = body: body // { bogus = 1; };
      # A builder that takes one attrset of fields: `valid` is a body it
      # takes, `wrong` that body with `field` set to `value`, and
      # `missing` the body without `required`.
      fromFields =
        name:
        {
          valid,
          field,
          value,
          required,
        }:
        {
          unknown = dsl.expr.${name} (withBogus valid);
          wrong = dsl.expr.${name} (valid // { ${field} = value; });
          missing = dsl.expr.${name} (removeAttrs valid [ required ]);
          inherit field required;
        };
      binaryOperator = name: {
        wrong = dsl.expr.${name} notAnExpression 1;
        field = "value";
      };
    in
    {
      concat = {
        wrong = dsl.expr.concat [ notAnExpression ];
        field = "value";
      };
      set = {
        wrong = dsl.expr.set [ notAnExpression ];
        field = "value";
      };
      map = {
        wrong = dsl.expr.map notAnExpression "m";
        field = "key";
      };
      prefix = {
        wrong = dsl.expr.prefix "10.0.0.0" 129;
        field = "len";
      };
      range = {
        wrong = dsl.expr.range notAnExpression 1;
        field = "value";
      };
      payload = {
        wrong = dsl.expr.payload 1 "dport";
        field = "protocol";
      };
      dccpOption = {
        wrong = dsl.expr.dccpOption "x";
        field = "type";
      };
      bitAnd = binaryOperator "bitAnd";
      bitOr = binaryOperator "bitOr";
      bitXor = binaryOperator "bitXor";
      shiftLeft = binaryOperator "shiftLeft";
      shiftRight = binaryOperator "shiftRight";
      ct = fromFields "ct" {
        valid = {
          key = "bytes";
          dir = "original";
        };
        field = "key";
        value = "bogus";
        required = "key";
      };
      rt = fromFields "rt" {
        valid = {
          key = "mtu";
          family = "ip";
        };
        field = "family";
        value = "inet";
        required = "key";
      };
      fib = fromFields "fib" {
        valid = {
          result = "oif";
          flags = [ "saddr" ];
        };
        field = "result";
        value = "bogus";
        required = "result";
      };
      ipsec = fromFields "ipsec" {
        valid = {
          key = "reqid";
          dir = "in";
        };
        field = "spnum";
        value = 256;
        required = "key";
      };
      osf = fromFields "osf" {
        valid = {
          key = "name";
          ttl = "loose";
        };
        field = "ttl";
        value = "bogus";
        required = "key";
      };
      numgen = fromFields "numgen" {
        valid = {
          mode = "inc";
          mod = 2;
        };
        field = "mode";
        value = "bogus";
        required = "mod";
      };
      jhash = fromFields "jhash" {
        valid = {
          mod = 2;
          expr = expression;
        };
        field = "expr";
        value = notAnExpression;
        required = "expr";
      };
      symhash = fromFields "symhash" {
        valid.mod = 2;
        field = "mod";
        value = 0;
        required = "mod";
      };
      elem = fromFields "elem" {
        valid.val = "10.0.0.1";
        field = "val";
        value = notAnExpression;
        required = "val";
      };
      exthdr = fromFields "exthdr" {
        valid.name = "frag";
        field = "offset";
        value = -1;
        required = "name";
      };
      tcpOption = fromFields "tcpOption" {
        valid.name = "maxseg";
        field = "field";
        value = 1;
        required = "name";
      };
      tcpOptionRaw = fromFields "tcpOptionRaw" {
        valid = {
          base = 2;
          offset = 16;
          len = 16;
        };
        field = "base";
        value = 256;
        required = "len";
      };
      ipOption = fromFields "ipOption" {
        valid.name = "rr";
        field = "name";
        value = 1;
        required = "name";
      };
      sctpChunk = fromFields "sctpChunk" {
        valid.name = "data";
        field = "field";
        value = 1;
        required = "name";
      };
      payloadRaw = fromFields "payloadRaw" {
        valid = {
          base = "th";
          offset = 16;
          len = 16;
        };
        field = "base";
        value = "bogus";
        required = "len";
      };
      payloadTunnel = fromFields "payloadTunnel" {
        valid = {
          tunnel = "vxlan";
          protocol = "ip";
          field = "saddr";
        };
        field = "tunnel";
        value = 1;
        required = "field";
      };
    };

  expressionBuilderTests = lib.concatMapAttrs (
    name: case:
    let
      # The field, or a path inside it such as a list entry's.
      option = field: "`${lib.escapeRegex "dsl.expr.${name}.${field}"}(\\.[^']*)?'";
    in
    {
      "testExpressionBuilderWrongValueThrows_${name}" = {
        expr = force case.wrong;
        expectedError.msg = "${option case.field} is not of type";
      };
    }
    // lib.optionalAttrs (case ? unknown) {
      "testExpressionBuilderUnknownArgumentThrows_${name}" = {
        expr = force case.unknown;
        expectedError.msg = "${option "bogus"} does not exist";
      };
      "testExpressionBuilderMissingArgumentThrows_${name}" = {
        expr = force case.missing;
        expectedError.msg = "${option case.required} was accessed but has no value defined";
      };
    }
  ) expressionBuilderCases;

  # The statements nft lists beside an element's value, as it lists them.
  elemStatements = {
    counter = {
      packets = 1;
      bytes = 64;
    };
    quota.val = 1024;
    limit = {
      rate = 10;
      per = "second";
    };
    last.used = 1000;
  };
  elemStatementKeys = builtins.attrNames elemStatements;

  # The ct keys nft loads only with a direction.
  ctKeysNeedingDir = [
    "saddr"
    "daddr"
    "proto-src"
    "proto-dst"
    "ip saddr"
    "ip daddr"
    "ip6 saddr"
    "ip6 daddr"
  ];

  # `expr.ct` throws, naming the builder, for one of these keys without a
  # direction, as nft fails it.
  ctDirectionTests = lib.listToAttrs (
    map (
      key:
      lib.nameValuePair "testExprCtWithoutDirThrows_${lib.replaceStrings [ " " ] [ "_" ] key}" {
        expr = force (dsl.expr.ct { inherit key; });
        expectedError.msg = "nix-nftypes: dsl\\.expr\\.ct: not of type `ct body with dir for";
      }
    ) ctKeysNeedingDir
  );

  # `expr.ct`, `expr.rt`, and `expr.osf` build a key with its Refinement;
  # without one, each key has a Field leaf, so the constructor throws and
  # points to it.
  unrefinedConstructorTests =
    lib.concatMapAttrs
      (
        tag: case:
        lib.listToAttrs (
          map (
            key:
            lib.nameValuePair "testExpr_${tag}_WithoutRefinementPointsToLeaf_${key}" {
              expr = force (dsl.expr.${tag} { inherit key; });
              expectedError.msg = "^nix-nftypes: dsl\\.expr\\.${tag}: `expr\\.${tag}` builds ${case.expression} with a refinement; without one, write the Field leaf `fields\\.${tag}\\.${key}`$";
            }
          ) case.keys
        )
      )
      {
        ct = {
          expression = "a ct expression";
          keys = [
            "mark"
            "bytes"
          ];
        };
        rt = {
          expression = "an rt expression";
          keys = [
            "mtu"
            "nexthop"
          ];
        };
        osf = {
          expression = "an osf expression";
          keys = [
            "name"
            "version"
          ];
        };
      };

  /*
    A chain's Symbolic priority resolves for its family and hook. A symbol
    nft rejects at the hook throws `compatibility.priorityValue`'s message
    at the chain's `prio`; a symbol without a hook has nothing to resolve
    for. A flowtable keeps an integer priority.
  */
  symbolicPriorityTests =
    let
      chain = {
        type = "filter";
        hook = "input";
        prio = "dstnat";
      };
      command = chain // {
        family = "ip";
        table = "t";
        name = "c";
      };
      rejectedAtInput = "family 'ip' has no priority 'dstnat' at hook 'input'\\. Valid priorities: any int, filter, mangle, raw, security, srcnat\\.$";
      needsHook = "a Symbolic priority resolves for the chain's family and hook; give both, or an int priority$";
    in
    {
      testTreeSymbolicPriorityRejectedAtHook = {
        expr = toJson (dsl.ruleset [ (dsl.table "ip" "t" { chains.c = chain; }) ]);
        expectedError.msg = "^nix-nftypes: dsl\\.table ip\\.t: chains\\.c\\.prio: ${rejectedAtInput}";
      };
      testAddChainSymbolicPriorityRejectedAtHook = {
        expr = commandJson (dsl.add.chain command);
        expectedError.msg = "^nix-nftypes: dsl\\.add\\.chain: prio: ${rejectedAtInput}";
      };
      testCreateChainSymbolicPriorityRejectedAtHook = {
        expr = commandJson (dsl.create.chain command);
        expectedError.msg = "^nix-nftypes: dsl\\.create\\.chain: prio: ${rejectedAtInput}";
      };
      testTreeSymbolicPriorityNeedsHook = {
        expr = toJson (
          dsl.ruleset [
            (dsl.table "ip" "t" { chains.c = removeAttrs (chain // { prio = "filter"; }) [ "hook" ]; })
          ]
        );
        expectedError.msg = "^nix-nftypes: dsl\\.table ip\\.t: chains\\.c\\.prio: ${needsHook}";
      };
      testAddChainSymbolicPriorityNeedsFamily = {
        expr = commandJson (dsl.add.chain (removeAttrs (command // { prio = "filter"; }) [ "family" ]));
        expectedError.msg = "^nix-nftypes: dsl\\.add\\.chain: prio: ${needsHook}";
      };
      testFlowtableSymbolicPriorityRejected = {
        expr = commandJson (
          dsl.add.flowtable {
            family = "ip";
            table = "t";
            name = "ft";
            hook = "ingress";
            prio = "filter";
          }
        );
        expectedError.msg = "dsl\\.add\\.flowtable\\.prio' is not of type `signed integer'";
      };
    };

  # A `.ref` takes a name or a map expression, never an inline body.
  referenceBodyTests = lib.listToAttrs (
    map (
      name:
      lib.nameValuePair "testReferenceTakesNoInlineBody_${name}" {
        expr = force (dsl.${name}.ref { val = 1; });
        expectedError.msg = "nix-nftypes: dsl\\.${name}\\.ref: expected an object name or a map expression, got an attribute set without the one key `map`";
      }
    ) referencingStatements
  );

  # nft's parser takes `l4proto` on these protocols but loads a header
  # field at offset 0 instead, a Known difference, so `expr.payload`
  # rejects it.
  payloadL4protoTests = lib.genAttrs' [ "ip" "ip6" "gre" ] (
    protocol:
    lib.nameValuePair "testExprPayloadL4protoThrows_${protocol}" {
      expr = force (dsl.expr.payload protocol "l4proto");
      expectedError.msg = "nix-nftypes: dsl\\.expr\\.payload: unknown ${protocol} field 'l4proto'";
    }
  );

  # The match operators, which build a match statement from its sides.
  matchOperators = [
    "eq"
    "ge"
    "gt"
    "hasAnyFlag"
    "inSet"
    "le"
    "lt"
    "ne"
    "notInSet"
  ];

  # Each match operator validates both sides, naming the operator and the
  # side.
  matchOperatorTests =
    lib.concatMapAttrs
      (
        side: build:
        lib.genAttrs' matchOperators (
          name:
          lib.nameValuePair "testMatchOperatorWrongSideThrows_${name}_${side}" {
            expr = force (build dsl.${name});
            expectedError.msg = "`dsl\\.${name}\\.${side}' is not of type";
          }
        )
      )
      {
        left = operator: operator notAnExpression 1;
        right = operator: operator expression notAnExpression;
      };

  # The imperative renderers, each of which names itself in its errors
  # (ADR 0009).
  imperativeRenderers = [
    "toJson"
    "toText"
    "toTextPretty"
  ];

  # ----- a rule command without `expr` ---------------------------------

  ruleScope = {
    family = "inet";
    table = "t";
    chain = "c";
  };

  # nft's JSON parser requires a rule's `expr` even where it ignores it, as
  # for destroy, so each imperative renderer fills the empty list: a rule
  # command without `expr` renders as it does with `expr = [ ]`, in a raw
  # ruleset or through `dsl.ruleset`. nft's JSON loads an added, inserted,
  # or replaced rule with no statements, but its text grammar has no
  # spelling for one, so text refuses it (#96).
  rawRuleCommands = {
    add = body: { add.rule = body; };
    insert = body: { insert.rule = body; };
    replace = body: {
      replace.rule = body // {
        handle = 4;
      };
    };
    destroy = body: {
      destroy.rule = body // {
        handle = 4;
      };
    };
  };
  verbsNeedingStatements = [
    "add"
    "insert"
    "replace"
  ];
  rulesets = {
    raw = command: { nftables = [ command ]; };
    dsl = command: dsl.ruleset [ command ];
  };
  missingRuleExprTests = lib.concatMapAttrs (
    verb: command:
    lib.concatMapAttrs (
      built: ruleset:
      lib.genAttrs' imperativeRenderers (
        renderer:
        if renderer != "toJson" && builtins.elem verb verbsNeedingStatements then
          lib.nameValuePair "testRuleWithoutExprRefused_${verb}_${built}_${renderer}" {
            expr = nftlib.${renderer} (ruleset (command ruleScope));
            expectedError.msg = helpers.refusals.ruleWithoutStatements;
          }
        else
          lib.nameValuePair "testRuleWithoutExprRendersAnEmptyExpr_${verb}_${built}_${renderer}" {
            expr = nftlib.${renderer} (ruleset (command ruleScope));
            expected = nftlib.${renderer} (ruleset (command (ruleScope // { expr = [ ]; })));
          }
      )
      // {
        "testRuleWithoutExprHasAnEmptyExprInJson_${verb}_${built}" = {
          expr = builtins.fromJSON (toJson (ruleset (command ruleScope)));
          expected.nftables = [ (command (ruleScope // { expr = [ ]; })) ];
        };
      }
    ) rulesets
  ) rawRuleCommands;

  # ----- a table tree passed where a ruleset belongs -------------------

  # Each imperative renderer throws for a table tree, alone or among a
  # ruleset's commands, and names the wrapper it needs.
  bareTableTests =
    let
      tree = dsl.table "inet" "t" { chains.c = { }; };
      placements = {
        alone = tree;
        inRuleset.nftables = [ tree ];
      };
    in
    lib.concatMapAttrs (
      placement: value:
      lib.genAttrs' imperativeRenderers (
        renderer:
        lib.nameValuePair "testBareTableThrows_${renderer}_${placement}" {
          expr = nftlib.${renderer} value;
          expectedError.msg = "nix-nftypes: ${renderer}: got a Table tree where a ruleset belongs; wrap it in dsl\\.ruleset";
        }
      )
    ) placements;

  # Each imperative renderer throws for a raw `nftables` command among a
  # ruleset's commands, which nft rejects, and points to `dsl.ruleset`,
  # which splices one in place.
  nestedRulesetTests =
    let
      values = {
        empty.nftables = [ { nftables = [ ]; } ];
        withCommands.nftables = [
          {
            nftables = [
              (dsl.add.table {
                family = "inet";
                name = "t";
              })
            ];
          }
        ];
        # A key beside `nftables` doesn't make it a command nft loads.
        besideAVerb.nftables = [
          {
            nftables = [ ];
            flush.ruleset = null;
          }
        ];
      };
    in
    lib.concatMapAttrs (
      shape: value:
      lib.genAttrs' imperativeRenderers (
        renderer:
        lib.nameValuePair "testNestedRulesetThrows_${renderer}_${shape}" {
          expr = nftlib.${renderer} value;
          expectedError.msg = "nix-nftypes: ${renderer}: got a ruleset \\{ nftables = \\[ … \\]; \\} nested among a ruleset's commands, which nft rejects; splice it in with dsl\\.ruleset \\[ … \\]";
        }
      )
    ) values;

  # An imperative renderer takes only a ruleset: a lone command, which nft
  # would reject as a bare `{"add":…}`, or any other value throws.
  notARulesetTests =
    let
      values = {
        command = dsl.add.table {
          family = "inet";
          name = "t";
        };
        commandList = [
          (dsl.add.table {
            family = "inet";
            name = "t";
          })
        ];
        string = "add table inet t";
        emptyAttrset = { };
        extraKey = {
          nftables = [ ];
          add.table = {
            family = "inet";
            name = "t";
          };
        };
      };
    in
    lib.concatMapAttrs (
      shape: value:
      lib.genAttrs' imperativeRenderers (
        renderer:
        lib.nameValuePair "testNotARulesetThrows_${renderer}_${shape}" {
          expr = nftlib.${renderer} value;
          expectedError.msg = "nix-nftypes: ${renderer}: expected a ruleset \\{ nftables = \\[ … \\]; \\}";
        }
      )
    ) values;

  # A Refusal names the renderer called, not the text renderers as a
  # whole.
  refusalNamesTheRendererTests =
    let
      # The schema takes a set comment, which nft's JSON parser ignores, so
      # text refuses it (ADR 0010).
      tree = dsl.table "inet" "t" {
        sets.s = {
          type = "ipv4_addr";
          comment = "c";
        };
      };
      renderers = {
        toText = nftlib.toText (dsl.ruleset [ tree ]);
        toTextPretty = nftlib.toTextPretty (dsl.ruleset [ tree ]);
        toTextBlock = nftlib.toTextBlock tree;
        toTextBlockPretty = nftlib.toTextBlockPretty tree;
      };
    in
    lib.mapAttrs' (
      renderer: rendered:
      lib.nameValuePair "testRefusalNamesTheRenderer_${renderer}" {
        expr = rendered;
        expectedError.msg = "^nix-nftypes: ${renderer}: refusing to render";
      }
    ) renderers;

  /*
    nft reads a handle only in Read-back, a Selector, and `insert` and
    `replace` rule (ADR 0009). Every `add`, `create`, and `rename` builder
    and every Table-tree body throws on one, at the handle, and points to
    Read-back. The body is otherwise valid, so only the handle fails.
  */
  handleTests =
    let
      scope = {
        family = "ip";
        table = "t";
      };
      named = scope // {
        name = "o";
      };
      # A valid body of each `add` kind.
      addBodies = {
        table = {
          family = "ip";
          name = "t";
        };
        chain = named;
        rule = scope // {
          chain = "c";
          statements = [ dsl.accept ];
        };
        set = named // {
          type = "ipv4_addr";
        };
        map = named // {
          type = "ipv4_addr";
          dataType = "verdict";
        };
        element = named // {
          elements = [ "10.0.0.1" ];
        };
        flowtable = named // {
          hook = "ingress";
          prio = 0;
        };
        counter = named;
        quota = named;
        ctHelper = named;
        limit = named // {
          rate = 1;
          per = "second";
        };
        ctTimeout = named;
        ctExpectation = named;
        ctCount = named // {
          val = 1;
        };
        secmark = named;
        synproxy = named // {
          mss = 1460;
          wscale = 7;
        };
      };
      withHandle = body: body // { handle = 3; };
      readBack = "nft ignores a handle on add, create, and rename, and a Table tree adds its objects; a handle appears in Read-back";
      rejects = verb: kind: body: {
        expr = commandJson (dsl.${verb}.${kind} (withHandle body));
        expectedError.msg = "^nix-nftypes: dsl\\.${verb}\\.${kind}: handle: ${readBack}";
      };
      treeRejects = at: body: {
        expr = toJson (dsl.ruleset [ (dsl.table "ip" "t" body) ]);
        expectedError.msg = "^nix-nftypes: dsl\\.table ip\\.t: ${at}\\.handle: ${readBack}";
      };
      ruleScope = scope // {
        chain = "c";
      };
    in
    lib.mapAttrs' (
      kind: body: lib.nameValuePair "testAdd${capitalise kind}HandleRejected" (rejects "add" kind body)
    ) addBodies
    // lib.mapAttrs' (
      kind: body:
      lib.nameValuePair "testCreate${capitalise kind}HandleRejected" (rejects "create" kind body)
    ) (removeAttrs addBodies [ "rule" ])
    // lib.mapAttrs' (
      kind: cfg:
      lib.nameValuePair "testTree${capitalise kind}HandleRejected" (
        treeRejects "${cfg.plural}\\.o" {
          ${cfg.plural}.o = withHandle (removeAttrs addBodies.${kind} (builtins.attrNames named));
        }
      )
    ) internal.dslObjectKinds
    // {
      # Every builder of each verb is covered.
      testHandleTestsCoverEveryAddKind = {
        expr = builtins.attrNames dsl.add;
        expected = builtins.attrNames addBodies;
      };
      testRenameChainHandleRejected = rejects "rename" "chain" (named // { newName = "d"; });
      testTreeTableHandleRejected = {
        expr = toJson (dsl.ruleset [ (dsl.table "ip" "t" { handle = 3; }) ]);
        expectedError.msg = "^nix-nftypes: dsl\\.table ip\\.t: handle: ${readBack}";
      };
      testTreeChainHandleRejected = treeRejects "chains\\.c" { chains.c.handle = 3; };
      testTreeRuleHandleRejected = treeRejects "chains\\.c\\.rules\\.0" {
        chains.c.rules = [
          {
            statements = [ dsl.accept ];
            handle = 3;
          }
        ];
      };
      # `insert.rule` places a rule and `replace.rule` replaces one by its
      # handle, a rule's Selector selects by it, and `delete` selects a
      # named object by it in place of the name.
      testHandleKeptWhereNftReadsIt = {
        expr = lib.mapAttrs (_: command: builtins.fromJSON (commandJson command)) {
          insert = dsl.insert.rule (withHandle addBodies.rule);
          replace = dsl.replace.rule (withHandle addBodies.rule);
          deleteRule = dsl.delete.rule (withHandle ruleScope);
          deleteTable = dsl.delete.table (withHandle {
            family = "ip";
          });
          deleteCounter = dsl.delete.counter (withHandle scope);
          deleteFlowtable = dsl.delete.flowtable (withHandle scope);
        };
        expected = lib.mapAttrs (_: command: { nftables = [ command ]; }) {
          insert.insert.rule = withHandle ruleScope // {
            expr = [ { accept = null; } ];
          };
          replace.replace.rule = withHandle ruleScope // {
            expr = [ { accept = null; } ];
          };
          deleteRule.delete.rule = withHandle ruleScope // {
            expr = [ ];
          };
          deleteTable.delete.table = withHandle { family = "ip"; };
          deleteCounter.delete.counter = withHandle scope;
          deleteFlowtable.delete.flowtable = withHandle scope;
        };
      };
      # With a name, nft never reads a handle: no Selector takes both.
      testNamedSelectorHandleRejected = {
        expr = commandJson (dsl.delete.counter (withHandle named));
        expectedError.msg = "^nix-nftypes: dsl\\.delete\\.counter: selects by `name` or by `handle`; got both, and nft ignores a handle beside a name\\.$";
      };
      testListSelectorHandleRejected = {
        expr = commandJson (dsl.list.set (withHandle scope));
        expectedError.msg = "^nix-nftypes: dsl\\.list\\.set: takes a Selector, with only `family`, `table`, and `name`; got `handle`\\.$";
      };
    };

  /*
    A Table tree's own errors: a rule entry takes no `index`, since the
    tree lists a chain's rules in order, in `dsl.ruleset` and block form
    alike.
  */
  tableTreeTests =
    let
      tree = body: dsl.ruleset [ (dsl.table "inet" "fw" body) ];
      indexed = {
        chains.input.rules = [
          [ dsl.accept ]
          {
            statements = [ dsl.drop ];
            index = 0;
          }
        ];
      };
      marked = dsl.table "inet" "fw" { chains.input.rules = [ [ dsl.accept ] ]; };
      rendered = [
        (toJson (dsl.ruleset [ marked ]))
        (nftlib.toText (dsl.ruleset [ marked ]))
        (nftlib.toTextBlock marked)
      ];
    in
    {
      # The nixpkgs convention marks a value's kind with `_type`.
      testTreeMarkedWithType = {
        expr = {
          inherit (marked) _type;
          oldMarker = marked ? __nftTable;
        };
        expected = {
          _type = "nix-nftypes.tableTree";
          oldMarker = false;
        };
      };

      # Cleaning strips the marker, so no rendering carries it.
      testTreeMarkerNeverRendered = {
        expr = builtins.filter (
          output:
          lib.hasInfix "tableTree" output || lib.hasInfix "__nft" output || lib.hasInfix "_type" output
        ) rendered;
        expected = [ ];
      };

      # `dsl.table` sets the marker, so a body's own `_type` would be lost.
      testTreeBodyTypeRejected = {
        expr = toJson (dsl.ruleset [ (dsl.table "inet" "fw" { _type = "example.table"; }) ]);
        expectedError.msg = "^nix-nftypes: dsl\\.table inet\\.fw: _type: is the Table tree's marker, which `dsl\\.table` sets to \"nix-nftypes\\.tableTree\", got \"example\\.table\"; remove it from the body$";
      };

      # The module system's option path starts with the tree, as a
      # builder's starts with the builder (`dsl.add.chain.prio`). It
      # quotes the part `dsl.table inet.fw`, which is no Nix identifier.
      testTreeModuleErrorTypeNamesTree = {
        expr = toJson (tree {
          chains.input = {
            type = "filter";
            hook = "input";
            # A string is a Symbolic priority, which the DSL resolves first.
            prio = true;
          };
        });
        expectedError.msg = "^A definition for option `\"?dsl\\.table inet\\.fw\"?\\.chains\\.input\\.prio' is not of type";
      };
      testTreeModuleErrorUnknownNamesTree = {
        expr = toJson (tree {
          counters.hits.bogus = 1;
        });
        expectedError.msg = "^The option `\"?dsl\\.table inet\\.fw\"?\\.counters\\.hits\\.bogus' does not exist";
      };
      testTreeModuleErrorRuleNamesTree = {
        expr = toJson (tree {
          chains.input.rules = [
            {
              statements = [ dsl.accept ];
              comment = 5;
            }
          ];
        });
        expectedError.msg = "^A definition for option `\"?dsl\\.table inet\\.fw\"?\\.chains\\.input\\.rules\\.\"?0\"?\\.comment' is not of type";
      };

      # An unknown key lists the keys a Table tree takes, and a kind's
      # singular name points to its plural.
      testTreeUnknownKeyListsAllowed = {
        expr = toJson (tree {
          chians.c = { };
        });
        expectedError.msg = "^nix-nftypes: dsl\\.table inet\\.fw: unsupported key\\(s\\): chians; a Table tree takes flags, comment, chains, counters, ctCounts, ctExpectations, ctHelpers, ctTimeouts, flowtables, limits, maps, quotas, secmarks, sets, synproxies$";
      };
      testTreeSingularKeySuggestsPlural = {
        expr = toJson (tree {
          set.s.type = "ipv4_addr";
          chain.c = { };
        });
        expectedError.msg = "^nix-nftypes: dsl\\.table inet\\.fw: unsupported key\\(s\\): chain, set; a Table tree takes flags, comment, chains, .*, synproxies; write `chains` for `chain` and `sets` for `set`$";
      };

      # The quota statement takes `val`, a quota object `bytes`.
      testTreeQuotaValPointsToBytes = {
        expr = toJson (tree {
          quotas.q.val = 100;
        });
        expectedError.msg = "^nix-nftypes: dsl\\.table inet\\.fw: quotas\\.q\\.val: is the quota statement's spelling; a quota object takes its threshold in `bytes`$";
      };
      testAddQuotaValPointsToBytes = {
        expr = commandJson (
          dsl.add.quota {
            family = "inet";
            table = "fw";
            name = "q";
            val = 100;
          }
        );
        expectedError.msg = "^nix-nftypes: dsl\\.add\\.quota: val: is the quota statement's spelling; a quota object takes its threshold in `bytes`$";
      };
      testCreateQuotaValPointsToBytes = {
        expr = commandJson (
          dsl.create.quota {
            family = "inet";
            table = "fw";
            name = "q";
            val = 100;
          }
        );
        expectedError.msg = "^nix-nftypes: dsl\\.create\\.quota: val: is the quota statement's spelling; a quota object takes its threshold in `bytes`$";
      };

      testTreeRuleIndexRejected = {
        expr = toJson (tree indexed);
        expectedError.msg = "^nix-nftypes: dsl\\.table inet\\.fw: chains\\.input\\.rules\\.1\\.index: a Table tree lists a chain's rules in order, so a rule takes no `index`; order the rules in the list, or place one with `add\\.rule` or `insert\\.rule` and its `index`$";
      };
    };

  /*
    A name that declares or selects an object is no Reference (ADR 0009):
    nft looks up `"@s"` there as a set literally named `@s`. The builders
    take the name with or without its `@` and emit the bare name; a Table
    tree's object key, which no builder spells, throws on a leading `@`.
    The schema takes a raw name as written.
  */
  namePositionTests =
    let
      scope = {
        family = "inet";
        table = "t";
      };
      # The command's object body, in the JSON `commandJson` renders.
      objectOf =
        command:
        let
          rendered = builtins.head (builtins.fromJSON (commandJson command)).nftables;
          verb = builtins.head (builtins.attrNames rendered);
        in
        builtins.head (builtins.attrValues rendered.${verb});
      # The name a builder emits for each spelling.
      namesFor = build: {
        bare = (objectOf (build "s")).name;
        at = (objectOf (build "@s")).name;
      };
      bothBare = {
        bare = "s";
        at = "s";
      };
      # Every Selector with a name: each kind of each selecting verb but
      # the rule, which a handle selects, and the ruleset.
      selectorBody =
        kind: name:
        if kind == "table" then
          {
            family = "inet";
            inherit name;
          }
        else
          scope
          // {
            inherit name;
          }
          // lib.optionalAttrs (kind == "element") { elements = [ "192.0.2.1" ]; };
      selectorNames = lib.concatMapAttrs (
        verb: _:
        lib.mapAttrs'
          (kind: build: lib.nameValuePair "${verb}.${kind}" (namesFor (name: build (selectorBody kind name))))
          (
            removeAttrs dsl.${verb} [
              "rule"
              "ruleset"
            ]
          )
      ) (lib.genAttrs [ "delete" "destroy" "list" "flush" "reset" ] lib.id);
      meterNamed =
        name:
        dsl.meter {
          inherit name;
          key = dsl.fields.ip.saddr;
          statement = dsl.counter.auto;
        };
      tree = body: dsl.ruleset [ (dsl.table "inet" "fw" body) ];
    in
    {
      testAddElementTakesBareName = {
        expr = {
          add = namesFor (name: dsl.add.element (selectorBody "element" name));
          create = namesFor (name: dsl.create.element (selectorBody "element" name));
        };
        expected = {
          add = bothBare;
          create = bothBare;
        };
      };

      # Every name-selecting kind, so a kind added later is covered.
      testSelectorTakesBareName = {
        expr = {
          wrong = builtins.attrNames (lib.filterAttrs (_: names: names != bothBare) selectorNames);
          inherit (selectorNames)
            "delete.set"
            "destroy.table"
            "flush.meter"
            "reset.element"
            ;
        };
        expected = {
          wrong = [ ];
          "delete.set" = bothBare;
          "destroy.table" = bothBare;
          "flush.meter" = bothBare;
          "reset.element" = bothBare;
        };
      };

      testMeterTakesBareName = {
        expr = {
          bare = (meterNamed "m").meter.name;
          at = (meterNamed "@m").meter.name;
        };
        expected = {
          bare = "m";
          at = "m";
        };
      };

      testNamePositionRejectsBareAt = {
        expr = commandJson (dsl.add.element (selectorBody "element" "@"));
        expectedError.msg = "^nix-nftypes: dsl\\.add\\.element: name: expected a name, got \"@\"$";
      };
      testMeterRejectsBareAt = {
        expr = meterNamed "@";
        expectedError.msg = "^nix-nftypes: dsl\\.meter: name: expected a name, got \"@\"$";
      };

      # A non-string name reaches the schema, which names the option.
      testNamePositionLeavesNonStringToSchema = {
        expr = commandJson (dsl.delete.set (scope // { name = 5; }));
        expectedError.msg = "dsl\\.delete\\.set\\.name' is not of type";
      };

      testTreeObjectKeyWithAtThrows = {
        expr = toJson (tree {
          sets."@s".type = "ipv4_addr";
        });
        expectedError.msg = "^nix-nftypes: dsl\\.table inet\\.fw: sets\\.@s: a Table tree declares an object by its bare name; drop the leading `@`, which only a Reference adds$";
      };
      testTreeCounterKeyWithAtThrows = {
        expr = toJson (tree {
          counters."@c" = { };
        });
        expectedError.msg = "^nix-nftypes: dsl\\.table inet\\.fw: counters\\.@c: a Table tree declares an object by its bare name";
      };

      # A raw command's name passes the schema as written.
      testRawNameKeepsAt = {
        expr =
          (builtins.head
            (builtins.fromJSON (toJson {
              nftables = [
                {
                  add.element = scope // {
                    name = "@s";
                    elem = [ "192.0.2.1" ];
                  };
                }
              ];
            })).nftables
          ).add.element.name;
        expected = "@s";
      };
    };
in
{
  # Building a table or ruleset stays lazy; only rendering validates.
  # `isAttrs` forces each value to weak head normal form only.
  testTableConstructionStaysLazy = {
    expr = builtins.isAttrs (dsl.table "inet" "fw" { chains.input.prio = "invalid"; });
    expected = true;
  };

  testRulesetConstructionStaysLazy = {
    expr = builtins.isAttrs (
      dsl.ruleset [ (dsl.table "inet" "fw" { chains.input.prio = "invalid"; }) ]
    );
    expected = true;
  };

  testRenderingValidatesLazyTable = {
    expr = toJson (dsl.ruleset [ (dsl.table "inet" "fw" { chains.input.prio = true; }) ]);
    expectedError.msg = "chains\\.input\\.prio.*is not of type";
  };

  testChainDeclarationDoesNotForceRuleBodies = {
    expr = force (
      builtins.elemAt
        (dsl.ruleset [
          (dsl.table "inet" "fw" { chains.input.rules = [ (throw "rule body forced") ]; })
        ]).nftables
        1
    );
    expected.add.chain = {
      family = "inet";
      table = "fw";
      name = "input";
    };
  };

  testTreeMatchingExplicitScopeAccepted = {
    expr = lib.mapAttrs (
      _: render:
      builtins.isString (
        render (
          dsl.table "inet" "fw" {
            family = "inet";
            name = "fw";
            chains.input = {
              family = "inet";
              table = "fw";
              name = "input";
              rules = [
                {
                  family = "inet";
                  table = "fw";
                  chain = "input";
                  statements = [ dsl.accept ];
                }
              ];
            };
            counters.hits = {
              family = "inet";
              table = "fw";
              name = "hits";
            };
          }
        )
      )
    ) tableRenderers;
    expected = lib.mapAttrs (_: _: true) tableRenderers;
  };

  # Table trees are a structural DSL surface rather than a schema body.
  # Reject misspelled collection names instead of silently dropping them
  # while expanding the tree.
  testTableUnknownCollectionRejected = {
    expr = toJson (
      dsl.ruleset [
        (dsl.table "inet" "t" {
          chians.c = { };
        })
      ]
    );
    expectedError.msg = "nix-nftypes: dsl\\.table inet\\.t: unsupported key.*chians";
  };

  # The list form of a lone null-body statement keeps it.
  testRuleStatementListKeepsBareStatement = {
    expr = nftlib.toText (
      dsl.ruleset [ (dsl.table "inet" "fw" { chains.input.rules = [ [ dsl.drop ] ]; }) ]
    );
    expected = "add table inet fw\nadd chain inet fw input\nadd rule inet fw input drop\n";
  };

  # The user's bug. Schema `chainBody.prio` is `nullOr int`; passing a
  # symbolic priority like "filter" used to render to `"prio":"filter"`
  # and the kernel silently dropped the base-chain attrs. The DSL now
  # resolves the symbol, so the JSON holds the int.
  testChainsCPrioSymbolRendersInt = {
    expr =
      (builtins.fromJSON (
        toJson (
          dsl.ruleset [
            (dsl.table "inet" "t" {
              chains.c = {
                type = "filter";
                hook = "input";
                policy = "drop";
                prio = "filter";
              };
            })
          ]
        )
      )).nftables;
    expected = [
      {
        add.table = {
          family = "inet";
          name = "t";
        };
      }
      {
        add.chain = {
          family = "inet";
          table = "t";
          name = "c";
          type = "filter";
          hook = "input";
          policy = "drop";
          prio = 0;
        };
      }
    ];
  };

  # ----- command-builder constructors (commands.nix) --------------------

  # A builder returns the fields it was given, renamed, and no unset
  # field as `null`.
  testCommandBuilderReturnsOnlyTheGivenFields = {
    expr = dsl.add.limit {
      family = "inet";
      table = "t";
      name = "l";
      rate = 10;
      per = "second";
      burstUnit = "kbytes";
    };
    expected.add.limit = {
      family = "inet";
      table = "t";
      name = "l";
      rate = 10;
      per = "second";
      burst_unit = "kbytes";
    };
  };

  # The selecting rule builders hold no `expr`, and render with the empty
  # list the renderers fill.
  testSelectingRuleBuildersRenderAnEmptyExpr = {
    expr = lib.genAttrs [ "delete" "destroy" ] (
      verb:
      let
        command = dsl.${verb}.rule (ruleScope // { handle = 4; });
      in
      {
        inherit command;
        json = builtins.fromJSON (commandJson command);
      }
    );
    expected = lib.genAttrs [ "delete" "destroy" ] (verb: {
      command.${verb}.rule = ruleScope // {
        handle = 4;
      };
      json.nftables = [
        {
          ${verb}.rule = ruleScope // {
            handle = 4;
            expr = [ ];
          };
        }
      ];
    });
  };

  # `validate` returns `{ }` as given, which is not a ruleset.
  testEmptyAttrsetIsNotARuleset = {
    expr = toJson (nftlib.validate nftlib.types.ruleset { });
    expectedError.msg = "nix-nftypes: toJson: expected a ruleset .*, got an empty attribute set; build one with dsl\\.ruleset";
  };

  # Nested bodies, such as a set element's, keep only their given fields
  # too.
  testCommandBuilderNestedBodiesKeepOnlyTheGivenFields = {
    expr = dsl.add.set {
      family = "inet";
      table = "t";
      name = "s";
      type = "ipv4_addr";
      elements = [
        {
          elem = {
            val = "10.0.0.1";
            timeout = 3;
          };
        }
      ];
    };
    expected.add.set = {
      family = "inet";
      table = "t";
      name = "s";
      type = "ipv4_addr";
      elem = [
        {
          elem = {
            val = "10.0.0.1";
            timeout = 3;
          };
        }
      ];
    };
  };

  testCreateChainPrioBoolRejected = {
    expr = commandJson (
      dsl.create.chain {
        family = "ip";
        table = "t";
        name = "c";
        prio = true;
      }
    );
    expectedError.msg = "create\\.chain\\.prio";
  };

  testDeleteCounterBadFamilyRejected = {
    expr = commandJson (
      dsl.delete.counter {
        family = "wireguard";
        table = "t";
        name = "ctr";
      }
    );
    expectedError.msg = "delete\\.counter\\.family.*is not of type";
  };

  testListMapBadNameRejected = {
    expr = commandJson (
      dsl.list.map {
        family = "ip";
        table = "t";
        name = 123;
      }
    );
    expectedError.msg = "list\\.map\\.name.*is not of type";
  };

  testRenameChainBadNewNameRejected = {
    expr = commandJson (
      dsl.rename.chain {
        family = "ip";
        table = "t";
        name = "c";
        newName = 42;
      }
    );
    expectedError.msg = "rename\\.chain\\.newname.*is not of type";
  };

  testAddFlowtableMissingHookRejected = {
    expr = commandJson (
      dsl.add.flowtable {
        family = "inet";
        table = "t";
        name = "ft";
        prio = 0;
      }
    );
    expectedError.msg = "add\\.flowtable\\.hook' was accessed but has no value defined";
  };

  testCreateFlowtableMissingPrioRejected = {
    expr = commandJson (
      dsl.create.flowtable {
        family = "inet";
        table = "t";
        name = "ft";
        hook = "ingress";
      }
    );
    expectedError.msg = "create\\.flowtable\\.prio' was accessed but has no value defined";
  };

  # nft refuses a flowtable at any hook but `ingress` ("invalid hook").
  testAddFlowtableHookOtherThanIngressRejected = {
    expr = commandJson (
      dsl.add.flowtable {
        family = "inet";
        table = "t";
        name = "ft";
        hook = "input";
        prio = 0;
      }
    );
    expectedError.msg = "add\\.flowtable\\.hook' is not of type";
  };

  testTreeFlowtableHookOtherThanIngressRejected = {
    expr = toJson (
      dsl.ruleset [
        (dsl.table "inet" "t" {
          flowtables.ft = {
            hook = "input";
            prio = 0;
          };
        })
      ]
    );
    expectedError.msg = "flowtables\\.ft\\.hook' is not of type";
  };

  # Every `.ref` takes a name or a map expression only, as the schema's
  # Reference does: a number or a boolean throws.
  testObjectReferenceBuildersRejectNumbersAndBooleans = {
    expr = lib.concatMap (
      name:
      builtins.filter (value: (builtins.tryEval (force (dsl.${name}.ref value))).success) [
        5
        true
      ]
    ) referencingStatements;
    expected = [ ];
  };

  # nft's reset statement strips a TCP option and refuses any other
  # expression ("Illegal TCP optstrip argument").
  testResetStmtOtherThanTcpOptionRejected = {
    expr = force (dsl.resetStmt dsl.fields.ct.mark);
    expectedError.msg = "`dsl\\.resetStmt\\.ct' does not exist";
  };

  testTreeFlowtableMissingHookRejected = {
    expr = toJson (
      dsl.ruleset [
        (dsl.table "inet" "t" {
          flowtables.ft.prio = 0;
        })
      ]
    );
    expectedError.msg = "flowtables\\.ft\\.hook' was accessed but has no value defined";
  };

  # A chain without `type` (or `prio`) loads as a regular chain that sees
  # no packets, so a table tree or builder must set all three.
  testTreeChainHookWithoutTypeRejected = {
    expr = toJson (
      dsl.ruleset [
        (dsl.table "ip" "t" {
          chains.c = {
            hook = "input";
            prio = 0;
          };
        })
      ]
    );
    expectedError.msg = "nix-nftypes: dsl\\.table ip\\.t: chains\\.c: not of type `chain body with type, hook and prio all set";
  };

  testAddChainWithoutPrioRejected = {
    expr = commandJson (
      dsl.add.chain {
        family = "ip";
        table = "t";
        name = "c";
        type = "filter";
        hook = "input";
      }
    );
    expectedError.msg = "nix-nftypes: dsl\\.add\\.chain: not of type `chain body with type, hook and prio all set";
  };

  testDestroyCounterByHandleRejected = {
    expr = commandJson (
      dsl.destroy.counter {
        family = "inet";
        table = "t";
        handle = 4;
      }
    );
    expectedError.msg = "nix-nftypes: dsl\\.destroy\\.counter: takes a Selector, with only `family`, `table`, and `name`; got `handle`\\. nft destroys by name only; dsl\\.delete\\.counter selects by handle\\.$";
  };

  # nft deletes a table, chain, set, map, flowtable, or stateful object
  # but a ct helper by name or by handle, and reads the handle only
  # without a name.
  testDeleteSelectorWithNameAndHandleThrows = {
    expr = commandJson (
      dsl.delete.set {
        family = "inet";
        table = "t";
        name = "s";
        handle = 4;
      }
    );
    expectedError.msg = "^nix-nftypes: dsl\\.delete\\.set: selects by `name` or by `handle`; got both, and nft ignores a handle beside a name\\.$";
  };
  testDeleteSelectorWithoutNameOrHandleThrows = {
    expr = commandJson (
      dsl.delete.table {
        family = "inet";
      }
    );
    expectedError.msg = "^nix-nftypes: dsl\\.delete\\.table: selects by `name` or by `handle`; got neither\\.$";
  };
  # nft reads a ct helper's name on delete, never its handle.
  testDeleteCtHelperByHandleThrows = {
    expr = commandJson (
      dsl.delete.ctHelper {
        family = "inet";
        table = "t";
        handle = 4;
      }
    );
    expectedError.msg = "^nix-nftypes: dsl\\.delete\\.ctHelper: takes a Selector, with only `family`, `table`, and `name`; got `handle`\\.$";
  };

  testRenameChainMissingNewNameRejected = {
    expr = commandJson (
      dsl.rename.chain {
        family = "ip";
        table = "t";
        name = "c";
      }
    );
    expectedError.msg = "rename\\.chain\\.newname' was accessed but has no value defined";
  };

  testReplaceRuleMissingHandleRejected = {
    expr = commandJson (
      dsl.replace.rule {
        family = "ip";
        table = "t";
        chain = "c";
        statements = [ dsl.accept ];
      }
    );
    expectedError.msg = "dsl\\.replace\\.rule\\.handle' was accessed but has no value defined";
  };

  testReplaceRuleBadHandleRejected = {
    expr = commandJson (
      dsl.replace.rule {
        family = "ip";
        table = "t";
        chain = "c";
        statements = [ dsl.accept ];
        handle = "abc";
      }
    );
    expectedError.msg = "dsl\\.replace\\.rule\\.handle.*is not of type";
  };

  testInsertRuleBadIndexRejected = {
    expr = commandJson (
      dsl.insert.rule {
        family = "ip";
        table = "t";
        chain = "c";
        statements = [ dsl.accept ];
        index = -1;
      }
    );
    expectedError.msg = "dsl\\.insert\\.rule\\.index.*is not of type";
  };

  # ----- flush and add namespaces (commands.nix) -------------------------

  testFlushTableBadFamilyRejected = {
    expr = commandJson (
      dsl.flush.table {
        family = "wireguard";
        name = "t";
      }
    );
    expectedError.msg = "flush\\.table\\.family";
  };

  testFlushChainBadNameRejected = {
    expr = commandJson (
      dsl.flush.chain {
        family = "ip";
        table = "t";
        name = 4;
      }
    );
    expectedError.msg = "flush\\.chain\\.name.*is not of type";
  };

  /*
    A selecting builder takes a Selector, which accepts no field nft
    ignores for the verb (ADR 0009): `delete set` with elements deletes
    the whole set, so `dsl.delete.set` throws, naming the builder and
    pointing to `delete.element`.
  */
  testDeleteSetElementsThrows = {
    expr = force (
      dsl.delete.set {
        family = "inet";
        table = "t";
        name = "s";
        elements = [ "10.0.0.1" ];
      }
    );
    expectedError.msg = "nix-nftypes: dsl\\.delete\\.set: takes a Selector, with only `family`, `table`, and `name` or `handle`; got `elements`\\. To delete elements, use dsl\\.delete\\.element\\.";
  };
  testSelectorIgnoredFieldThrows = {
    expr = force (
      dsl.flush.chain {
        family = "inet";
        table = "t";
        name = "c";
        policy = "accept";
        comment = "x";
      }
    );
    expectedError.msg = "nix-nftypes: dsl\\.flush\\.chain: takes a Selector, with only `family`, `table`, and `name`; got `comment` and `policy`\\.$";
  };
  # An element's Selector names the elements in the DSL spelling.
  testDeleteElementSelectorNamesElements = {
    expr = force (
      dsl.reset.element {
        family = "inet";
        table = "t";
        name = "s";
        elements = [ "10.0.0.1" ];
        timeout = 5;
      }
    );
    expectedError.msg = "nix-nftypes: dsl\\.reset\\.element: takes a Selector, with only `family`, `table`, `name`, and `elements`; got `timeout`";
  };
  # A JSON spelling points to the DSL name before the Selector check.
  testSelectorJsonSpellingThrows = {
    expr = force (
      dsl.delete.element {
        family = "inet";
        table = "t";
        name = "s";
        elem = [ "10.0.0.1" ];
      }
    );
    expectedError.msg = "nix-nftypes: dsl\\.delete\\.element: elem: is the JSON spelling; write `elements`";
  };
  testDeleteRuleStatementsThrows = {
    expr = force (
      dsl.destroy.rule (
        ruleScope
        // {
          handle = 4;
          statements = [ dsl.accept ];
        }
      )
    );
    expectedError.msg = "nix-nftypes: dsl\\.destroy\\.rule: takes a Selector, with only `family`, `table`, `chain`, and `handle`; got `statements`";
  };
  testListRulesetFamily = {
    expr = map dsl.list.ruleset [
      { }
      { family = "ip"; }
    ];
    expected = [
      { list.ruleset = null; }
      { list.ruleset.family = "ip"; }
    ];
  };

  # A flush selects its set or map by name: nft ignores the datatypes.
  testFlushSetMissingNameRejected = {
    expr = commandJson (
      dsl.flush.set {
        family = "ip";
        table = "t";
      }
    );
    expectedError.msg = "flush\\.set\\.name.*was accessed but has no value defined";
  };

  testFlushMapTypeRejected = {
    expr = commandJson (
      dsl.flush.map {
        family = "ip";
        table = "t";
        name = "m";
        type = "ipv4_addr";
      }
    );
    expectedError.msg = "nix-nftypes: dsl\\.flush\\.map: takes a Selector, with only `family`, `table`, and `name`; got `type`\\.$";
  };

  testFlushMeterBadTableRejected = {
    expr = commandJson (
      dsl.flush.meter {
        family = "ip";
        table = 42;
        name = "m";
      }
    );
    expectedError.msg = "flush\\.meter\\.table.*is not of type";
  };

  testFlushRulesetBadFamilyRejected = {
    expr = commandJson (
      dsl.flush.ruleset {
        family = "wireguard";
      }
    );
    expectedError.msg = "`dsl\\.flush\\.ruleset\\.family' is not of type";
  };

  # ----- table-tree leaves (lib/table.nix) ------------------------------
  # One per plural-keyed object container, each picking a clearly-bad
  # value for the matching schema submodule. Asserts the leaf-validation
  # in lib/table.nix routes every kind through the right body type.

  testTreeTableBadFlagsRejected = {
    expr = toJson (
      dsl.ruleset [
        (dsl.table "ip" "t" {
          flags = [ "no-such-flag" ];
        })
      ]
    );
    expectedError.msg = "flags\\..*is not of type";
  };

  testTreeSetBadTypeRejected = {
    expr = toJson (
      dsl.ruleset [
        (dsl.table "ip" "t" {
          sets.s = {
            type = 42;
          };
        })
      ]
    );
    expectedError.msg = "sets\\.s\\.type.*is not of type";
  };

  testTreeMapMissingMapRejected = {
    expr = toJson (
      dsl.ruleset [
        (dsl.table "ip" "t" {
          maps.m = {
            type = "ipv4_addr";
          };
        })
      ]
    );
    expectedError.msg = "maps\\.m\\.map.*was accessed but has no value defined";
  };

  # `setElem` (the type behind `elem`) accepts string/int/bool/list as
  # bare expressions, so we exercise the schema via a different field —
  # `family` is a strict enum, easy to violate cleanly.
  testAddElementBadFamilyRejected = {
    expr = commandJson (
      dsl.add.element {
        family = "wireguard";
        table = "t";
        name = "s";
        elements = [ "1.2.3.4" ];
      }
    );
    expectedError.msg = "add\\.element\\.family.*is not of type";
  };

  # flowtable.dev must be an interface name or a list of them; pass a
  # number to force a clean failure.
  testTreeFlowtableBadDevRejected = {
    expr = toJson (
      dsl.ruleset [
        (dsl.table "ip" "t" {
          flowtables.ft = {
            hook = "ingress";
            prio = 0;
            dev = 42;
          };
        })
      ]
    );
    expectedError.msg = "flowtables\\.ft\\.dev.*is not of type";
  };

  testTreeCounterBadPacketsRejected = {
    expr = toJson (
      dsl.ruleset [
        (dsl.table "ip" "t" {
          counters.c = {
            packets = "lots";
          };
        })
      ]
    );
    expectedError.msg = "counters\\.c\\.packets";
  };

  testTreeQuotaBadBytesRejected = {
    expr = toJson (
      dsl.ruleset [
        (dsl.table "ip" "t" {
          quotas.q = {
            bytes = "infinity";
          };
        })
      ]
    );
    expectedError.msg = "quotas\\.q\\.bytes.*is not of type";
  };

  testTreeLimitMissingPerRejected = {
    expr = toJson (
      dsl.ruleset [
        (dsl.table "ip" "t" {
          limits.l = {
            rate = 100;
          };
        })
      ]
    );
    expectedError.msg = "limits\\.l\\.per.*was accessed but has no value defined";
  };

  testTreeCtHelperBadProtocolRejected = {
    expr = toJson (
      dsl.ruleset [
        (dsl.table "ip" "t" {
          ctHelpers.h = {
            protocol = "icmp";
          };
        })
      ]
    );
    expectedError.msg = "ctHelpers\\.h\\.protocol.*is not of type";
  };

  testTreeCtTimeoutBadL3protoRejected = {
    expr = toJson (
      dsl.ruleset [
        (dsl.table "ip" "t" {
          ctTimeouts.t = {
            l3proto = "ipx";
          };
        })
      ]
    );
    expectedError.msg = "ctTimeouts\\.t\\.l3proto.*is not of type";
  };

  testTreeCtExpectationBadDportRejected = {
    expr = toJson (
      dsl.ruleset [
        (dsl.table "ip" "t" {
          ctExpectations.e = {
            dport = 99999;
          };
        })
      ]
    );
    expectedError.msg = "ctExpectations\\.e\\.dport.*is not of type";
  };

  testTreeSecmarkBadContextRejected = {
    expr = toJson (
      dsl.ruleset [
        (dsl.table "ip" "t" {
          secmarks.s = {
            context = 42;
          };
        })
      ]
    );
    expectedError.msg = "secmarks\\.s\\.context.*is not of type";
  };

  testTreeSynproxyMissingMssRejected = {
    expr = toJson (
      dsl.ruleset [
        (dsl.table "ip" "t" {
          synproxies.sp = {
            wscale = 7;
          };
        })
      ]
    );
    expectedError.msg = "synproxies\\.sp\\.mss.*was accessed but has no value defined";
  };

  # The table tree has no tunnel kind (tests/fixtures/nft-misbehaviour.nix).
  testTreeTunnelsRejected = {
    expr = toJson (
      dsl.ruleset [
        (dsl.table "netdev" "t" {
          tunnels.tn = {
            id = 1;
          };
        })
      ]
    );
    expectedError.msg = "nix-nftypes: dsl\\.table netdev\\.t: unsupported key.*tunnels";
  };

  # A path-like name is a name: the synproxy reference isn't imported as
  # a module file.
  testTreePathLikeReferenceIsAName = {
    expr =
      builtins.elemAt
        (builtins.fromJSON (
          toJson (
            dsl.ruleset [
              (dsl.table "inet" "t" {
                chains.c.rules = [ [ (dsl.synproxy.ref "/sp1") ] ];
              })
            ]
          )
        )).nftables
        2;
    expected.add.rule = {
      family = "inet";
      table = "t";
      chain = "c";
      expr = [ { synproxy = "/sp1"; } ];
    };
  };

  # ----- expr.payload: nft's protocol and field table -----------------

  # A protocol nft's JSON parser does not know fails at evaluation, and
  # the error lists the ones it does.
  testExprPayloadUnknownProtocolThrows = {
    expr = force (dsl.expr.payload "ipv4" "saddr");
    expectedError.msg = lib.escapeRegex "nix-nftypes: dsl.expr.payload: unknown protocol 'ipv4'. Valid protocols: ah, arp, comp, dccp, esp, ether, gre, icmp, icmpv6, igmp, ip, ip6, sctp, tcp, th, udp, udplite, vlan.";
  };

  # A field the protocol lacks, such as a Field leaf's camelCase name,
  # fails at evaluation, and the error lists the protocol's fields in
  # nft's spelling.
  testExprPayloadUnknownFieldThrows = {
    expr = force (dsl.expr.payload "ip" "fragOff");
    expectedError.msg = lib.escapeRegex "nix-nftypes: dsl.expr.payload: unknown ip field 'fragOff'. Valid ip fields: version, hdrlength, dscp, ecn, length, id, frag-off, ttl, protocol, checksum, saddr, daddr.";
  };

  # A tunnel header loads only through `expr.payloadTunnel`; nft fails
  # its named form.
  testExprPayloadTunnelHeaderThrows = {
    expr = force (dsl.expr.payload "vxlan" "vni");
    expectedError.msg = "nix-nftypes: dsl\\.expr\\.payload: unknown protocol 'vxlan'";
  };

  # A protocol or field that is not a string still fails the payload
  # body's type, at the field's option.
  testExprPayloadNonStringFieldThrows = {
    expr = force (dsl.expr.payload "tcp" 1);
    expectedError.msg = "`dsl\\.expr\\.payload\\.field' is not of type";
  };

  # Every payload Field leaf is a protocol and field in the table, so
  # `expr.payload` rebuilds it.
  testEveryPayloadFieldLeafBuilds = {
    expr =
      lib.filterAttrs (_: leaf: dsl.expr.payload leaf.payload.protocol leaf.payload.field != leaf)
        (
          lib.concatMapAttrs (
            protocol: leaves:
            lib.mapAttrs' (name: leaf: lib.nameValuePair "${protocol}.${name}" leaf) (
              lib.filterAttrs (_: leaf: leaf ? payload) leaves
            )
          ) dsl.fields
        );
    expected = { };
  };

  # ----- the flat namespace --------------------------------------------

  # The DSL's flat namespace merges its layers; a name two layers define
  # throws instead of one layer silently shadowing the other.
  testDslLayerCollisionThrows = {
    expr = internal.dslMergeDisjoint {
      ops.match = 1;
      verdicts = {
        accept = 2;
        match = 3;
      };
    };
    expectedError.msg = "nix-nftypes: dsl: `match' is defined by more than one layer: ops, verdicts";
  };

  testDslLayersMerge = {
    expr = internal.dslMergeDisjoint {
      ops.eq = 1;
      verdicts.accept = 2;
    };
    expected = {
      eq = 1;
      accept = 2;
    };
  };

  # ----- reset order ---------------------------------------------------

  # nft runs a reset of a counter, quota, set, map, or rule only as the
  # batch's last command, so `dsl.ruleset` throws for one placed earlier,
  # whether a builder or a raw attrset made it.
  testRulesetResetBeforeTableThrows = {
    expr = toJson (
      dsl.ruleset [
        (dsl.reset.counter {
          family = "inet";
          table = "t";
          name = "c";
        })
        (dsl.table "inet" "t" { })
      ]
    );
    expectedError.msg = "nix-nftypes: dsl\\.ruleset: .*reset.*last command";
  };

  testRulesetRawResetBeforeCommandThrows = {
    expr = toJson (
      dsl.ruleset [
        {
          reset.quota = {
            family = "inet";
            table = "t";
            name = "q";
          };
        }
        { flush.ruleset = null; }
      ]
    );
    expectedError.msg = "nix-nftypes: dsl\\.ruleset: .*reset.*last command";
  };

  testRulesetAcceptsResetLast = {
    expr = toJson (
      dsl.ruleset [
        (dsl.table "inet" "t" { counters.c = { }; })
        (dsl.reset.counter {
          family = "inet";
          table = "t";
          name = "c";
        })
      ]
    );
    expected = "{\"nftables\":[{\"add\":{\"table\":{\"family\":\"inet\",\"name\":\"t\"}}},{\"add\":{\"counter\":{\"family\":\"inet\",\"name\":\"c\",\"table\":\"t\"}}},{\"reset\":{\"counter\":{\"family\":\"inet\",\"name\":\"c\",\"table\":\"t\"}}}]}";
  };

  # nft refuses an empty tproxy, and the kernel an snat or dnat with
  # neither an address nor a port, so the builders need one of them.
  testSnatWithoutAddrOrPortThrows = {
    expr = force (dsl.snat { family = "ip"; });
    expectedError.msg = "nix-nftypes: dsl\\.snat: not of type `snat/dnat body with addr or port'";
  };

  testDnatWithoutAddrOrPortThrows = {
    expr = force (dsl.dnat { });
    expectedError.msg = "nix-nftypes: dsl\\.dnat: not of type `snat/dnat body with addr or port'";
  };

  testTproxyWithoutAddrOrPortThrows = {
    expr = force (dsl.tproxy { });
    expectedError.msg = "nix-nftypes: dsl\\.tproxy: not of type `tproxy body with addr or port'";
  };

  # Every `dsl.expr` builder has a case in `expressionBuilderCases`.
  # `setRef` checks its name itself.
  testEveryExpressionBuilderHasACase = {
    expr = lib.subtractLists (builtins.attrNames expressionBuilderCases) (builtins.attrNames dsl.expr);
    expected = [ "setRef" ];
  };

  # nft needs `saddr` or `daddr` among a FIB lookup's flags, and a
  # direction for every IPsec key.
  testExprFibWithoutAddressFlagThrows = {
    expr = force (
      dsl.expr.fib {
        result = "oif";
        flags = [ "iif" ];
      }
    );
    expectedError.msg = "nix-nftypes: dsl\\.expr\\.fib: not of type `fib body with saddr or daddr among its flags'";
  };

  testExprIpsecWithoutDirThrows = {
    expr = force (dsl.expr.ipsec { key = "reqid"; });
    expectedError.msg = "nix-nftypes: dsl\\.expr\\.ipsec: not of type `ipsec body with dir'";
  };

  # A ct key nft reads no direction for fails with one.
  testExprCtDirOnADirectionlessKeyThrows = {
    expr = force (
      dsl.expr.ct {
        key = "state";
        dir = "original";
      }
    );
    expectedError.msg = "nix-nftypes: dsl\\.expr\\.ct: not of type `ct body with dir for";
  };

  # nft's JSON parser ignores a ct expression's `family`.
  testExprCtFamilyThrows = {
    expr = force (
      dsl.expr.ct {
        key = "mark";
        family = "ip";
      }
    );
    expectedError.msg = "`dsl\\.expr\\.ct\\.family' does not exist";
  };

  # nft's JSON parser ignores an element's statements on input, so
  # `expr.elem` takes none, as `elemBody` does; nft lists them, and
  # `elemReadBackBody` keeps them for Read-back.
  testExprElemTakesNoStatements = {
    expr = map (
      tag:
      (builtins.tryEval (
        force (
          dsl.expr.elem {
            val = "10.0.0.1";
            ${tag} = elemStatements.${tag};
          }
        )
      )).success
    ) elemStatementKeys;
    expected = map (_: false) elemStatementKeys;
  };

  testExprElemStatementNamesTheBuilder = {
    expr = force (
      dsl.expr.elem {
        val = "10.0.0.1";
        inherit (elemStatements) counter;
      }
    );
    expectedError.msg = "`dsl\\.expr\\.elem\\.counter' does not exist";
  };

  testExprElemReadBackKeepsStatements = {
    expr = map (
      tag:
      helpers.validates nftlib.types.expressionBodies.elemReadBackBody {
        val = "10.0.0.1";
        ${tag} = elemStatements.${tag};
      }
    ) elemStatementKeys;
    expected = map (_: true) elemStatementKeys;
  };

  # An anonymous set is a list; a bare string throws, pointing to setRef.
  testExprSetBareStringNamesTheBuilder = {
    expr = force (dsl.expr.set "trusted_v4");
    expectedError.msg = "nix-nftypes: dsl\\.expr\\.set: a bare string";
  };

  # A builder for one form of its tag's body takes that form only.
  testExprPayloadRawTakesNoNamedField = {
    expr = force (
      dsl.expr.payloadRaw {
        protocol = "tcp";
        field = "dport";
      }
    );
    expectedError.msg = "`dsl\\.expr\\.payloadRaw\\.(protocol|field)' does not exist";
  };

  testExprTcpOptionTakesNoRawBits = {
    expr = force (
      dsl.expr.tcpOption {
        base = 2;
        offset = 16;
        len = 16;
      }
    );
    expectedError.msg = "`dsl\\.expr\\.tcpOption\\.base' does not exist";
  };

  testStatementBuilderBodyNotAnAttrsetThrows = {
    expr = force (dsl.log "DROP: ");
    expectedError.msg = "nix-nftypes: dsl\\.log: expected an attribute set of fields, got a string";
  };

  testStatementBuilderMissingFieldThrows = {
    expr = force (dsl.limit { rate = 10; });
    expectedError.msg = "`dsl\\.limit\\.per' was accessed but has no value defined";
  };

  # A raw command, which `dsl.ruleset` passes through unvalidated, holds
  # a statement its builder validated.
  testRawCommandBadStatementThrows = {
    expr = toJson (
      dsl.ruleset [
        {
          add.rule = {
            family = "inet";
            table = "t";
            chain = "c";
            expr = [ (dsl.log { level = "bogus"; }) ];
          };
        }
      ]
    );
    expectedError.msg = "`dsl\\.log\\.level' is not of type";
  };

  testRawCommandBadMatchThrows = {
    expr = toJson (
      dsl.ruleset [
        {
          add.rule = {
            family = "inet";
            table = "t";
            chain = "c";
            expr = [ (dsl.eq { bogus = 1; } 2) ];
          };
        }
      ]
    );
    expectedError.msg = "`dsl\\.eq\\.left' is not of type";
  };

  # A valid statement is the body its builder was given, with the null
  # fields left out and its keys renamed to their JSON spellings.
  testStatementBuilderReturnsTheGivenFields = {
    expr = force [
      (dsl.log {
        prefix = "DROP: ";
        queueThreshold = 2;
        group = null;
      })
      (dsl.snat { port = 80; })
      (dsl.setStmt {
        op = "add";
        element = dsl.fields.ip.saddr;
        set = "s";
      })
    ];
    expected = [
      {
        log = {
          prefix = "DROP: ";
          queue-threshold = 2;
        };
      }
      { snat.port = 80; }
      {
        set = {
          op = "add";
          elem.payload = {
            protocol = "ip";
            field = "saddr";
          };
          set = "@s";
        };
      }
    ];
  };

  # ----- happy path: a complete, valid ruleset still renders -----------

  testTreeAcceptedRulesetSucceeds = {
    expr = builtins.isString (
      toJson (
        dsl.ruleset [
          (dsl.table "ip" "t" {
            chains.c = {
              type = "filter";
              hook = "input";
              prio = 0;
              policy = "accept";
              rules = [ [ dsl.accept ] ];
            };
          })
        ]
      )
    );
    expected = true;
  };
}
// scopeTests
// handleTests
// droppedInputTests
// malformedRuleEntryTests
// uncalledStatementTests
// ruleCommandTests
// statementBuilderTests
// expressionBuilderTests
// ctDirectionTests
// unrefinedConstructorTests
// symbolicPriorityTests
// payloadL4protoTests
// referenceBodyTests
// matchOperatorTests
// missingRuleExprTests
// bareTableTests
// nestedRulesetTests
// notARulesetTests
// refusalNamesTheRendererTests
// tableTreeTests
// namePositionTests
