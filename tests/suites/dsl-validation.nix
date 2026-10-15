{
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
  dsl = nftlib.dsl;
  inherit (nftlib) toJson;

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
        expr = [ dsl.accept ];
      }
    ];
    ruleTable.chains.input.rules = [
      {
        table = "other";
        expr = [ dsl.accept ];
      }
    ];
    ruleChain.chains = {
      input.rules = [
        {
          chain = "output";
          expr = [ dsl.accept ];
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
    withinBareString = {
      value = dsl.within dsl.fields.tcp.dport "ports";
      msg = "within: .*\"ports\".*expr\\.setRef";
    };
    setElemAndElements = {
      value = dsl.ruleset [
        (dsl.table "inet" "t" {
          sets.s = {
            type = "ipv4_addr";
            elem = [ "192.0.2.1" ];
            elements = [ "192.0.2.2" ];
          };
        })
      ];
      msg = "sets\\.s\\.elements: .*`elem`";
    };
    elementElemAndElements = {
      value = dsl.ruleset [
        (dsl.table "inet" "t" {
          sets.s.type = "ipv4_addr";
          elements.s = {
            elem = [ "192.0.2.1" ];
            elements = [ "192.0.2.2" ];
          };
        })
      ];
      msg = "elements\\.s\\.elements: .*`elem`";
    };
    addMapElemAndElements = {
      value = dsl.add.map {
        family = "inet";
        table = "t";
        name = "m";
        type = "ipv4_addr";
        map = "mark";
        elem = [ ];
        elements = [ ];
      };
      msg = "nix-nftypes: dsl\\.add\\.map: elements: .*`elem`";
    };
    limitRateUnitTwice = {
      value = dsl.ruleset [
        (dsl.table "inet" "t" {
          limits.l = {
            rate = 10;
            per = "second";
            rateUnit = "packets";
            rate_unit = "bytes";
          };
        })
      ];
      msg = "limits\\.l\\.rateUnit: .*`rate_unit`";
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
              expr = [ dsl.accept ];
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
      msg = "flush\\.ruleset\\.value.*is not of type";
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
    `expr`. A bare statement such as `dsl.drop` expanded to a rule with no
    statement, so each entry here must throw in every form, naming the
    rule's path and showing the list form.
  */
  malformedRuleEntries = {
    drop = dsl.drop;
    accept = dsl.accept;
    return = dsl.return;
    continue = dsl.continue;
    notrack = dsl.notrack;
    last = dsl.last;
    counterAuto = dsl.counter.auto;
    synproxyAuto = dsl.synproxy.auto;
    jump = dsl.jump "other";
    emptyList = [ ];
    emptyExpr.expr = [ ];
    nullExpr.expr = null;
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

  # A rule command needs its statements in `expr`: without them, `add`,
  # `insert`, and `replace` rendered a rule with no statement. Each must
  # throw in JSON and text, naming the command and showing the list form.
  ruleCommandBuilders = {
    "add.rule" = dsl.add.rule;
    insert = dsl.insert;
    replace = body: dsl.replace (body // { handle = 1; });
  };
  ruleCommandBodies = {
    noExpr = { };
    emptyExpr.expr = [ ];
    nullExpr.expr = null;
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
            expectedError.msg = "nix-nftypes: dsl\\.${lib.escapeRegex verb}: .*a list of statements.*expr = \\[ dsl\\.drop \\]";
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
      expr = toJson case.value;
      expectedError.msg = case.msg;
    };
    "testDroppedInputCatchable_${name}" = {
      expr = (builtins.tryEval (builtins.deepSeq (toJson case.value) null)).success;
      expected = false;
    };
  }) droppedInputs;

  # ----- a table tree passed where a ruleset belongs -------------------

  # Each imperative renderer refuses a bare table tree, alone or among a
  # ruleset's commands, and names the wrapper it needs. Each error starts
  # with the renderer's own API name.
  bareTableTests =
    let
      tree = dsl.table "inet" "t" { chains.c = { }; };
      renderers = {
        toJson = "toJson";
        toNix = "toNix";
        toText = "text";
        toTextPretty = "text";
      };
      placements = {
        alone = tree;
        inRuleset.nftables = [ tree ];
      };
    in
    lib.concatMapAttrs (
      renderer: api:
      lib.mapAttrs' (
        placement: value:
        lib.nameValuePair "testBareTableRefused_${renderer}_${placement}" {
          expr = nftlib.${renderer} value;
          expectedError.msg = "nix-nftypes: ${api}: got a dsl\\.table node; wrap it in dsl\\.ruleset";
        }
      ) placements
    ) renderers;
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
    expr = toJson (dsl.ruleset [ (dsl.table "inet" "fw" { chains.input.prio = "invalid"; }) ]);
    expectedError.msg = "chains\\.input\\.prio.*is not of type";
  };

  testChainDeclarationDoesNotForceRuleBodies = {
    expr = toJson (
      builtins.elemAt
        (dsl.ruleset [
          (dsl.table "inet" "fw" { chains.input.rules = [ (throw "rule body forced") ]; })
        ]).nftables
        1
    );
    expected = toJson {
      add.chain = {
        family = "inet";
        table = "fw";
        name = "input";
      };
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
                  expr = [ dsl.accept ];
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
    expected = "add table inet fw\nadd chain inet fw input\nadd rule inet fw input drop";
  };

  testTableTypeMarkerAccepted = {
    expr = builtins.isString (
      toJson (
        dsl.ruleset [
          (dsl.table "inet" "t" {
            _type = "example.table";
          })
        ]
      )
    );
    expected = true;
  };

  # The user's bug. Schema `chainBody.prio` is `nullOr int`; passing a
  # symbolic priority like "filter" used to render to `"prio":"filter"`
  # and the kernel silently dropped the base-chain attrs.
  testChainsCPrioStringRejected = {
    expr = toJson (
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
    );
    expectedError.msg = "chains\\.c\\.prio";
  };

  # ----- command-builder constructors (commands.nix) --------------------

  testCreateChainPrioStringRejected = {
    expr = toJson (
      dsl.create.chain {
        family = "ip";
        table = "t";
        name = "c";
        prio = "filter";
      }
    );
    expectedError.msg = "create\\.chain\\.prio";
  };

  testDeleteCounterBadFamilyRejected = {
    expr = toJson (
      dsl.delete.counter {
        family = "wireguard";
        table = "t";
        name = "ctr";
      }
    );
    expectedError.msg = "delete\\.counter\\.family.*is not of type";
  };

  testListMapBadTypeRejected = {
    expr = toJson (
      dsl.list.map {
        family = "ip";
        table = "t";
        name = "m";
        type = 123;
        map = "mark";
      }
    );
    expectedError.msg = "list\\.map\\.type.*is not of type";
  };

  testRenameChainBadNewnameRejected = {
    expr = toJson (
      dsl.rename.chain {
        family = "ip";
        table = "t";
        name = "c";
        newname = 42;
      }
    );
    expectedError.msg = "rename\\.chain\\.newname.*is not of type";
  };

  testAddFlowtableMissingHookRejected = {
    expr = toJson (
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
    expr = toJson (
      dsl.create.flowtable {
        family = "inet";
        table = "t";
        name = "ft";
        hook = "ingress";
      }
    );
    expectedError.msg = "create\\.flowtable\\.prio' was accessed but has no value defined";
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
    expr = toJson (
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
    expr = toJson (
      dsl.destroy.counter {
        family = "inet";
        table = "t";
        handle = 4;
      }
    );
    expectedError.msg = "destroy\\.counter\\.name' was accessed but has no value defined";
  };

  testRenameChainMissingNewnameRejected = {
    expr = toJson (
      dsl.rename.chain {
        family = "ip";
        table = "t";
        name = "c";
      }
    );
    expectedError.msg = "rename\\.chain\\.newname' was accessed but has no value defined";
  };

  testReplaceRuleMissingHandleRejected = {
    expr = toJson (
      dsl.replace {
        family = "ip";
        table = "t";
        chain = "c";
        expr = [ dsl.accept ];
      }
    );
    expectedError.msg = "dsl\\.replace\\.handle' was accessed but has no value defined";
  };

  testReplaceRuleBadHandleRejected = {
    expr = toJson (
      dsl.replace {
        family = "ip";
        table = "t";
        chain = "c";
        expr = [ dsl.accept ];
        handle = "abc";
      }
    );
    expectedError.msg = "dsl\\.replace\\.handle.*is not of type";
  };

  testInsertRuleBadIndexRejected = {
    expr = toJson (
      dsl.insert {
        family = "ip";
        table = "t";
        chain = "c";
        expr = [ dsl.accept ];
        index = -1;
      }
    );
    expectedError.msg = "dsl\\.insert\\.index.*is not of type";
  };

  # ----- flush and add namespaces (commands.nix) -------------------------

  testFlushTableBadFamilyRejected = {
    expr = toJson (
      dsl.flush.table {
        family = "wireguard";
        name = "t";
      }
    );
    expectedError.msg = "flush\\.table\\.family";
  };

  testFlushChainBadHandleRejected = {
    expr = toJson (
      dsl.flush.chain {
        family = "ip";
        table = "t";
        name = "c";
        handle = "not-a-number";
      }
    );
    expectedError.msg = "flush\\.chain\\.handle.*is not of type";
  };

  # A flush selects its set or map by name: nft ignores the datatypes.
  testFlushSetMissingNameRejected = {
    expr = toJson (
      dsl.flush.set {
        family = "ip";
        table = "t";
        type = "ipv4_addr";
      }
    );
    expectedError.msg = "flush\\.set\\.name.*was accessed but has no value defined";
  };

  testFlushMapBadTypeRejected = {
    expr = toJson (
      dsl.flush.map {
        family = "ip";
        table = "t";
        name = "m";
        type = 42;
      }
    );
    expectedError.msg = "flush\\.map\\.type.*is not of type";
  };

  testFlushMeterBadTableRejected = {
    expr = toJson (
      dsl.flush.meter {
        family = "ip";
        table = 42;
        name = "m";
      }
    );
    expectedError.msg = "flush\\.meter\\.table.*is not of type";
  };

  testFlushRulesetBadFamilyRejected = {
    expr = toJson (
      dsl.flush.ruleset {
        family = "wireguard";
      }
    );
    expectedError.msg = "flush\\.ruleset\\.value\\.family.*is not of type";
  };

  # nft 1.1.6's JSON parser ignores a handle on `add rule`, so the
  # builder refuses one.
  testAddRuleHandleRejected = {
    expr = toJson (
      dsl.add.rule {
        family = "ip";
        table = "t";
        chain = "c";
        expr = [ dsl.accept ];
        handle = 4;
      }
    );
    expectedError.msg = "dsl\\.add\\.rule\\.handle' does not exist";
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

  # A table tree's rule loads through `add rule`, which takes no handle.
  testTreeRuleHandleRejected = {
    expr = toJson (
      dsl.ruleset [
        (dsl.table "ip" "t" {
          chains.c = {
            rules = [
              {
                expr = [ dsl.accept ];
                handle = 4;
              }
            ];
          };
        })
      ]
    );
    expectedError.msg = "chains\\.c\\.rules\\..*\\.handle' does not exist";
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
  testTreeElementBadFamilyRejected = {
    expr = toJson (
      dsl.ruleset [
        (dsl.table "ip" "t" {
          elements.s = {
            family = "wireguard";
            elements = [ "1.2.3.4" ];
          };
        })
      ]
    );
    expectedError.msg = "elements\\.s\\.family.*is not of type";
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
// droppedInputTests
// malformedRuleEntryTests
// ruleCommandTests
// bareTableTests
