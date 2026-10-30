{
  helpers,
  internal,
  lib,
  nftlib,
  ...
}:

let
  inherit (helpers) roundtrip;
  inherit (nftlib) toJson;

  # A rule whose verdict carries a library's `_type` marker.
  markedVerdictRuleset.nftables = [
    {
      add.rule = {
        family = "inet";
        table = "t";
        chain = "c";
        expr = [
          {
            drop = null;
            _type = "x.y";
          }
        ];
      };
    }
  ];

  # A stateful-object reference selected by destination port.
  portMapReference.map = {
    key.payload = {
      protocol = "tcp";
      field = "dport";
    };
    data.set = [
      [
        22
        "a"
      ]
      [
        80
        "b"
      ]
    ];
  };
  portMapReferenceJson = "{\"map\":{\"data\":{\"set\":[[22,\"a\"],[80,\"b\"]]},\"key\":{\"payload\":{\"field\":\"dport\",\"protocol\":\"tcp\"}}}}";

  # The statements that name a stateful object, by a Reference.
  objectReferenceTags = [
    "counter"
    "quota"
    "limit"
    "ct count"
    "synproxy"
    "ct helper"
    "ct timeout"
    "ct expectation"
    "secmark"
    "tunnel"
  ];

  # A listed command validated as a singleton ruleset, deep-forced so
  # lazy submodule checks run.
  readBack =
    command:
    let
      ruleset = helpers.validate nftlib.types.ruleset { nftables = [ command ]; };
    in
    builtins.deepSeq ruleset ruleset;

  /*
    Schema↔text drift: every tag in the schema's `statement`, `expression`
    (its tagged forms), and `addObject`/`readBackObject` unions must have a
    matching entry in the corresponding text/* dispatch table — otherwise
    the renderer throws at *render time* (`no renderer for tag '…'`)
    instead of failing eval-time. Catches the regression class where a new
    schema tag is added without a renderer.
  */
  textDriftTests =
    let
      inherit (internal) textDispatch;

      # Tags in `xs` that don't appear in `ys`. A non-empty result lists
      # the offenders verbatim, which makes the failure output
      # self-explanatory.
      missing = xs: ys: lib.subtractLists ys xs;
      statementTags = builtins.attrNames nftlib.types.statement.functor.payload.tags;
      expressionTags = helpers.tagsOf nftlib.types.expression;
      # Renderable object kinds: every union tag in addObject ∪
      # readBackObject (the latter adds `metainfo`, `meter`, and the
      # Read-back-only `tunnel`) plus `ruleset`, which appears only as a
      # command-level envelope but still needs a header renderer for
      # `list/flush/reset ruleset`.
      objectKinds =
        lib.unique (
          builtins.attrNames nftlib.types.addObject.functor.payload.tags
          ++ builtins.attrNames nftlib.types.readBackObject.functor.payload.tags
        )
        ++ [ "ruleset" ];
    in
    {
      # Schema → renderer: every tag the schema accepts must be
      # renderable (otherwise renderStatement/Expression/Object throws
      # at render time).
      testTextDrift_statementTagsCovered = {
        expr = missing statementTags textDispatch.statementTags;
        expected = [ ];
      };
      testTextDrift_expressionTagsCovered = {
        expr = missing expressionTags textDispatch.expressionTags;
        expected = [ ];
      };
      testTextDrift_objectKindsCovered = {
        expr = missing objectKinds textDispatch.objectKinds;
        expected = [ ];
      };

      # Renderer → schema: every entry in the renderer dispatch table
      # must correspond to a real schema tag (otherwise it's dead code
      # — unreachable because no schema route emits that tag).
      testTextDrift_statementRendererHasNoOrphans = {
        expr = missing textDispatch.statementTags statementTags;
        expected = [ ];
      };
      testTextDrift_expressionRendererHasNoOrphans = {
        expr = missing textDispatch.expressionTags expressionTags;
        expected = [ ];
      };
      testTextDrift_objectRendererHasNoOrphans = {
        expr = missing textDispatch.objectKinds objectKinds;
        expected = [ ];
      };
    };

  /*
    Block-form field drift: block form must render, refuse, or take from
    the table tree's scope every field of the bodies a table tree prepares,
    or the tree must reject it before rendering. A field added to one of
    these bodies fails here until text classifies it, so block form cannot
    drop it silently, as it once dropped a rule's `index`.
  */
  blockFieldDriftTests =
    let
      inherit (internal) textBlockFields;
      bodyTypes = {
        table = nftlib.types.objectBodies.tableBody;
        chain = nftlib.types.objectBodies.chainBody;
        rule = nftlib.types.objectBodies.addRuleBody;
      };
      schemaFields = type: builtins.attrNames (removeAttrs (type.getSubOptions [ ]) [ "_module" ]);
      classified = body: lib.concatLists (builtins.attrValues textBlockFields.${body});
      perBody = f: lib.mapAttrs (body: type: f (schemaFields type) (classified body)) bodyTypes;
      none = {
        table = [ ];
        chain = [ ];
        rule = [ ];
      };
    in
    {
      testBlockFieldDrift_everyFieldClassified = {
        expr = perBody (fields: known: lib.subtractLists known fields);
        expected = none;
      };
      testBlockFieldDrift_noUnknownField = {
        expr = perBody (fields: known: lib.subtractLists fields known);
        expected = none;
      };
      testBlockFieldDrift_eachFieldClassifiedOnce = {
        expr = perBody (_: known: lib.subtractLists (lib.unique known) known);
        expected = none;
      };
    };

  /*
    Commands nft mishandles are Known differences (ADR 0010), each with a
    live "still misbehaves" case in tests/fixtures/nft-misbehaviour.nix:
    delete or destroy of a ct expectation deletes its table, list of one
    lists the table, ct timeout delete fails and list aborts, and nft 1.1.7
    aborts on delete or destroy of a ct count.
  */
  mishandledCommandTests =
    let
      bodies = {
        "ct count" = {
          family = "inet";
          table = "t";
          name = "cc";
          val = 10;
        };
        "ct expectation" = {
          family = "inet";
          table = "t";
          name = "ce";
          protocol = "tcp";
          dport = 21;
          timeout = 1000;
          size = 10;
          l3proto = "ip";
        };
        "ct timeout" = {
          family = "inet";
          table = "t";
          name = "cto";
          protocol = "tcp";
          l3proto = "ip";
          policy.established = 100;
        };
      };
      mishandled = lib.mapAttrs (_: command: lib.splitString ":" command) {
        testDeleteCtCountRejected = "delete:ct count";
        testDestroyCtCountRejected = "destroy:ct count";
        testDeleteCtExpectationRejected = "delete:ct expectation";
        testDestroyCtExpectationRejected = "destroy:ct expectation";
        testListCtExpectationRejected = "list:ct expectation";
        testDeleteCtTimeoutRejected = "delete:ct timeout";
        testDestroyCtTimeoutRejected = "destroy:ct timeout";
        testListCtTimeoutRejected = "list:ct timeout";
      };
    in
    lib.mapAttrs (_: command: {
      expr = roundtrip nftlib.types.command (lib.setAttrByPath command bodies.${lib.last command});
      expectedError.msg = "validate\\.${builtins.head command}.*is not of type";
    }) mishandled
    // {
      # The same objects still add, and still read back as listed objects.
      testMishandledKindsStillAdd = {
        expr = map (
          kind: builtins.isString (roundtrip nftlib.types.command { add.${kind} = bodies.${kind}; })
        ) (builtins.attrNames bodies);
        expected = [
          true
          true
          true
        ];
      };
      testMishandledKindsStillReadBack = {
        expr = map (
          kind:
          builtins.isAttrs (readBack {
            ${kind} = bodies.${kind};
          })
        ) (builtins.attrNames bodies);
        expected = [
          true
          true
          true
        ];
      };
    };

  /*
    nft's JSON parser writes a tunnel's dport into its sport and leaves a
    missing port, ttl, or tos uninitialised, and nft crashes on delete,
    destroy, and list of a tunnel. So types.command rejects every tunnel
    command (Known differences, ADR 0010), each with a live "still
    misbehaves" case in tests/fixtures/nft-misbehaviour.nix, and only the
    Read-back shape validates.
  */
  tunnelCommandTests =
    let
      tunnel = {
        family = "netdev";
        table = "t";
        name = "tun";
        id = 10;
        "src-ipv4" = "192.0.2.1";
        "dst-ipv4" = "192.0.2.2";
        sport = 1111;
        dport = 2222;
        tos = 0;
        ttl = 64;
      };
    in
    lib.mapAttrs
      (_: verb: {
        expr = roundtrip nftlib.types.command { ${verb}.tunnel = tunnel; };
        expectedError.msg = "validate\\.${verb}.*is not of type";
      })
      {
        testAddTunnelRejected = "add";
        testCreateTunnelRejected = "create";
        testDeleteTunnelRejected = "delete";
        testDestroyTunnelRejected = "destroy";
        testListTunnelRejected = "list";
      }
    // {
      testTunnelStillReadsBack = {
        expr = builtins.isAttrs (readBack {
          tunnel = tunnel // {
            handle = 1;
          };
        });
        expected = true;
      };
    };

  # Each command requires the fields nft's JSON parser requires for it
  # (parser_json.c), and no others: a command missing one fails naming the
  # field, and a field nft ignores for the verb isn't demanded.
  commandRequirementTests =
    let
      missing = field: "validate\\.${field}' was accessed but has no value defined";
      selector = {
        family = "inet";
        table = "t";
        name = "ft";
      };
      byHandle = removeAttrs selector [ "name" ] // {
        handle = 4;
      };
      flowtable = selector // {
        hook = "ingress";
        prio = 0;
        dev = "lo";
      };
    in
    {
      testRenameChainRequiresNewname = {
        expr = roundtrip nftlib.types.command {
          rename.chain = {
            family = "ip";
            table = "t";
            name = "c";
          };
        };
        expectedError.msg = missing "rename\\.chain\\.newname";
      };
      testRenameChainWithNewname = {
        expr = roundtrip nftlib.types.command {
          rename.chain = {
            family = "ip";
            table = "t";
            name = "c";
            newname = "d";
          };
        };
        expected = "{\"rename\":{\"chain\":{\"family\":\"ip\",\"name\":\"c\",\"newname\":\"d\",\"table\":\"t\"}}}";
      };
      # `newname` belongs to the rename command, not to a chain.
      testAddChainRejectsNewname = {
        expr = roundtrip nftlib.types.command {
          add.chain = {
            family = "ip";
            table = "t";
            name = "c";
            newname = "d";
          };
        };
        expectedError.msg = "newname' does not exist";
      };
      testReplaceRuleRequiresHandle = {
        expr = roundtrip nftlib.types.command {
          replace.rule = {
            family = "ip";
            table = "t";
            chain = "c";
            expr = [ { accept = null; } ];
          };
        };
        expectedError.msg = missing "replace\\.rule\\.handle";
      };
      # nft treats handle 0 as missing: "Handle is required when replacing
      # a rule."
      testReplaceRuleRejectsHandleZero = {
        expr = roundtrip nftlib.types.command {
          replace.rule = {
            family = "ip";
            table = "t";
            chain = "c";
            handle = 0;
            expr = [ { accept = null; } ];
          };
        };
        expectedError.msg = "validate\\.replace\\.rule\\.handle.*is not of type";
      };
      testAddFlowtableRequiresHook = {
        expr = roundtrip nftlib.types.command {
          add.flowtable = removeAttrs flowtable [ "hook" ];
        };
        expectedError.msg = missing "add\\.flowtable\\.hook";
      };
      testAddFlowtableRequiresPrio = {
        expr = roundtrip nftlib.types.command {
          add.flowtable = removeAttrs flowtable [ "prio" ];
        };
        expectedError.msg = missing "add\\.flowtable\\.prio";
      };
      testCreateFlowtableRequiresHook = {
        expr = roundtrip nftlib.types.command {
          create.flowtable = removeAttrs flowtable [ "hook" ];
        };
        expectedError.msg = missing "create\\.flowtable\\.hook";
      };
      testAddFlowtableWithHookAndPrio = {
        expr = roundtrip nftlib.types.command { add.flowtable = flowtable; };
        expected = "{\"add\":{\"flowtable\":{\"dev\":\"lo\",\"family\":\"inet\",\"hook\":\"ingress\",\"name\":\"ft\",\"prio\":0,\"table\":\"t\"}}}";
      };
      # Delete and destroy select the flowtable by name only.
      testDeleteFlowtableWithoutHook = {
        expr = roundtrip nftlib.types.command { delete.flowtable = selector; };
        expected = "{\"delete\":{\"flowtable\":{\"family\":\"inet\",\"name\":\"ft\",\"table\":\"t\"}}}";
      };
      testDestroyFlowtableWithoutHook = {
        expr = roundtrip nftlib.types.command { destroy.flowtable = selector; };
        expected = "{\"destroy\":{\"flowtable\":{\"family\":\"inet\",\"name\":\"ft\",\"table\":\"t\"}}}";
      };
      # nft's JSON parser ignores a set's or map's datatypes, a limit's
      # rate and a synproxy's mss and wscale on delete and destroy.
      testDeleteAndDestroySelectByName = {
        expr =
          lib.concatMap
            (
              verb:
              map (kind: roundtrip nftlib.types.command { ${verb}.${kind} = selector; }) [
                "set"
                "map"
                "limit"
                "synproxy"
              ]
            )
            [
              "delete"
              "destroy"
            ];
        expected = [
          ''{"delete":{"set":{"family":"inet","name":"ft","table":"t"}}}''
          ''{"delete":{"map":{"family":"inet","name":"ft","table":"t"}}}''
          ''{"delete":{"limit":{"family":"inet","name":"ft","table":"t"}}}''
          ''{"delete":{"synproxy":{"family":"inet","name":"ft","table":"t"}}}''
          ''{"destroy":{"set":{"family":"inet","name":"ft","table":"t"}}}''
          ''{"destroy":{"map":{"family":"inet","name":"ft","table":"t"}}}''
          ''{"destroy":{"limit":{"family":"inet","name":"ft","table":"t"}}}''
          ''{"destroy":{"synproxy":{"family":"inet","name":"ft","table":"t"}}}''
        ];
      };
      # Adding one still needs them.
      testAddSetRequiresType = {
        expr = roundtrip nftlib.types.command { add.set = selector; };
        expectedError.msg = missing "add\\.set\\.type";
      };
      testAddLimitRequiresRate = {
        expr = roundtrip nftlib.types.command {
          add.limit = selector // {
            per = "second";
          };
        };
        expectedError.msg = missing "add\\.limit\\.rate";
      };
      # nft rejects a destroy by handle alone ("Object item not found:
      # name").
      testDestroyRequiresName = {
        expr = map (kind: helpers.validates nftlib.types.command { destroy.${kind} = byHandle; }) [
          "set"
          "map"
          "limit"
          "flowtable"
          "counter"
          "chain"
        ];
        expected = [
          false
          false
          false
          false
          false
          false
        ];
      };
      testDestroySetRequiresName = {
        expr = roundtrip nftlib.types.command {
          destroy.set = removeAttrs selector [ "name" ];
        };
        expectedError.msg = missing "destroy\\.set\\.name";
      };
      testDestroyTableRequiresName = {
        expr = roundtrip nftlib.types.command {
          destroy.table.family = "inet";
        };
        expectedError.msg = missing "destroy\\.table\\.name";
      };
      testReplaceRuleWithHandle = {
        expr = roundtrip nftlib.types.command {
          replace.rule = {
            family = "ip";
            table = "t";
            chain = "c";
            handle = 4;
            expr = [ { accept = null; } ];
          };
        };
        expected = "{\"replace\":{\"rule\":{\"chain\":\"c\",\"expr\":[{\"accept\":null}],\"family\":\"ip\",\"handle\":4,\"table\":\"t\"}}}";
      };
    };

  /*
    Each selecting verb takes a Selector, which accepts no field nft's JSON
    parser ignores for the verb (ADR 0009): `delete set` with `elem`
    deletes the whole set, not the elements (a Known difference with a
    live case in tests/fixtures/nft-misbehaviour.nix).
  */
  selectorTests =
    let
      inTable = {
        family = "inet";
        table = "t";
      };
      named = inTable // {
        name = "x";
      };
      # Each kind's Selector, with the fields nft reads.
      selectorOf =
        kind:
        {
          table = {
            family = "inet";
            name = "t";
          };
          rule = inTable // {
            chain = "c";
            handle = 4;
          };
          element = named // {
            elem = [ "10.0.0.1" ];
          };
          ruleset = null;
        }
        .${kind} or named;
      # For each kind, a field its add body takes that nft ignores when it
      # selects one.
      ignoredOf = {
        table.comment = "c";
        chain.policy = "accept";
        rule.expr = [ ];
        set.elem = [ "10.0.0.1" ];
        map.type = "ipv4_addr";
        meter.type = "ipv4_addr";
        element.comment = "c";
        flowtable.hook = "ingress";
        counter.packets = 1;
        quota.bytes = 1;
        "ct helper".type = "ftp";
        limit.rate = 1;
        secmark.context = "c";
        synproxy.mss = 1460;
        ruleset = inTable;
      };
      deleteKinds = [
        "table"
        "chain"
        "rule"
        "set"
        "map"
        "element"
        "flowtable"
        "counter"
        "quota"
        "ct helper"
        "limit"
        "secmark"
        "synproxy"
      ];
      kindsByVerb = {
        delete = deleteKinds;
        destroy = deleteKinds;
        list = [
          "table"
          "chain"
          "set"
          "map"
          "meter"
          "counter"
          "quota"
          "ct helper"
          "limit"
          "secmark"
          "ruleset"
        ];
        flush = [
          "table"
          "chain"
          "set"
          "map"
          "meter"
          "ruleset"
        ];
        reset = [
          "counter"
          "quota"
          "rule"
          "set"
          "map"
          "element"
        ];
      };
      # `verb.kind` for each command whose `body kind` fails validation.
      rejected =
        body:
        lib.concatLists (
          lib.mapAttrsToList (
            verb: kinds:
            map (kind: "${verb}.${kind}") (
              builtins.filter (
                kind: !(helpers.validates nftlib.types.command { ${verb}.${kind} = body kind; })
              ) kinds
            )
          ) kindsByVerb
        );
      every = lib.concatLists (lib.mapAttrsToList (verb: map (kind: "${verb}.${kind}")) kindsByVerb);
    in
    {
      testEverySelectorValidates = {
        expr = rejected selectorOf;
        expected = [ ];
      };
      testEverySelectorRejectsAFieldNftIgnores = {
        expr = rejected (
          kind: if kind == "ruleset" then ignoredOf.ruleset else selectorOf kind // ignoredOf.${kind}
        );
        expected = every;
      };
      # With a name, nft never reads a handle, so no Selector takes both.
      testNamedSelectorsRejectAHandle = {
        expr = rejected (
          kind:
          if kind == "ruleset" then
            ignoredOf.ruleset
          else
            selectorOf kind
            // lib.optionalAttrs (kind != "rule") {
              handle = 1;
            }
        );
        expected = builtins.filter (command: !(lib.hasSuffix ".rule" command)) every;
      };
      # nft's JSON parser reads the handle without a name only on delete,
      # and never of a ct helper, an element, or a ruleset; destroy, list,
      # flush, and reset require the name ("Object item not found: name").
      testOnlyDeleteSelectsByHandle = {
        expr =
          let
            byHandle =
              kind:
              if kind == "rule" then
                selectorOf kind
              else if kind == "ruleset" then
                ignoredOf.ruleset
              else
                removeAttrs (selectorOf kind) [ "name" ] // { handle = 2; };
          in
          lib.subtractLists (rejected byHandle) every;
        expected = [
          "delete.table"
          "delete.chain"
          "delete.rule"
          "delete.set"
          "delete.map"
          "delete.flowtable"
          "delete.counter"
          "delete.quota"
          "delete.limit"
          "delete.secmark"
          "delete.synproxy"
          "destroy.rule"
          "reset.rule"
        ];
      };
      testDeleteTableByHandle = {
        expr = roundtrip nftlib.types.command {
          delete.table = {
            family = "ip";
            handle = 2;
          };
        };
        expected = ''{"delete":{"table":{"family":"ip","handle":2}}}'';
      };
      testDeleteCounterByHandle = {
        expr = roundtrip nftlib.types.command {
          delete.counter = inTable // {
            handle = 2;
          };
        };
        expected = "{\"delete\":{\"counter\":{\"family\":\"inet\",\"handle\":2,\"table\":\"t\"}}}";
      };
      # A delete Selector takes the name or the handle: not neither, and not
      # both.
      testDeleteSelectorRequiresNameOrHandle = {
        expr = roundtrip nftlib.types.command { delete.counter = inTable; };
        expectedError.msg = "validate\\.delete\\.counter' is not of type `counter Selector with exactly one of name and handle'";
      };
      testDeleteSelectorRejectsBothNameAndHandle = {
        expr = roundtrip nftlib.types.command {
          delete.set = named // {
            handle = 2;
          };
        };
        expectedError.msg = "validate\\.delete\\.set' is not of type `set Selector with exactly one of name and handle'";
      };
      # nft takes handle 0 as no handle, and the kernel then deletes every
      # table of the family (measured on nft 1.1.6), so the handle is
      # positive.
      testDeleteRejectsHandleZero = {
        expr = roundtrip nftlib.types.command {
          delete.table = {
            family = "ip";
            handle = 0;
          };
        };
        expectedError.msg = "validate\\.delete\\.table\\.handle' is not of type `null or \\(positive integer";
      };
      testListRuleset = {
        expr = map (body: roundtrip nftlib.types.command { list.ruleset = body; }) [
          null
          { family = "ip"; }
        ];
        expected = [
          ''{"list":{"ruleset":null}}''
          ''{"list":{"ruleset":{"family":"ip"}}}''
        ];
      };
      testDeleteSetRejectsElem = {
        expr = roundtrip nftlib.types.command {
          delete.set = {
            family = "inet";
            table = "t";
            name = "s";
            elem = [ "10.0.0.1" ];
          };
        };
        expectedError.msg = "validate\\.delete\\.set\\.elem' does not exist";
      };
    };

  # nft's `list` command, in text and JSON, has no singular selector for a
  # ct count, element, flowtable, metainfo, rule, or synproxy ("Unknown
  # object passed to list command"), so the schema rejects each (ADR 0009).
  listSelectorTests =
    let
      inTable = {
        family = "inet";
        table = "t";
      };
      bodies = {
        "ct count" = inTable // {
          name = "cc";
          val = 10;
        };
        element = inTable // {
          name = "s";
          elem = [ "10.0.0.1" ];
        };
        flowtable = inTable // {
          name = "ft";
          hook = "ingress";
          prio = 0;
        };
        metainfo = {
          version = "1.1.6";
          release_name = "Commodore Bullmoose #7";
          json_schema_version = 1;
        };
        rule = inTable // {
          chain = "c";
          handle = 2;
          expr = [ ];
        };
        synproxy = inTable // {
          name = "sp";
          mss = 1460;
          wscale = 7;
        };
      };
    in
    {
      testListRejectsKindsWithoutSelector = {
        expr = lib.mapAttrs (
          kind: body: helpers.validates nftlib.types.command { list.${kind} = body; }
        ) bodies;
        expected = lib.mapAttrs (_: _: false) bodies;
      };
      # Each body still reads back, so the rejection is the kind's.
      testListBodiesReadBack = {
        expr = lib.mapAttrs (
          kind: body: helpers.validates nftlib.types.readBackObject { ${kind} = body; }
        ) bodies;
        expected = lib.mapAttrs (_: _: true) bodies;
      };
    };

  /*
    nft reads a `handle` only in Read-back, a Selector, and `insert` and
    `replace` rule (ADR 0009). It ignores one on `add`, `create`, and
    `rename`, except that nft 1.1.7 places an added rule after it, so
    those bodies reject it and the error points to Read-back (a Known
    difference, ADR 0010). An element has no handle at all.
  */
  handleTests =
    let
      scope = {
        family = "ip";
        table = "t";
      };
      # A minimal valid add body of each kind but `element`.
      addBodies = {
        table = {
          family = "ip";
          name = "t";
        };
        chain = scope // {
          name = "c";
        };
        rule = scope // {
          chain = "c";
          expr = [ { accept = null; } ];
        };
        set = scope // {
          name = "s";
          type = "ipv4_addr";
        };
        map = scope // {
          name = "m";
          type = "ipv4_addr";
          map = "verdict";
        };
        flowtable = scope // {
          name = "f";
          hook = "ingress";
          prio = 0;
        };
        counter = scope // {
          name = "o";
        };
        quota = scope // {
          name = "o";
        };
        "ct helper" = scope // {
          name = "o";
        };
        limit = scope // {
          name = "o";
          rate = 1;
          per = "second";
        };
        "ct timeout" = scope // {
          name = "o";
        };
        "ct expectation" = scope // {
          name = "o";
        };
        "ct count" = scope // {
          name = "o";
          val = 1;
        };
        secmark = scope // {
          name = "o";
        };
        synproxy = scope // {
          name = "o";
          mss = 1460;
          wscale = 7;
        };
      };
      withHandle = body: body // { handle = 3; };
      rejects =
        verb: kind: body:
        lib.nameValuePair
          "test${helpers.capitalise verb}${lib.concatMapStrings helpers.capitalise (lib.splitString " " kind)}RejectsHandle"
          {
            expr = roundtrip nftlib.types.command { ${verb}.${kind} = withHandle body; };
            expectedError.msg = "${verb}\\.\"?${kind}\"?' is not of type `[^']*without a handle[^']*Read-back";
          };
      accepts = command: {
        expr = helpers.validates nftlib.types.command command;
        expected = true;
      };
      rule = withHandle addBodies.rule;
    in
    lib.listToAttrs (
      lib.mapAttrsToList (rejects "add") addBodies
      ++ lib.mapAttrsToList (rejects "create") (removeAttrs addBodies [ "rule" ])
      ++ [
        (rejects "rename" "chain" (addBodies.chain // { newname = "d"; }))
      ]
    )
    // {
      testAddBodiesWithoutHandle = {
        expr = lib.mapAttrs (
          kind: body: helpers.validates nftlib.types.command { add.${kind} = body; }
        ) addBodies;
        expected = lib.mapAttrs (_: _: true) addBodies;
      };
      testAddElementRejectsHandle = {
        expr = roundtrip nftlib.types.command {
          add.element = scope // {
            name = "s";
            elem = [ "10.0.0.1" ];
            handle = 3;
          };
        };
        expectedError.msg = "add\\.element\\.handle' does not exist";
      };
      testAddRuleWithoutHandle = {
        expr = roundtrip nftlib.types.command { add.rule = addBodies.rule; };
        expected = "{\"add\":{\"rule\":{\"chain\":\"c\",\"expr\":[{\"accept\":null}],\"family\":\"ip\",\"table\":\"t\"}}}";
      };
      testInsertRuleKeepsHandle = {
        expr = roundtrip nftlib.types.command { insert.rule = rule; };
        expected = "{\"insert\":{\"rule\":{\"chain\":\"c\",\"expr\":[{\"accept\":null}],\"family\":\"ip\",\"handle\":3,\"table\":\"t\"}}}";
      };
      testReplaceRuleKeepsHandle = accepts { replace.rule = rule; };
      testListedRuleKeepsHandle = {
        expr = roundtrip nftlib.types.readBackObject { inherit rule; };
        expected = "{\"rule\":{\"chain\":\"c\",\"expr\":[{\"accept\":null}],\"family\":\"ip\",\"handle\":3,\"table\":\"t\"}}";
      };
      # Read-back lists every object with the handle nft assigned.
      testReadBackObjectsKeepHandle = {
        expr = lib.mapAttrs (
          kind: body: helpers.validates nftlib.types.readBackObject { ${kind} = withHandle body; }
        ) addBodies;
        expected = lib.mapAttrs (_: _: true) addBodies;
      };
      # A Selector selects by handle where nft reads one: a rule's always,
      # and a named object's on delete, in place of its name. With a name,
      # nft never reads a handle (`testNamedSelectorsRejectAHandle`).
      testSelectorsSelectByHandle = {
        expr = lib.mapAttrs (_: helpers.validates nftlib.types.command) {
          deleteRule.delete.rule = removeAttrs rule [ "expr" ];
          destroyRule.destroy.rule = removeAttrs rule [ "expr" ];
          resetRule.reset.rule = removeAttrs rule [ "expr" ];
          deleteTable.delete.table = withHandle (removeAttrs addBodies.table [ "name" ]);
          deleteChain.delete.chain = withHandle (removeAttrs addBodies.chain [ "name" ]);
          deleteCounter.delete.counter = withHandle (removeAttrs addBodies.counter [ "name" ]);
          deleteSet.delete.set = withHandle scope;
          destroyChain.destroy.chain = withHandle scope;
          flushChain.flush.chain = withHandle scope;
          listTable.list.table = withHandle (removeAttrs addBodies.table [ "name" ]);
          resetQuota.reset.quota = withHandle scope;
        };
        expected = {
          deleteRule = true;
          destroyRule = true;
          resetRule = true;
          deleteTable = true;
          deleteChain = true;
          deleteCounter = true;
          deleteSet = true;
          destroyChain = false;
          flushChain = false;
          listTable = false;
          resetQuota = false;
        };
      };
    };

  /*
    Element statements: nft lists an element's `counter`, `quota`,
    `limit`, or `last` beside its value (json.c set_elem_expr_json), in a
    set's or map's elements and in a rule's anonymous set alike. Its JSON
    parser reads only `val`, `timeout`, `expires`, and `comment`
    (json_parse_set_elem_expr), so an input command takes `elemBody`,
    which rejects them, and Read-back takes `elemReadBackBody`.
  */
  elementStatementTests =
    let
      scope = {
        family = "ip";
        table = "t";
      };
      statementsByKey = {
        counter = {
          packets = 1;
          bytes = 2;
        };
        quota = {
          val = 100;
          val_unit = "bytes";
        };
        limit = {
          rate = 5;
          per = "second";
        };
        last.used = 1200;
      };
      element = key: {
        elem = {
          val = "10.0.0.1";
          ${key} = statementsByKey.${key};
        };
      };
      rule = key: {
        chain = "c";
        expr = [
          {
            match = {
              op = "==";
              left.payload = {
                protocol = "ip";
                field = "saddr";
              };
              right.set = [
                (element key)
                "10.0.0.2"
              ];
            };
          }
        ];
      };
      # The objects that hold elements, as input commands and Read-back
      # take them.
      holders = key: {
        set = scope // {
          name = "s";
          type = "ipv4_addr";
          elem = [ (element key) ];
        };
        map = scope // {
          name = "m";
          type = "ipv4_addr";
          map = "mark";
          elem = [
            [
              (element key)
              5
            ]
          ];
        };
        element = scope // {
          name = "s";
          elem = [ (element key) ];
        };
        rule = scope // rule key;
      };
      inputCommands = key: {
        "add set" = {
          add.set = (holders key).set;
        };
        "create map" = {
          create.map = (holders key).map;
        };
        "add element" = {
          add.element = (holders key).element;
        };
        "delete element" = {
          delete.element = (holders key).element;
        };
        "add rule" = {
          add.rule = (holders key).rule;
        };
        "insert rule" = {
          insert.rule = (holders key).rule;
        };
        "replace rule" = {
          replace.rule = (holders key).rule // {
            handle = 4;
          };
        };
      };
      keys = builtins.attrNames statementsByKey;
      ruleset = command: { nftables = [ command ]; };
    in
    lib.listToAttrs (
      lib.concatMap (
        key:
        lib.mapAttrsToList (
          name: command:
          lib.nameValuePair
            "testInputRejectsElementStatement_${lib.replaceStrings [ " " ] [ "_" ] name}_${key}"
            {
              expr = builtins.deepSeq (helpers.validate nftlib.types.ruleset (ruleset command)) null;
              expectedError.msg = "is not of type `element body without counter, quota, limit, or last[^']*Read-back";
            }
        ) (inputCommands key)
      ) keys
    )
    // {
      testReadBackAcceptsElementStatements = {
        expr = map (
          key:
          lib.mapAttrs (
            kind: body:
            helpers.validates nftlib.types.ruleset (ruleset {
              ${kind} = body // lib.optionalAttrs (kind != "element") { handle = 3; };
            })
          ) (holders key)
        ) keys;
        expected = map (_: {
          set = true;
          map = true;
          element = true;
          rule = true;
        }) keys;
      };
      testElementBodyRejectsStatements = {
        expr = map (key: helpers.validates nftlib.types.expressionBodies.elemBody (element key).elem) keys;
        expected = map (_: false) keys;
      };
      testElementReadBackBodyKeepsStatements = {
        expr = map (
          key: helpers.validates nftlib.types.expressionBodies.elemReadBackBody (element key).elem
        ) keys;
        expected = map (_: true) keys;
      };
      # `types.expression` is the input expression: its element takes
      # `elemBody`.
      testExpressionElementRejectsStatements = {
        expr = map (key: helpers.validates nftlib.types.expression (element key)) keys;
        expected = map (_: false) keys;
      };
    };
in
textDriftTests
// blockFieldDriftTests
// mishandledCommandTests
// tunnelCommandTests
// commandRequirementTests
// handleTests
// elementStatementTests
// listSelectorTests
// selectorTests
// {
  # ------------------------------------------------------------------
  # Verdicts
  # ------------------------------------------------------------------
  testAcceptVerdict = {
    expr = roundtrip nftlib.types.statement { accept = null; };
    expected = ''{"accept":null}'';
  };

  testDropVerdict = {
    expr = roundtrip nftlib.types.statement { drop = null; };
    expected = ''{"drop":null}'';
  };

  testJumpVerdict = {
    expr = roundtrip nftlib.types.statement {
      jump = {
        target = "inbound";
      };
    };
    expected = ''{"jump":{"target":"inbound"}}'';
  };

  # ------------------------------------------------------------------
  # Match with payload expression
  # ------------------------------------------------------------------
  testMatchPayload = {
    expr = roundtrip nftlib.types.statement {
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
    expected = "{\"match\":{\"left\":{\"payload\":{\"field\":\"dport\",\"protocol\":\"tcp\"}},\"op\":\"==\",\"right\":22}}";
  };

  # ------------------------------------------------------------------
  # Match with IPv6 address and prefix
  # ------------------------------------------------------------------
  testMatchIPv6Prefix = {
    expr = roundtrip nftlib.types.statement {
      match = {
        left = {
          payload = {
            protocol = "ip6";
            field = "saddr";
          };
        };
        right = {
          prefix = {
            addr = "2001:db8::";
            len = 32;
          };
        };
        op = "==";
      };
    };
    expected = "{\"match\":{\"left\":{\"payload\":{\"field\":\"saddr\",\"protocol\":\"ip6\"}},\"op\":\"==\",\"right\":{\"prefix\":{\"addr\":\"2001:db8::\",\"len\":32}}}}";
  };

  # ------------------------------------------------------------------
  # Port range
  # ------------------------------------------------------------------
  testPortRange = {
    expr = roundtrip nftlib.types.expression {
      range = [
        1024
        65535
      ];
    };
    expected = ''{"range":[1024,65535]}'';
  };

  # ------------------------------------------------------------------
  # Anonymous set of ports
  # ------------------------------------------------------------------
  testAnonymousSet = {
    expr = roundtrip nftlib.types.statement {
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
    };
    expected = "{\"match\":{\"left\":{\"payload\":{\"field\":\"dport\",\"protocol\":\"tcp\"}},\"op\":\"==\",\"right\":{\"set\":[22,80,443]}}}";
  };

  # ------------------------------------------------------------------
  # inet_service lookup via @set-reference string
  # ------------------------------------------------------------------
  testSetReference = {
    expr = roundtrip nftlib.types.statement {
      match = {
        left = {
          payload = {
            protocol = "tcp";
            field = "dport";
          };
        };
        right = "@allowed_ports";
        op = "==";
      };
    };
    expected = "{\"match\":{\"left\":{\"payload\":{\"field\":\"dport\",\"protocol\":\"tcp\"}},\"op\":\"==\",\"right\":\"@allowed_ports\"}}";
  };

  # ------------------------------------------------------------------
  # `{ set = "@name" }` — canonical libnftables-JSON named-set
  # reference shape (vs. the bare-string form above). Both shapes are
  # accepted by `nft -j`; this asserts the JSON renderer emits the
  # shape unchanged so consumers using `expr.setRef` get the documented
  # form on the wire.
  # ------------------------------------------------------------------
  testSetReferenceWrapped = {
    expr = roundtrip nftlib.types.statement {
      match = {
        left = {
          meta = {
            key = "iifname";
          };
        };
        right = {
          set = "@trusted";
        };
        op = "==";
      };
    };
    expected = "{\"match\":{\"left\":{\"meta\":{\"key\":\"iifname\"}},\"op\":\"==\",\"right\":{\"set\":\"@trusted\"}}}";
  };

  # ------------------------------------------------------------------
  # DNAT with port
  # ------------------------------------------------------------------
  testDnat = {
    expr = roundtrip nftlib.types.statement {
      dnat = {
        addr = "10.0.0.1";
        port = 8080;
        family = "ip";
      };
    };
    expected = ''{"dnat":{"addr":"10.0.0.1","family":"ip","port":8080}}'';
  };

  # ------------------------------------------------------------------
  # SNAT with flags
  # ------------------------------------------------------------------
  testSnatFlags = {
    expr = roundtrip nftlib.types.statement {
      snat = {
        addr = "192.0.2.1";
        flags = [
          "random"
          "persistent"
        ];
      };
    };
    expected = "{\"snat\":{\"addr\":\"192.0.2.1\",\"flags\":[\"random\",\"persistent\"]}}";
  };

  # ------------------------------------------------------------------
  # Masquerade (no addr)
  # ------------------------------------------------------------------
  testMasquerade = {
    expr = roundtrip nftlib.types.statement { masquerade = { }; };
    expected = ''{"masquerade":{}}'';
  };

  # ------------------------------------------------------------------
  # Named set using ipv4_addr type
  # ------------------------------------------------------------------
  testNamedSet = {
    expr = roundtrip nftlib.types.readBackObject {
      set = {
        family = "inet";
        table = "filter";
        name = "trusted_hosts";
        type = "ipv4_addr";
        flags = [ "interval" ];
        elem = [
          {
            prefix = {
              addr = "10.0.0.0";
              len = 8;
            };
          }
          "192.168.1.1"
        ];
      };
    };
    expected = "{\"set\":{\"elem\":[{\"prefix\":{\"addr\":\"10.0.0.0\",\"len\":8}},\"192.168.1.1\"],\"family\":\"inet\",\"flags\":[\"interval\"],\"name\":\"trusted_hosts\",\"table\":\"filter\",\"type\":\"ipv4_addr\"}}";
  };

  # ------------------------------------------------------------------
  # Map with concatenated key AND value: both sides are tuple types.
  # The nftables JSON parser (parser_json.c:3365) accepts datatype lists
  # for `type`/`map`; the dot-separated string form the adoc suggests
  # ("ipv4_addr . inet_service") is rejected at runtime.
  # ------------------------------------------------------------------
  testMapConcatenated = {
    expr = roundtrip nftlib.types.readBackObject {
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
      };
    };
    expected = "{\"map\":{\"family\":\"ip\",\"flags\":[\"interval\"],\"map\":[\"ipv4_addr\",\"inet_service\"],\"name\":\"port_forward\",\"table\":\"nat\",\"type\":[\"ipv4_addr\",\"inet_service\"]}}";
  };

  # ------------------------------------------------------------------
  # vmap (verdict map) with jumps
  # ------------------------------------------------------------------
  testVmap = {
    expr = roundtrip nftlib.types.statement {
      vmap = {
        key = {
          meta = {
            key = "iifname";
          };
        };
        data = "@iifname_vmap";
      };
    };
    expected = "{\"vmap\":{\"data\":\"@iifname_vmap\",\"key\":{\"meta\":{\"key\":\"iifname\"}}}}";
  };

  # nft rejects a bare list as the data of a vmap or a map lookup
  # ("invalid mapping expression list"); it takes the anonymous map
  # `{ set = [ … ]; }`.
  testVmapListDataRejected = {
    expr = roundtrip nftlib.types.statement {
      vmap = {
        key.meta.key = "mark";
        data = [
          [
            1
            { accept = null; }
          ]
        ];
      };
    };
    expectedError.msg = "validate\\.vmap\\.data.*is not of type";
  };
  testMapLookupListDataRejected = {
    expr = roundtrip nftlib.types.expression {
      map = {
        key.meta.key = "mark";
        data = [
          [
            1
            2
          ]
        ];
      };
    };
    expectedError.msg = "validate\\.map\\.data.*is not of type";
  };

  # ------------------------------------------------------------------
  # Meta expression
  # ------------------------------------------------------------------
  testMetaExpr = {
    expr = roundtrip nftlib.types.expression {
      meta = {
        key = "mark";
      };
    };
    expected = ''{"meta":{"key":"mark"}}'';
  };

  # nft's aliases for `ibrname`, `obrname`, and `ipsec` have no Field leaf
  # but stay valid raw input, since nft loads them.
  testMetaAliasKeysValidate = {
    expr = map (key: roundtrip nftlib.types.expression { meta = { inherit key; }; }) [
      "ibriport"
      "obriport"
      "secpath"
    ];
    expected = [
      ''{"meta":{"key":"ibriport"}}''
      ''{"meta":{"key":"obriport"}}''
      ''{"meta":{"key":"secpath"}}''
    ];
  };

  # ------------------------------------------------------------------
  # CT expression with direction
  # ------------------------------------------------------------------
  testCtExpr = {
    expr = roundtrip nftlib.types.expression {
      ct = {
        key = "saddr";
        dir = "original";
      };
    };
    expected = ''{"ct":{"dir":"original","key":"saddr"}}'';
  };

  # nft's JSON parser looks a ct key up in ct_templates (src/ct.c) and
  # fails on any other with "Unknown ct key".
  testCtKeyIsOneOfNftsCtKeys =
    let
      ctKeys = [
        "state"
        "direction"
        "status"
        "mark"
        "expiration"
        "helper"
        "l3proto"
        "saddr"
        "daddr"
        "protocol"
        "proto-src"
        "proto-dst"
        "label"
        "bytes"
        "packets"
        "avgpkt"
        "zone"
        "event"
        "ip saddr"
        "ip daddr"
        "ip6 saddr"
        "ip6 daddr"
        "secmark"
        "id"
      ];
      # The keys nft loads only with a direction.
      directional = [
        "saddr"
        "daddr"
        "proto-src"
        "proto-dst"
        "ip saddr"
        "ip daddr"
        "ip6 saddr"
        "ip6 daddr"
      ];
      inStatement = key: {
        match = {
          op = "==";
          left.ct = {
            inherit key;
          }
          // lib.optionalAttrs (builtins.elem key directional) { dir = "original"; };
          right = 1;
        };
      };
    in
    {
      expr = lib.filter (key: helpers.validates nftlib.types.statement (inStatement key)) (
        ctKeys
        ++ [
          "count"
          "wug"
        ]
      );
      expected = ctKeys;
    };

  /*
    A ct key's direction, by ct_dir_keys in nftables' json_parse_ct_expr
    and `nft -c -j` on 1.1.7: these keys fail ("Invalid argument") without
    `dir`, and the keys outside ct_dir_keys fail with it ("Direction not
    supported by CT key"). The other ct_dir_keys load either way.
  */
  testCtDirIsRequiredExactlyWhereNftNeedsIt =
    let
      requiresDir = [
        "saddr"
        "daddr"
        "proto-src"
        "proto-dst"
        "ip saddr"
        "ip daddr"
        "ip6 saddr"
        "ip6 daddr"
      ];
      takesDir = [
        "l3proto"
        "protocol"
        "packets"
        "bytes"
        "avgpkt"
        "zone"
      ];
      refusesDir = [
        "state"
        "direction"
        "status"
        "mark"
        "expiration"
        "helper"
        "label"
        "event"
        "secmark"
        "id"
      ];
      validates =
        keys: body:
        map (
          key:
          helpers.validates nftlib.types.expression {
            ct = {
              inherit key;
            }
            // body;
          }
        ) keys;
    in
    {
      expr = {
        requiresDir = {
          bare = validates requiresDir { };
          directed = validates requiresDir { dir = "original"; };
        };
        takesDir = {
          bare = validates takesDir { };
          directed = validates takesDir { dir = "reply"; };
        };
        refusesDir = {
          bare = validates refusesDir { };
          directed = validates refusesDir { dir = "original"; };
        };
      };
      expected = {
        requiresDir = {
          bare = map (_: false) requiresDir;
          directed = map (_: true) requiresDir;
        };
        takesDir = {
          bare = map (_: true) takesDir;
          directed = map (_: true) takesDir;
        };
        refusesDir = {
          bare = map (_: true) refusesDir;
          directed = map (_: false) refusesDir;
        };
      };
    };

  # nft's JSON parser never reads the ct expression's `family`, and its
  # printer never writes one, so the ct body has none.
  testCtHasNoFamily = {
    expr = helpers.validates nftlib.types.expression {
      ct = {
        key = "mark";
        family = "ip";
      };
    };
    expected = false;
  };

  # nft fails a FIB result without `saddr` or `daddr` among its flags
  # ("fib: need either saddr or daddr").
  testFibNeedsAnAddressFlag = {
    expr =
      map
        (
          body:
          helpers.validates nftlib.types.expression {
            fib = {
              result = "oif";
            }
            // body;
          }
        )
        [
          { }
          { flags = "iif"; }
          {
            flags = [
              "mark"
              "iif"
            ];
          }
          { flags = "daddr"; }
        ];
    expected = [
      false
      false
      false
      true
    ];
  };

  # nft fails every IPsec key without a direction ("Invalid argument").
  testIpsecNeedsDir = {
    expr =
      map
        (
          body:
          helpers.validates nftlib.types.expression {
            ipsec = {
              key = "reqid";
            }
            // body;
          }
        )
        [
          { }
          { dir = "in"; }
        ];
    expected = [
      false
      true
    ];
  };

  # ------------------------------------------------------------------
  # Binary AND operation (mask)
  # ------------------------------------------------------------------
  testBitAnd = {
    expr = roundtrip nftlib.types.expression {
      "&" = [
        {
          meta = {
            key = "mark";
          };
        }
        255
      ];
    };
    expected = ''{"&":[{"meta":{"key":"mark"}},255]}'';
  };

  # ------------------------------------------------------------------
  # Log with level and flags
  # ------------------------------------------------------------------
  testLog = {
    expr = roundtrip nftlib.types.statement {
      log = {
        prefix = "DROPPED: ";
        level = "info";
        flags = [
          "tcp options"
          "ip options"
        ];
      };
    };
    expected = "{\"log\":{\"flags\":[\"tcp options\",\"ip options\"],\"level\":\"info\",\"prefix\":\"DROPPED: \"}}";
  };

  # ------------------------------------------------------------------
  # Limit with per-unit
  # ------------------------------------------------------------------
  testLimit = {
    expr = roundtrip nftlib.types.statement {
      limit = {
        rate = 100;
        per = "second";
        burst = 50;
      };
    };
    expected = ''{"limit":{"burst":50,"per":"second","rate":100}}'';
  };

  /*
    nft's JSON parser reads every unit but `packets` as bytes
    (rate_to_bytes), and its text grammar takes a byte unit only as bytes,
    kbytes, or mbytes, so each unit field takes nft's units and nothing
    else. A rate is in packets or a byte unit; a burst, a quota, and a used
    amount are in a byte unit.
  */
  testUnitFieldsTakeNftsUnits =
    let
      limitStatement = fields: {
        limit = {
          rate = 10;
          per = "second";
        }
        // fields;
      };
      quotaStatement = fields: {
        quota = {
          val = 10;
          used = 5;
        }
        // fields;
      };
      limitObject = {
        family = "inet";
        table = "t";
        name = "l";
        rate = 10;
        per = "second";
      };
      accepted = {
        statement = helpers.validates nftlib.types.statement;
        limitObject = body: helpers.validates nftlib.types.objectBodies.limitBody (limitObject // body);
      };
      byField = {
        limit_rate_unit =
          unit:
          accepted.statement (limitStatement {
            rate_unit = unit;
          });
        limit_burst_unit =
          unit:
          accepted.statement (limitStatement {
            burst_unit = unit;
          });
        quota_val_unit =
          unit:
          accepted.statement (quotaStatement {
            val_unit = unit;
          });
        quota_used_unit =
          unit:
          accepted.statement (quotaStatement {
            used_unit = unit;
          });
        limitObject_rate_unit = unit: accepted.limitObject { rate_unit = unit; };
        limitObject_burst_unit = unit: accepted.limitObject { burst_unit = unit; };
      };
      units = [
        "packets"
        "bytes"
        "kbytes"
        "mbytes"
        "gbytes"
        "furlongs"
      ];
    in
    {
      expr = lib.mapAttrs (_: check: lib.filter check units) byField;
      expected =
        let
          rateUnits = [
            "packets"
            "bytes"
            "kbytes"
            "mbytes"
          ];
          byteUnits = [
            "bytes"
            "kbytes"
            "mbytes"
          ];
        in
        {
          limit_rate_unit = rateUnits;
          limit_burst_unit = byteUnits;
          quota_val_unit = byteUnits;
          quota_used_unit = byteUnits;
          limitObject_rate_unit = rateUnits;
          limitObject_burst_unit = byteUnits;
        };
    };

  # ------------------------------------------------------------------
  # Counter (named reference)
  # ------------------------------------------------------------------
  testCounterReference = {
    expr = roundtrip nftlib.types.statement { counter = "http_hits"; };
    expected = ''{"counter":"http_hits"}'';
  };

  # ------------------------------------------------------------------
  # Counter (anonymous)
  # ------------------------------------------------------------------
  testCounterAnonymous = {
    expr = roundtrip nftlib.types.statement {
      counter = {
        packets = 0;
        bytes = 0;
      };
    };
    expected = ''{"counter":{"bytes":0,"packets":0}}'';
  };

  # nft parses an inline counter only with both fields; any other object
  # is taken for a named-counter reference and fails.
  testCounterInlineNeedsPacketsAndBytes = {
    expr = map (body: helpers.validates nftlib.types.statement { counter = body; }) [
      { }
      { packets = 5; }
      { bytes = 5; }
    ];
    expected = [
      false
      false
      false
    ];
  };

  # A counter with one of them is a type error naming both, not a missing
  # option.
  testCounterInlineWithOnlyPacketsIsATypeError = {
    expr = roundtrip nftlib.types.statement { counter.packets = 5; };
    expectedError.msg = "is not of type .*inline counter with packets and bytes";
  };
  testCounterInlineWithOnlyBytesIsATypeError = {
    expr = roundtrip nftlib.types.statement { counter.bytes = 5; };
    expectedError.msg = "is not of type .*inline counter with packets and bytes";
  };

  # tproxy, snat and dnat translate to an address or a port: nft refuses
  # an empty tproxy ("Either address or port must be specified!"), and the
  # kernel an snat or dnat with neither ("Invalid argument").
  testTranslationNeedsAddressOrPort = {
    expr = map (helpers.validates nftlib.types.statement) [
      { tproxy = { }; }
      { tproxy.family = "ip"; }
      { tproxy = null; }
      { snat = { }; }
      { snat.flags = [ "random" ]; }
      { snat = null; }
      { dnat = { }; }
      { dnat.family = "ip"; }
      { tproxy.port = 8080; }
      { tproxy.addr = "10.0.0.1"; }
      { snat.port = 1024; }
      { dnat.addr = "10.0.0.1"; }
    ];
    expected = [
      false
      false
      false
      false
      false
      false
      false
      false
      true
      true
      true
      true
    ];
  };

  # nft lists a statement with no options as a null body, and its JSON
  # parser loads that body back.
  testReadBackNullStatementBodies = {
    expr = toJson (readBack {
      rule = {
        family = "inet";
        table = "t";
        chain = "c";
        handle = 2;
        expr = [
          { log = null; }
          { masquerade = null; }
          { redirect = null; }
          { queue = null; }
          { reject = null; }
        ];
      };
    });
    expected = "{\"nftables\":[{\"rule\":{\"chain\":\"c\",\"expr\":[{\"log\":null},{\"masquerade\":null},{\"redirect\":null},{\"queue\":null},{\"reject\":null}],\"family\":\"inet\",\"handle\":2,\"table\":\"t\"}}]}";
  };

  # ------------------------------------------------------------------
  # FIB reverse-path check
  # ------------------------------------------------------------------
  testFib = {
    expr = roundtrip nftlib.types.expression {
      fib = {
        result = "oif";
        flags = [
          "saddr"
          "mark"
        ];
      };
    };
    expected = ''{"fib":{"flags":["saddr","mark"],"result":"oif"}}'';
  };

  # ------------------------------------------------------------------
  # FIB result "check" — predicate form (parser_json.c:1181, special
  # NFT_FIB_F_PRESENT branch).
  # ------------------------------------------------------------------
  testFibResultCheck = {
    expr = roundtrip nftlib.types.expression {
      fib = {
        result = "check";
        flags = [ "saddr" ];
      };
    };
    expected = ''{"fib":{"flags":["saddr"],"result":"check"}}'';
  };

  # ------------------------------------------------------------------
  # rt key "ipsec" — NFT_RT_XFRM token (parser_json.c:993-997).
  # ------------------------------------------------------------------
  testRtIpsecKey = {
    expr = roundtrip nftlib.types.expression {
      rt = {
        key = "ipsec";
        family = "ip";
      };
    };
    expected = ''{"rt":{"family":"ip","key":"ipsec"}}'';
  };

  # ------------------------------------------------------------------
  # osf key "version" — second branch in parser_json.c:486-489 that
  # was missed when the schema was first derived (only "name" present).
  # ------------------------------------------------------------------
  testOsfVersionKey = {
    expr = roundtrip nftlib.types.expression {
      osf = {
        key = "version";
        ttl = "loose";
      };
    };
    expected = ''{"osf":{"key":"version","ttl":"loose"}}'';
  };

  # ------------------------------------------------------------------
  # `flush meter` — accepted by parser_json.c:4302 but previously
  # missing from the schema's `flushObject` union.
  # ------------------------------------------------------------------
  testFlushMeter = {
    expr = roundtrip nftlib.types.command {
      flush = {
        meter = {
          family = "inet";
          table = "filter";
          name = "rate_meter";
        };
      };
    };
    expected = "{\"flush\":{\"meter\":{\"family\":\"inet\",\"name\":\"rate_meter\",\"table\":\"filter\"}}}";
  };

  # ------------------------------------------------------------------
  # `flush flowtable` — rejected by parser_json.c (no `flowtable` row
  # in `cmd_obj_table[]` at line 4297-4304). Schema previously
  # accepted it; this asserts that's no longer the case.
  # ------------------------------------------------------------------
  testFlushFlowtableRejected = {
    expr = roundtrip nftlib.types.command {
      flush = {
        flowtable = {
          family = "inet";
          table = "filter";
          name = "ft";
        };
      };
    };
    expectedError.msg = "validate\\.flush.*is not of type";
  };

  # nft evaluates a flowtable's hook as a netdev hook and refuses any but
  # `ingress` ("invalid hook"), whatever the table's family.
  testFlowtableHookIsIngressOnly = {
    expr =
      map
        (
          hook:
          helpers.validates nftlib.types.addObject {
            flowtable = {
              family = "inet";
              table = "t";
              name = "ft";
              inherit hook;
              prio = 0;
            };
          }
        )
        [
          "ingress"
          "input"
          "egress"
        ];
    expected = [
      true
      false
      false
    ];
  };

  testFlowtableHookEnum = {
    expr = {
      enum = nftlib.enums.flowtableHook;
      type = map nftlib.types.flowtableHook.check [
        "ingress"
        "input"
      ];
    };
    expected = {
      enum = [ "ingress" ];
      type = [
        true
        false
      ];
    };
  };

  # nft's JSON loads an added, inserted, or replaced rule with no
  # statements as written, so the schema accepts one (ADR 0010); only the
  # text renderers refuse it (#96).
  testRuleWithoutStatementsValidates =
    let
      body = {
        family = "inet";
        table = "filter";
        chain = "input";
        expr = [ ];
      };
      commands = {
        add.add.rule = body;
        insert.insert.rule = body;
        replace.replace.rule = body // {
          handle = 4;
        };
      };
    in
    {
      expr = lib.mapAttrs (_: helpers.validates nftlib.types.command) commands;
      expected = lib.mapAttrs (_: _: true) commands;
    };

  # nftables rejects `create rule` explicitly. `create` must not reuse the
  # broader add-object union or raw typed input would accept an impossible
  # command even though the DSL omits its constructor.
  testCreateRuleRejected = {
    expr = roundtrip nftlib.types.command {
      create = {
        rule = {
          family = "inet";
          table = "filter";
          chain = "input";
          expr = [ ];
        };
      };
    };
    expectedError.msg = "validate\\.create.*is not of type";
  };

  # ------------------------------------------------------------------
  # Limit object: only fields the JSON parser actually reads
  # (parser_json.c:3863-3884). The previously-exposed `unit` field was
  # vestigial — the limit type is derived from `rate_unit`. Asserts
  # that a `unit` key is now rejected so future re-additions get caught.
  # ------------------------------------------------------------------
  testLimitObjectMinimal = {
    expr = roundtrip nftlib.types.readBackObject {
      limit = {
        family = "inet";
        table = "filter";
        name = "slow";
        rate = 5;
        per = "second";
        burst = 10;
      };
    };
    expected = "{\"limit\":{\"burst\":10,\"family\":\"inet\",\"name\":\"slow\",\"per\":\"second\",\"rate\":5,\"table\":\"filter\"}}";
  };

  testLimitObjectUnitRejected = {
    expr = roundtrip nftlib.types.readBackObject {
      limit = {
        family = "inet";
        table = "filter";
        name = "slow";
        rate = 5;
        per = "second";
        unit = "packets";
      };
    };
    expectedError.msg = "validate\\.limit\\.unit.*does not exist";
  };

  # ------------------------------------------------------------------
  # Numgen
  # ------------------------------------------------------------------
  testNumgen = {
    expr = roundtrip nftlib.types.expression {
      numgen = {
        mode = "inc";
        mod = 4;
        offset = 100;
      };
    };
    expected = ''{"numgen":{"mod":4,"mode":"inc","offset":100}}'';
  };

  # ------------------------------------------------------------------
  # Concatenation expression
  # ------------------------------------------------------------------
  testConcat = {
    expr = roundtrip nftlib.types.expression {
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
    expected = "{\"concat\":[{\"payload\":{\"field\":\"saddr\",\"protocol\":\"ip\"}},{\"payload\":{\"field\":\"dport\",\"protocol\":\"tcp\"}}]}";
  };

  # ------------------------------------------------------------------
  # Table object
  # ------------------------------------------------------------------
  testTable = {
    expr = roundtrip nftlib.types.readBackObject {
      table = {
        family = "inet";
        name = "filter";
      };
    };
    expected = ''{"table":{"family":"inet","name":"filter"}}'';
  };

  # ------------------------------------------------------------------
  # Base chain
  # ------------------------------------------------------------------
  testBaseChain = {
    expr = roundtrip nftlib.types.readBackObject {
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
    expected = "{\"chain\":{\"family\":\"inet\",\"hook\":\"input\",\"name\":\"input\",\"policy\":\"drop\",\"prio\":0,\"table\":\"filter\",\"type\":\"filter\"}}";
  };

  /*
    nft's chain parser reads type, hook and prio as one optional group,
    so a chain missing any of them loads as a regular chain whose rules
    never see packets. The schema takes all three or none (a Known
    difference, ADR 0010), in commands and in Read-back.
  */
  testBaseChainNeedsTypeHookAndPrio =
    let
      chain = {
        family = "ip";
        table = "t";
        name = "c";
      };
      placements = [
        { }
        { type = "filter"; }
        { hook = "input"; }
        { prio = 0; }
        {
          type = "filter";
          hook = "input";
        }
        {
          type = "filter";
          prio = 0;
        }
        {
          hook = "input";
          prio = 0;
        }
        {
          type = "filter";
          hook = "input";
          prio = 0;
        }
      ];
      validatesIn = placement: {
        add = helpers.validates nftlib.types.command { add.chain = chain // placement; };
        create = helpers.validates nftlib.types.command { create.chain = chain // placement; };
        readBack = helpers.validates nftlib.types.ruleset {
          nftables = [ { chain = chain // placement // { handle = 1; }; } ];
        };
      };
      everywhere = accepted: {
        add = accepted;
        create = accepted;
        readBack = accepted;
      };
    in
    {
      expr = map validatesIn placements;
      expected = [
        (everywhere true)
        (everywhere false)
        (everywhere false)
        (everywhere false)
        (everywhere false)
        (everywhere false)
        (everywhere false)
        (everywhere true)
      ];
    };

  /*
    nft's chain parser reads dev and policy only with type, hook and prio,
    so JSON loads a regular chain without them, and text fails. The schema
    takes them on a base chain only, in commands and in Read-back.
  */
  testDevAndPolicyNeedABaseChain =
    let
      chain = {
        family = "netdev";
        table = "t";
        name = "c";
      };
      base = {
        type = "filter";
        hook = "ingress";
        prio = 0;
      };
      fields = [
        { policy = "drop"; }
        { dev = "lo"; }
      ];
      validatesIn = body: {
        add = helpers.validates nftlib.types.command { add.chain = chain // body; };
        create = helpers.validates nftlib.types.command { create.chain = chain // body; };
        readBack = helpers.validates nftlib.types.ruleset {
          nftables = [ { chain = chain // body // { handle = 1; }; } ];
        };
      };
      everywhere = accepted: {
        add = accepted;
        create = accepted;
        readBack = accepted;
      };
    in
    {
      expr = map validatesIn (fields ++ map (field: base // field) fields);
      expected = [
        (everywhere false)
        (everywhere false)
        (everywhere true)
        (everywhere true)
      ];
    };

  testBaseChainWithoutTypeNamesTheConstraint = {
    expr = helpers.validate nftlib.types.command {
      add.chain = {
        family = "ip";
        table = "t";
        name = "c";
        hook = "input";
        prio = 0;
      };
    };
    expectedError.msg = "type, hook and prio";
  };

  # ------------------------------------------------------------------
  # Rule with multiple statements
  # ------------------------------------------------------------------
  testRule = {
    expr = roundtrip nftlib.types.readBackObject {
      rule = {
        family = "inet";
        table = "filter";
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
          {
            counter = {
              packets = 0;
              bytes = 0;
            };
          }
          { accept = null; }
        ];
      };
    };
    expected = "{\"rule\":{\"chain\":\"input\",\"expr\":[{\"match\":{\"left\":{\"payload\":{\"field\":\"dport\",\"protocol\":\"tcp\"}},\"op\":\"==\",\"right\":22}},{\"counter\":{\"bytes\":0,\"packets\":0}},{\"accept\":null}],\"family\":\"inet\",\"table\":\"filter\"}}";
  };

  # ------------------------------------------------------------------
  # Flush ruleset command
  # ------------------------------------------------------------------
  testFlushRuleset = {
    expr = roundtrip nftlib.types.command {
      flush = {
        ruleset = null;
      };
    };
    expected = ''{"flush":{"ruleset":null}}'';
  };

  # ------------------------------------------------------------------
  # Add command wrapping a table
  # ------------------------------------------------------------------
  testAddCommand = {
    expr = roundtrip nftlib.types.command {
      add = {
        table = {
          family = "ip";
          name = "nat";
        };
      };
    };
    expected = ''{"add":{"table":{"family":"ip","name":"nat"}}}'';
  };

  # ------------------------------------------------------------------
  # Whole ruleset envelope
  # ------------------------------------------------------------------
  testRulesetEnvelope = {
    expr = roundtrip nftlib.types.ruleset {
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
      ];
    };
    expected = "{\"nftables\":[{\"flush\":{\"ruleset\":null}},{\"add\":{\"table\":{\"family\":\"inet\",\"name\":\"filter\"}}}]}";
  };

  # ------------------------------------------------------------------
  # Element object
  # ------------------------------------------------------------------
  testElement = {
    expr = roundtrip nftlib.types.readBackObject {
      element = {
        family = "inet";
        table = "filter";
        name = "blocklist";
        elem = [
          "1.2.3.4"
          "5.6.7.8"
        ];
      };
    };
    expected = "{\"element\":{\"elem\":[\"1.2.3.4\",\"5.6.7.8\"],\"family\":\"inet\",\"name\":\"blocklist\",\"table\":\"filter\"}}";
  };

  # ------------------------------------------------------------------
  # Element statements: nft lists each element's stateful statement as a
  # key beside `val` (json.c set_elem_expr_json), and its JSON parser
  # ignores both that and a `stmt` list on input (ADR 0010).
  # ------------------------------------------------------------------
  testReadBackElementStatements = {
    expr = builtins.isAttrs (readBack {
      set = {
        family = "ip";
        name = "s";
        table = "t";
        type = "ipv4_addr";
        handle = 3;
        elem = [
          {
            elem = {
              val = "10.0.0.1";
              counter = {
                packets = 1;
                bytes = 2;
              };
            };
          }
          {
            elem = {
              val = "10.0.0.2";
              quota = {
                val = 100;
                val_unit = "bytes";
                used = 40;
                used_unit = "bytes";
              };
            };
          }
          {
            elem = {
              val = "10.0.0.3";
              limit = {
                rate = 5;
                burst = 0;
                per = "second";
              };
            };
          }
          {
            elem = {
              val = "10.0.0.4";
              last.used = 1200;
            };
          }
        ];
        stmt = [ { counter = null; } ];
      };
    });
    expected = true;
  };

  # `nft -s` lists a counter and a last statement without state.
  testReadBackStatelessElementStatements = {
    expr = builtins.isAttrs (readBack {
      element = {
        family = "ip";
        name = "s";
        table = "t";
        elem = [
          {
            elem = {
              val = "10.0.0.1";
              counter = null;
              last = null;
            };
          }
        ];
      };
    });
    expected = true;
  };

  # The keys keep their statement bodies: a partial counter is refused
  # here as in a rule.
  testElementCounterRejectsPartialBody = {
    expr = readBack {
      element = {
        family = "ip";
        name = "s";
        table = "t";
        elem = [
          {
            elem.val = "10.0.0.1";
            elem.counter.packets = 1;
          }
        ];
      };
    };
    expectedError.msg = "elem\.counter.*is not of type";
  };

  # No listing emits a `stmt` list, and nft's JSON parser ignores it.
  testElementRejectsStmt = {
    expr = roundtrip nftlib.types.expression {
      elem = {
        val = "1.2.3.4";
        stmt = [ { counter = null; } ];
      };
    };
    expectedError.msg = "elem\.stmt' does not exist";
  };

  # ------------------------------------------------------------------
  # Reject with icmp code
  # ------------------------------------------------------------------
  testReject = {
    expr = roundtrip nftlib.types.statement {
      reject = {
        type = "icmp";
        expr = "host-unreachable";
      };
    };
    expected = ''{"reject":{"expr":"host-unreachable","type":"icmp"}}'';
  };

  # ------------------------------------------------------------------
  # Meter statement
  # ------------------------------------------------------------------
  testMeter = {
    expr = roundtrip nftlib.types.statement {
      meter = {
        name = "http_ratelimit";
        key = {
          meta = {
            key = "iifname";
          };
        };
        stmt = {
          limit = {
            rate = 100;
            per = "second";
          };
        };
      };
    };
    expected = "{\"meter\":{\"key\":{\"meta\":{\"key\":\"iifname\"}},\"name\":\"http_ratelimit\",\"stmt\":{\"limit\":{\"per\":\"second\",\"rate\":100}}}}";
  };

  # ------------------------------------------------------------------
  # List-of-singleton flag coercion: single flag written as a string
  # ------------------------------------------------------------------
  testSingletonFlag = {
    expr = roundtrip nftlib.types.statement {
      snat = {
        addr = "192.0.2.1";
        flags = "random";
      };
    };
    expected = ''{"snat":{"addr":"192.0.2.1","flags":"random"}}'';
  };

  # ------------------------------------------------------------------
  # Raw payload form (base+offset+len)
  # ------------------------------------------------------------------
  testRawPayload = {
    expr = roundtrip nftlib.types.expression {
      payload = {
        base = "nh";
        offset = 72;
        len = 16;
      };
    };
    expected = ''{"payload":{"base":"nh","len":16,"offset":72}}'';
  };

  # ------------------------------------------------------------------
  # Mixed raw+named payload keys must be rejected (spec: mutually exclusive)
  # ------------------------------------------------------------------
  testPayloadMixingRejected = {
    expr = roundtrip nftlib.types.expression {
      payload = {
        base = "nh";
        offset = 0;
        len = 16;
        protocol = "tcp";
        field = "dport";
      };
    };
    expectedError.msg = "validate\\.payload\\.field.*does not exist";
  };

  # ------------------------------------------------------------------
  # Incomplete raw payload (missing len) must be rejected
  # ------------------------------------------------------------------
  testRawPayloadIncompleteRejected = {
    expr = roundtrip nftlib.types.expression {
      payload = {
        base = "nh";
        offset = 0;
      };
    };
    expectedError.msg = "validate\\.payload. is not of type";
  };

  # ------------------------------------------------------------------
  # Incomplete named payload (missing field) must be rejected
  # ------------------------------------------------------------------
  testNamedPayloadIncompleteRejected = {
    expr = roundtrip nftlib.types.expression {
      payload = {
        protocol = "tcp";
      };
    };
    expectedError.msg = "validate\\.payload. is not of type";
  };

  # ------------------------------------------------------------------
  # `last` statement (bare null form)
  # ------------------------------------------------------------------
  testLastStmtNull = {
    expr = roundtrip nftlib.types.statement { last = null; };
    expected = ''{"last":null}'';
  };

  # ------------------------------------------------------------------
  # Counter stateless null form (emitted by `nft -j list --stateless`)
  # ------------------------------------------------------------------
  testCounterStatelessNull = {
    expr = roundtrip nftlib.types.statement { counter = null; };
    expected = ''{"counter":null}'';
  };

  # ------------------------------------------------------------------
  # `last` statement with timestamp
  # ------------------------------------------------------------------
  testLastStmtUsed = {
    expr = roundtrip nftlib.types.statement {
      last = {
        used = -1;
      };
    };
    expected = ''{"last":{"used":-1}}'';
  };

  # ------------------------------------------------------------------
  # `flow` offload statement
  # ------------------------------------------------------------------
  testFlowStmt = {
    expr = roundtrip nftlib.types.statement {
      flow = {
        op = "add";
        flowtable = "@ft";
      };
    };
    expected = ''{"flow":{"flowtable":"@ft","op":"add"}}'';
  };

  # ------------------------------------------------------------------
  # `tproxy` transparent proxy
  # ------------------------------------------------------------------
  testTproxyStmt = {
    expr = roundtrip nftlib.types.statement {
      tproxy = {
        family = "ip";
        addr = "127.0.0.1";
        port = 8080;
      };
    };
    expected = ''{"tproxy":{"addr":"127.0.0.1","family":"ip","port":8080}}'';
  };

  # ------------------------------------------------------------------
  # `synproxy` anonymous configuration
  # ------------------------------------------------------------------
  testSynproxyAnon = {
    expr = roundtrip nftlib.types.statement {
      synproxy = {
        mss = 1460;
        wscale = 7;
        flags = [
          "timestamp"
          "sack-perm"
        ];
      };
    };
    expected = "{\"synproxy\":{\"flags\":[\"timestamp\",\"sack-perm\"],\"mss\":1460,\"wscale\":7}}";
  };

  # A string is a name, never a module path: the anonymous body doesn't
  # claim a path-like reference and import it.
  testSynproxyPathLikeNameIsAName = {
    expr = roundtrip nftlib.types.statement { synproxy = "/sp1"; };
    expected = ''{"synproxy":"/sp1"}'';
  };

  testSynproxyObjectPathLikeNameIsAName = {
    expr = roundtrip nftlib.types.command {
      add.synproxy = {
        family = "inet";
        table = "t";
        name = "/sp1";
        mss = 1460;
        wscale = 7;
      };
    };
    expected = "{\"add\":{\"synproxy\":{\"family\":\"inet\",\"mss\":1460,\"name\":\"/sp1\",\"table\":\"t\",\"wscale\":7}}}";
  };

  # A body is an attrset of fields: a path-like string or a module function
  # in a body position is a schema error, not a module to import or call.
  testBodiesAreData = {
    expr = map (helpers.validates nftlib.types.statement) [
      { jump = "/c"; }
      { jump = _: { target = "c"; }; }
      {
        jump = {
          target = "c";
          _module.check = false;
          bogus = 1;
        };
      }
      { counter = "/c"; }
    ];
    expected = [
      false
      false
      false
      true
    ];
  };

  # ------------------------------------------------------------------
  # `synproxy` empty (all defaults)
  # ------------------------------------------------------------------
  testSynproxyNull = {
    expr = roundtrip nftlib.types.statement { synproxy = null; };
    expected = ''{"synproxy":null}'';
  };

  # ------------------------------------------------------------------
  # `reset` tcp option strip
  # ------------------------------------------------------------------
  testResetStmt = {
    expr = roundtrip nftlib.types.statement {
      reset = {
        "tcp option" = {
          name = "sack-perm";
        };
      };
    };
    expected = ''{"reset":{"tcp option":{"name":"sack-perm"}}}'';
  };

  # nft's reset statement strips a TCP option and refuses anything else
  # ("Illegal TCP optstrip argument").
  testResetStmtRejectsOtherExpressions = {
    expr = builtins.filter (helpers.validates nftlib.types.statement) [
      { reset.ct.key = "mark"; }
      { reset = "sack-perm"; }
      { reset = 1; }
    ];
    expected = [ ];
  };

  # ------------------------------------------------------------------
  # `secmark` and `tunnel` statements (reference forms)
  # ------------------------------------------------------------------
  testSecmarkStmt = {
    expr = roundtrip nftlib.types.statement { secmark = "@my_secmark"; };
    expected = ''{"secmark":"@my_secmark"}'';
  };

  testTunnelStmt = {
    expr = roundtrip nftlib.types.statement { tunnel = "@my_tunnel"; };
    expected = ''{"tunnel":"@my_tunnel"}'';
  };

  # ------------------------------------------------------------------
  # `ipsec` (xfrm) expression
  # ------------------------------------------------------------------
  testIpsecExpr = {
    expr = roundtrip nftlib.types.expression {
      ipsec = {
        key = "saddr";
        family = "ip";
        dir = "in";
      };
    };
    expected = ''{"ipsec":{"dir":"in","family":"ip","key":"saddr"}}'';
  };

  # ------------------------------------------------------------------
  # `tunnel` expression (metadata key)
  # ------------------------------------------------------------------
  testTunnelExpr = {
    expr = roundtrip nftlib.types.expression {
      tunnel = {
        key = "id";
      };
    };
    expected = ''{"tunnel":{"key":"id"}}'';
  };

  # ------------------------------------------------------------------
  # `secmark` named object
  # ------------------------------------------------------------------
  testSecmarkObject = {
    expr = roundtrip nftlib.types.readBackObject {
      secmark = {
        family = "inet";
        table = "filter";
        name = "sec_http";
        context = "system_u:object_r:http_packet_t:s0";
      };
    };
    expected = "{\"secmark\":{\"context\":\"system_u:object_r:http_packet_t:s0\",\"family\":\"inet\",\"name\":\"sec_http\",\"table\":\"filter\"}}";
  };

  # ------------------------------------------------------------------
  # `synproxy` named object
  # ------------------------------------------------------------------
  testSynproxyObject = {
    expr = roundtrip nftlib.types.readBackObject {
      synproxy = {
        family = "inet";
        table = "filter";
        name = "sp1";
        mss = 1460;
        wscale = 7;
        flags = [ "timestamp" ];
      };
    };
    expected = "{\"synproxy\":{\"family\":\"inet\",\"flags\":[\"timestamp\"],\"mss\":1460,\"name\":\"sp1\",\"table\":\"filter\",\"wscale\":7}}";
  };

  # ------------------------------------------------------------------
  # `ct count` named object (nftables 1.1.7+)
  # ------------------------------------------------------------------
  testCtCountObject = {
    expr = roundtrip nftlib.types.readBackObject {
      "ct count" = {
        family = "ip";
        table = "t";
        name = "c1";
        val = 5;
        inv = true;
        comment = "over five";
      };
    };
    expected = "{\"ct count\":{\"comment\":\"over five\",\"family\":\"ip\",\"inv\":true,\"name\":\"c1\",\"table\":\"t\",\"val\":5}}";
  };

  testCtCountObjectRequiresVal = {
    expr = roundtrip nftlib.types.readBackObject {
      "ct count" = {
        family = "ip";
        table = "t";
        name = "c1";
      };
    };
    expectedError.msg = "val.*was accessed but has no value defined";
  };

  # ------------------------------------------------------------------
  # Stateful statements reference a named object by name or by a map
  # expression that selects the name (objref).
  # ------------------------------------------------------------------
  testCtCountNamedReference = {
    expr = roundtrip nftlib.types.statement { "ct count" = "c1"; };
    expected = ''{"ct count":"c1"}'';
  };

  testStatefulMapReferences = {
    expr = map (tag: roundtrip nftlib.types.statement { ${tag} = portMapReference; }) [
      "counter"
      "quota"
      "limit"
      "ct count"
      "synproxy"
    ];
    expected = map (tag: ''{"${tag}":${portMapReferenceJson}}'') [
      "counter"
      "quota"
      "limit"
      "ct count"
      "synproxy"
    ];
  };

  # A reference is only a name or a map: other expressions stay rejected
  # where the statement has no inline form that accepts them.
  testCtCountRejectsNonMapExpression = {
    expr = roundtrip nftlib.types.statement {
      "ct count".payload = {
        protocol = "tcp";
        field = "dport";
      };
    };
    expectedError.msg = "validate\\.\"ct count\"\\.payload.*does not exist";
  };

  /*
    Every stateful object Reference takes the one name-or-map type, so a
    number or a boolean fails for each tag as for a quota. nft refuses a
    boolean ("Boolean values not allowed in this context") and loads a
    number as the name "5", a Known difference (ADR 0010).
  */
  testObjectReferencesRejectNumbersAndBooleans = {
    expr = lib.concatMap (
      tag:
      lib.optional (helpers.validates nftlib.types.statement { ${tag} = 5; }) "${tag} = 5"
      ++ lib.optional (helpers.validates nftlib.types.statement { ${tag} = true; }) "${tag} = true"
    ) objectReferenceTags;
    expected = [ ];
  };

  # A Reference is a name or a map, never another expression.
  testObjectReferencesRejectNonMapExpressions = {
    expr = builtins.filter (
      tag: helpers.validates nftlib.types.statement { ${tag}.meta.key = "mark"; }
    ) objectReferenceTags;
    expected = [ ];
  };

  testObjectReferencesTakeNamesAndMaps = {
    expr = lib.concatMap (tag: [
      (roundtrip nftlib.types.statement { ${tag} = "o"; })
      (roundtrip nftlib.types.statement { ${tag} = portMapReference; })
    ]) objectReferenceTags;
    expected = lib.concatMap (tag: [
      ''{"${tag}":"o"}''
      ''{"${tag}":${portMapReferenceJson}}''
    ]) objectReferenceTags;
  };

  # ------------------------------------------------------------------
  # NAT flag: netmap (added alongside random/fully-random/persistent)
  # ------------------------------------------------------------------
  testNetmapNatFlag = {
    expr = roundtrip nftlib.types.statement {
      dnat = {
        addr = "10.0.0.0/24";
        flags = [ "netmap" ];
      };
    };
    expected = ''{"dnat":{"addr":"10.0.0.0/24","flags":["netmap"]}}'';
  };

  # ------------------------------------------------------------------
  # `destroy` command (like delete but idempotent)
  # ------------------------------------------------------------------
  testDestroyCommand = {
    expr = roundtrip nftlib.types.command {
      destroy = {
        table = {
          family = "ip";
          name = "old";
        };
      };
    };
    expected = ''{"destroy":{"table":{"family":"ip","name":"old"}}}'';
  };

  # ------------------------------------------------------------------
  # Tunnel object: VXLAN encapsulation
  # ------------------------------------------------------------------
  testTunnelVxlan = {
    expr = roundtrip nftlib.types.readBackObject {
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
    expected = "{\"tunnel\":{\"dst-ipv4\":\"10.0.0.2\",\"family\":\"inet\",\"id\":42,\"name\":\"v\",\"src-ipv4\":\"10.0.0.1\",\"table\":\"t\",\"tunnel\":{\"gbp\":100},\"type\":\"vxlan\"}}";
  };

  # ------------------------------------------------------------------
  # Tunnel object: ERSPAN v1
  # ------------------------------------------------------------------
  testTunnelErspanV1 = {
    expr = roundtrip nftlib.types.readBackObject {
      tunnel = {
        family = "inet";
        table = "t";
        name = "e1";
        type = "erspan";
        tunnel = {
          version = 1;
          index = 7;
        };
      };
    };
    expected = "{\"tunnel\":{\"family\":\"inet\",\"name\":\"e1\",\"table\":\"t\",\"tunnel\":{\"index\":7,\"version\":1},\"type\":\"erspan\"}}";
  };

  # ------------------------------------------------------------------
  # Tunnel object: ERSPAN v2
  # ------------------------------------------------------------------
  testTunnelErspanV2 = {
    expr = roundtrip nftlib.types.readBackObject {
      tunnel = {
        family = "inet";
        table = "t";
        name = "e2";
        type = "erspan";
        tunnel = {
          version = 2;
          dir = "ingress";
          hwid = 3;
        };
      };
    };
    expected = "{\"tunnel\":{\"family\":\"inet\",\"name\":\"e2\",\"table\":\"t\",\"tunnel\":{\"dir\":\"ingress\",\"hwid\":3,\"version\":2},\"type\":\"erspan\"}}";
  };

  # ------------------------------------------------------------------
  # Tunnel object: GENEVE (list of options)
  # ------------------------------------------------------------------
  testTunnelGeneve = {
    expr = roundtrip nftlib.types.readBackObject {
      tunnel = {
        family = "inet";
        table = "t";
        name = "g";
        type = "geneve";
        tunnel = [
          {
            class = 258;
            "opt-type" = 128;
            data = "deadbeef";
          }
        ];
      };
    };
    expected = "{\"tunnel\":{\"family\":\"inet\",\"name\":\"g\",\"table\":\"t\",\"tunnel\":[{\"class\":258,\"data\":\"deadbeef\",\"opt-type\":128}],\"type\":\"geneve\"}}";
  };

  # ------------------------------------------------------------------
  # Audit-pass additions: fields confirmed in parser_json.c
  # ------------------------------------------------------------------

  # limit.per is required in inline form (parser_json.c:2084)
  testLimitPerRejectedWithoutPer = {
    expr = roundtrip nftlib.types.statement {
      limit = {
        rate = 100;
      };
    };
    expectedError.msg = "validate\\.limit\\.per.*was accessed but has no value defined";
  };

  # queue without num is valid
  testQueueNoNum = {
    expr = roundtrip nftlib.types.statement {
      queue = {
        flags = [ "bypass" ];
      };
    };
    expected = ''{"queue":{"flags":["bypass"]}}'';
  };

  # meter.size (parser_json.c:2793)
  testMeterSize = {
    expr = roundtrip nftlib.types.statement {
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
    expected = "{\"meter\":{\"key\":{\"meta\":{\"key\":\"iifname\"}},\"name\":\"m\",\"size\":4096,\"stmt\":{\"counter\":{\"bytes\":0,\"packets\":0}}}}";
  };

  # nat.type_flags (parser_json.c:2353)
  testNatTypeFlags = {
    expr = roundtrip nftlib.types.statement {
      dnat = {
        addr = "10.0.0.0/24";
        type_flags = [
          "interval"
          "prefix"
        ];
      };
    };
    expected = "{\"dnat\":{\"addr\":\"10.0.0.0/24\",\"type_flags\":[\"interval\",\"prefix\"]}}";
  };

  # ip option expression (parser_json.c:822)
  testIpOptionExpr = {
    expr = roundtrip nftlib.types.expression {
      "ip option" = {
        name = "lsrr";
        field = "length";
      };
    };
    expected = ''{"ip option":{"field":"length","name":"lsrr"}}'';
  };

  # tcp option raw form (parser_json.c:745)
  testTcpOptionRaw = {
    expr = roundtrip nftlib.types.expression {
      "tcp option" = {
        base = 2;
        offset = 16;
        len = 16;
      };
    };
    expected = ''{"tcp option":{"base":2,"len":16,"offset":16}}'';
  };

  # payload tunnel form (parser_json.c:686)
  testPayloadTunnelForm = {
    expr = roundtrip nftlib.types.expression {
      payload = {
        tunnel = "vxlan";
        protocol = "ip";
        field = "daddr";
      };
    };
    expected = "{\"payload\":{\"field\":\"daddr\",\"protocol\":\"ip\",\"tunnel\":\"vxlan\"}}";
  };

  # payload base "ih" (inner header)
  testPayloadInnerHeader = {
    expr = roundtrip nftlib.types.expression {
      payload = {
        base = "ih";
        offset = 0;
        len = 8;
      };
    };
    expected = ''{"payload":{"base":"ih","len":8,"offset":0}}'';
  };

  # Chain dev accepts string list (parser_json.c:3143 via json_parse_devs)
  testChainDevList = {
    expr = roundtrip nftlib.types.readBackObject {
      chain = {
        family = "netdev";
        table = "filter";
        name = "ingress";
        type = "filter";
        hook = "ingress";
        prio = -500;
        dev = [
          "eth0"
          "eth1"
        ];
      };
    };
    expected = "{\"chain\":{\"dev\":[\"eth0\",\"eth1\"],\"family\":\"netdev\",\"hook\":\"ingress\",\"name\":\"ingress\",\"prio\":-500,\"table\":\"filter\",\"type\":\"filter\"}}";
  };

  # secmark object: context is optional (parser_json.c:3769)
  testSecmarkObjectNoContext = {
    expr = roundtrip nftlib.types.readBackObject {
      secmark = {
        family = "inet";
        table = "t";
        name = "x";
      };
    };
    expected = ''{"secmark":{"family":"inet","name":"x","table":"t"}}'';
  };

  # ct helper object: protocol/type optional (parser_json.c:3782-3809)
  testCtHelperObjectMinimal = {
    expr = roundtrip nftlib.types.readBackObject {
      "ct helper" = {
        family = "inet";
        table = "t";
        name = "h";
      };
    };
    expected = ''{"ct helper":{"family":"inet","name":"h","table":"t"}}'';
  };

  # ------------------------------------------------------------------
  # Mixing VXLAN keys into an ERSPAN tunnel nested object must be rejected
  # ------------------------------------------------------------------
  testTunnelNestedDisjoint = {
    expr = roundtrip nftlib.types.readBackObject {
      tunnel = {
        family = "inet";
        table = "t";
        name = "bad";
        type = "vxlan";
        tunnel = {
          version = 1;
          gbp = 10;
        };
      };
    };
    expectedError.msg = "validate\\.tunnel\\.tunnel\\.gbp.*does not exist";
  };

  # ------------------------------------------------------------------
  # Socket keys: mark and wildcard (added in audit pass)
  # ------------------------------------------------------------------
  testSocketMark = {
    expr = roundtrip nftlib.types.expression {
      socket = {
        key = "mark";
      };
    };
    expected = ''{"socket":{"key":"mark"}}'';
  };

  testSocketWildcard = {
    expr = roundtrip nftlib.types.expression {
      socket = {
        key = "wildcard";
      };
    };
    expected = ''{"socket":{"key":"wildcard"}}'';
  };

  # ------------------------------------------------------------------
  # Meta keys added from meta_templates audit
  # ------------------------------------------------------------------
  testMetaIpsecKey = {
    expr = roundtrip nftlib.types.expression {
      meta = {
        key = "ipsec";
      };
    };
    expected = ''{"meta":{"key":"ipsec"}}'';
  };

  testMetaTimeKey = {
    expr = roundtrip nftlib.types.expression {
      meta = {
        key = "time";
      };
    };
    expected = ''{"meta":{"key":"time"}}'';
  };

  testMetaSdifKey = {
    expr = roundtrip nftlib.types.expression {
      meta = {
        key = "sdif";
      };
    };
    expected = ''{"meta":{"key":"sdif"}}'';
  };

  # ------------------------------------------------------------------
  # ct timeout object: nested `policy` mapping state → seconds
  # ------------------------------------------------------------------
  testCtTimeoutObject = {
    expr = roundtrip nftlib.types.readBackObject {
      "ct timeout" = {
        family = "ip";
        table = "filter";
        name = "fast_tcp";
        protocol = "tcp";
        l3proto = "ip";
        policy = {
          established = 300;
          syn_sent = 30;
          close = 5;
        };
      };
    };
    expected = "{\"ct timeout\":{\"family\":\"ip\",\"l3proto\":\"ip\",\"name\":\"fast_tcp\",\"policy\":{\"close\":5,\"established\":300,\"syn_sent\":30},\"protocol\":\"tcp\",\"table\":\"filter\"}}";
  };

  # ------------------------------------------------------------------
  # set statement: delete op plus stmt attachment
  # ------------------------------------------------------------------
  testSetStmtDeleteWithStmt = {
    expr = roundtrip nftlib.types.statement {
      set = {
        op = "delete";
        elem = "10.0.0.1";
        set = "@blocked";
        stmt = [
          {
            counter = {
              packets = 0;
              bytes = 0;
            };
          }
        ];
      };
    };
    expected = "{\"set\":{\"elem\":\"10.0.0.1\",\"op\":\"delete\",\"set\":\"@blocked\",\"stmt\":[{\"counter\":{\"bytes\":0,\"packets\":0}}]}}";
  };

  # ------------------------------------------------------------------
  # map statement (distinct from vmap)
  # ------------------------------------------------------------------
  testMapStatement = {
    expr = roundtrip nftlib.types.statement {
      map = {
        op = "update";
        elem = "10.0.0.1";
        data = 42;
        map = "@cache";
      };
    };
    expected = "{\"map\":{\"data\":42,\"elem\":\"10.0.0.1\",\"map\":\"@cache\",\"op\":\"update\"}}";
  };

  # nft's JSON parser rejects a set, map or flow statement reference
  # without its `@` ("Illegal set reference").
  testStatementReferencesNeedAt = {
    expr = map (helpers.validates nftlib.types.statement) [
      {
        set = {
          op = "add";
          elem = "10.0.0.1";
          set = "blocked";
        };
      }
      {
        map = {
          op = "update";
          elem = "10.0.0.1";
          data = 42;
          map = "cache";
        };
      }
      {
        flow = {
          op = "add";
          flowtable = "ft";
        };
      }
      {
        set = {
          op = "add";
          elem = "10.0.0.1";
          set = "@";
        };
      }
    ];
    expected = [
      false
      false
      false
      false
    ];
  };

  # ------------------------------------------------------------------
  # table with comment
  # ------------------------------------------------------------------
  testTableComment = {
    expr = roundtrip nftlib.types.readBackObject {
      table = {
        family = "inet";
        name = "filter";
        comment = "main firewall";
      };
    };
    expected = "{\"table\":{\"comment\":\"main firewall\",\"family\":\"inet\",\"name\":\"filter\"}}";
  };

  # ------------------------------------------------------------------
  # chain with comment
  # ------------------------------------------------------------------
  testChainComment = {
    expr = roundtrip nftlib.types.readBackObject {
      chain = {
        family = "inet";
        table = "filter";
        name = "input";
        comment = "accept established";
      };
    };
    expected = "{\"chain\":{\"comment\":\"accept established\",\"family\":\"inet\",\"name\":\"input\",\"table\":\"filter\"}}";
  };

  # ------------------------------------------------------------------
  # Comment on a named object (counter)
  # ------------------------------------------------------------------
  testObjectComment = {
    expr = roundtrip nftlib.types.readBackObject {
      counter = {
        family = "ip";
        table = "filter";
        name = "pkts";
        comment = "HTTP hits";
      };
    };
    expected = "{\"counter\":{\"comment\":\"HTTP hits\",\"family\":\"ip\",\"name\":\"pkts\",\"table\":\"filter\"}}";
  };

  # ------------------------------------------------------------------
  # `_type` tag stripping — libraries built on top of nftypes (e.g.
  # nix-nftzones, matching nix-libnet's convention) tag values with
  # `_type = "<lib>.<kind>"` for boundary checks. clean drops the tag
  # so rendered output stays accepted by `nft -j -f` (which rejects
  # unknown top-level keys).
  # ------------------------------------------------------------------
  testCleanStripsTypeRuleset = {
    expr = toJson {
      _type = "x.y";
      nftables = [ ];
    };
    expected = ''{"nftables":[]}'';
  };

  # Cleaning reaches every command: an unset field's `null` and a marker
  # never render.
  testCleanStripsTypeAndNullsInCommands = {
    expr = toJson {
      nftables = [
        {
          _type = "x.y";
          add.table = {
            _type = "x.z";
            family = "inet";
            name = "t";
            comment = null;
          };
        }
      ];
    };
    expected = "{\"nftables\":[{\"add\":{\"table\":{\"family\":\"inet\",\"name\":\"t\"}}}]}";
  };

  # A marker doesn't hide the null sentinel: a marked verdict stays a
  # verdict instead of becoming `{}`, in JSON and in text.
  testCleanKeepsMarkedVerdictInRule = {
    expr = toJson markedVerdictRuleset;
    expected = "{\"nftables\":[{\"add\":{\"rule\":{\"chain\":\"c\",\"expr\":[{\"drop\":null}],\"family\":\"inet\",\"table\":\"t\"}}}]}";
  };

  testCleanKeepsMarkedVerdictInText = {
    expr = nftlib.toText markedVerdictRuleset;
    expected = "add rule inet t c drop\n";
  };

  # ------------------------------------------------------------------
  # prioritiesByFamily — the symbols nft accepts at each hook of each
  # family, measured with `nft -c` on nftables 1.1.6 and 1.1.7 and read
  # from `std_prio_family_hook_compat` in `src/rule.c`.
  # integration-chain-placement checks it against the package set's nft.
  # ------------------------------------------------------------------
  testPrioritiesByFamilyMatchesNft =
    let
      inetAt = {
        prerouting = {
          raw = -300;
          mangle = -150;
          dstnat = -100;
          filter = 0;
          security = 50;
        };
        input = {
          raw = -300;
          mangle = -150;
          filter = 0;
          security = 50;
          srcnat = 100;
        };
        forward = {
          raw = -300;
          mangle = -150;
          filter = 0;
          security = 50;
        };
        output = {
          raw = -300;
          mangle = -150;
          dstnat = -100;
          filter = 0;
          security = 50;
        };
        postrouting = {
          raw = -300;
          mangle = -150;
          filter = 0;
          security = 50;
          srcnat = 100;
        };
      };
    in
    {
      expr = nftlib.compatibility.prioritiesByFamily;
      expected = {
        ip = inetAt;
        ip6 = inetAt;
        inet = inetAt // {
          ingress = {
            raw = -300;
            mangle = -150;
            filter = 0;
            security = 50;
          };
        };
        bridge = {
          prerouting = {
            dstnat = -300;
            filter = -200;
          };
          input.filter = -200;
          forward.filter = -200;
          output = {
            filter = -200;
            out = 100;
          };
          postrouting = {
            filter = -200;
            srcnat = 300;
          };
        };
        arp = {
          input.filter = 0;
          output.filter = 0;
        };
        netdev = {
          ingress.filter = 0;
          egress.filter = 0;
        };
      };
    };

  # ------------------------------------------------------------------
  # priorityValue — symbol → int at a family's hook
  # ------------------------------------------------------------------
  testPriorityValueIntPassthroughIp = {
    expr = nftlib.compatibility.priorityValue "ip" "input" 42;
    expected = 42;
  };

  testPriorityValueIntPassthroughBridge = {
    expr = nftlib.compatibility.priorityValue "bridge" "input" (-100);
    expected = -100;
  };

  # Every symbol at every hook resolves to its value in its table.
  testPriorityValueEverySymbol = {
    expr = lib.mapAttrs (
      family:
      lib.mapAttrs (hook: lib.mapAttrs (symbol: _: nftlib.compatibility.priorityValue family hook symbol))
    ) nftlib.compatibility.prioritiesByFamily;
    expected = nftlib.compatibility.prioritiesByFamily;
  };

  testPriorityValueBridgeFilter = {
    expr = nftlib.compatibility.priorityValue "bridge" "forward" "filter";
    expected = -200;
  };

  testPriorityValueNatHooks = {
    expr = map (placement: nftlib.compatibility.priorityValue "inet" placement.hook placement.symbol) [
      {
        hook = "prerouting";
        symbol = "dstnat";
      }
      {
        hook = "output";
        symbol = "dstnat";
      }
      {
        hook = "input";
        symbol = "srcnat";
      }
      {
        hook = "postrouting";
        symbol = "srcnat";
      }
    ];
    expected = [
      (-100)
      (-100)
      100
      100
    ];
  };

  # nft accepts only `filter` in arp and netdev.
  testPriorityValueNetdevMangleThrows = {
    expr = nftlib.compatibility.priorityValue "netdev" "ingress" "mangle";
    expectedError.msg = "nix-nftypes: compatibility.priorityValue: family 'netdev' has no priority 'mangle' at hook 'ingress'. Valid priorities: any int, filter.";
  };

  testPriorityValueArpRawThrows = {
    expr = nftlib.compatibility.priorityValue "arp" "input" "raw";
    expectedError.msg = "family 'arp' has no priority 'raw' at hook 'input'";
  };

  # nft accepts `dstnat` only at prerouting and output, and `srcnat`
  # only at input and postrouting.
  testPriorityValueDstnatAtInputThrows = {
    expr = nftlib.compatibility.priorityValue "ip" "input" "dstnat";
    expectedError.msg = "family 'ip' has no priority 'dstnat' at hook 'input'";
  };

  testPriorityValueDstnatAtForwardThrows = {
    expr = nftlib.compatibility.priorityValue "inet" "forward" "dstnat";
    expectedError.msg = "family 'inet' has no priority 'dstnat' at hook 'forward'";
  };

  testPriorityValueSrcnatAtPreroutingThrows = {
    expr = nftlib.compatibility.priorityValue "ip6" "prerouting" "srcnat";
    expectedError.msg = "family 'ip6' has no priority 'srcnat' at hook 'prerouting'";
  };

  testPriorityValueSrcnatAtIngressThrows = {
    expr = nftlib.compatibility.priorityValue "inet" "ingress" "srcnat";
    expectedError.msg = "family 'inet' has no priority 'srcnat' at hook 'ingress'";
  };

  # In bridge, `dstnat`, `out`, and `srcnat` are each accepted at one
  # hook.
  testPriorityValueBridgeDstnatAtInputThrows = {
    expr = nftlib.compatibility.priorityValue "bridge" "input" "dstnat";
    expectedError.msg = "family 'bridge' has no priority 'dstnat' at hook 'input'";
  };

  testPriorityValueBridgeOutAtPostroutingThrows = {
    expr = nftlib.compatibility.priorityValue "bridge" "postrouting" "out";
    expectedError.msg = "family 'bridge' has no priority 'out' at hook 'postrouting'";
  };

  testPriorityValueBridgeSrcnatAtForwardThrows = {
    expr = nftlib.compatibility.priorityValue "bridge" "forward" "srcnat";
    expectedError.msg = "family 'bridge' has no priority 'srcnat' at hook 'forward'";
  };

  # `raw`, `mangle`, and `security` are default-table symbols only.
  testPriorityValueBridgeRawThrows = {
    expr = nftlib.compatibility.priorityValue "bridge" "prerouting" "raw";
    expectedError.msg = "family 'bridge' has no priority 'raw' at hook 'prerouting'";
  };

  testPriorityValueUnknownSymbolThrows = {
    expr = nftlib.compatibility.priorityValue "ip" "input" "out";
    expectedError.msg = "family 'ip' has no priority 'out' at hook 'input'";
  };

  testPriorityValueNonStringThrows = {
    expr = nftlib.compatibility.priorityValue "ip" "input" [ "filter" ];
    expectedError.msg = "family 'ip' has no priority of type list at hook 'input'";
  };

  # Family and hook are checked for an int too.
  testPriorityValueUnknownFamilyThrows = {
    expr = nftlib.compatibility.priorityValue "wat" "input" 0;
    expectedError.msg = "nix-nftypes: compatibility.priorityValue: unknown family 'wat'. Valid families: ip, ip6, inet, arp, bridge, netdev.";
  };

  testPriorityValueHookFamilyLacksThrows = {
    expr = nftlib.compatibility.priorityValue "arp" "forward" 0;
    expectedError.msg = "nix-nftypes: compatibility.priorityValue: family 'arp' has no hook 'forward'. Valid hooks: input, output.";
  };

  # ------------------------------------------------------------------
  # priorityName — int → symbol, the reverse of priorityValue.
  # ------------------------------------------------------------------
  testPriorityNameIpZero = {
    expr = nftlib.compatibility.priorityName "ip" "input" 0;
    expected = "filter";
  };

  testPriorityNameSymbolPassthrough = {
    expr = nftlib.compatibility.priorityName "ip" "input" "filter";
    expected = "filter";
  };

  testPriorityNameIpSrcnat = {
    expr = nftlib.compatibility.priorityName "ip" "postrouting" 100;
    expected = "srcnat";
  };

  testPriorityNameIpUnknownInt = {
    expr = nftlib.compatibility.priorityName "ip" "input" 17;
    expected = 17;
  };

  # -100 is `dstnat` only where nft accepts `dstnat`; elsewhere nft lists
  # the int.
  testPriorityNameDstnatIntAtPrerouting = {
    expr = nftlib.compatibility.priorityName "ip" "prerouting" (-100);
    expected = "dstnat";
  };

  testPriorityNameDstnatIntAtInput = {
    expr = nftlib.compatibility.priorityName "ip" "input" (-100);
    expected = -100;
  };

  testPriorityNameNetdevMangleInt = {
    expr = nftlib.compatibility.priorityName "netdev" "ingress" (-150);
    expected = -150;
  };

  # Bridge-specific: -200 is bridge filter (not 0).
  testPriorityNameBridgeFilter = {
    expr = nftlib.compatibility.priorityName "bridge" "input" (-200);
    expected = "filter";
  };

  testPriorityNameBridgeSrcnat = {
    expr = nftlib.compatibility.priorityName "bridge" "postrouting" 300;
    expected = "srcnat";
  };

  testPriorityNameBridgeSrcnatIntAtInput = {
    expr = nftlib.compatibility.priorityName "bridge" "input" 300;
    expected = 300;
  };

  # 0 is `filter` for ip but unknown for bridge — no canonicalization.
  testPriorityNameBridgeZero = {
    expr = nftlib.compatibility.priorityName "bridge" "input" 0;
    expected = 0;
  };

  testPriorityNameRejectedSymbolThrows = {
    expr = nftlib.compatibility.priorityName "ip" "input" "dstnat";
    expectedError.msg = "nix-nftypes: compatibility.priorityName: family 'ip' has no priority 'dstnat' at hook 'input'";
  };

  testPriorityNameUnknownSymbolThrows = {
    expr = nftlib.compatibility.priorityName "bridge" "input" "bogus";
    expectedError.msg = "nix-nftypes: compatibility.priorityName: family 'bridge' has no priority 'bogus' at hook 'input'";
  };

  testPriorityNameUnknownFamilyThrows = {
    expr = nftlib.compatibility.priorityName "nope" "input" 0;
    expectedError.msg = "nix-nftypes: compatibility.priorityName: unknown family 'nope'";
  };

  testPriorityNameHookFamilyLacksThrows = {
    expr = nftlib.compatibility.priorityName "netdev" "input" 0;
    expectedError.msg = "nix-nftypes: compatibility.priorityName: family 'netdev' has no hook 'input'";
  };

  # ------------------------------------------------------------------
  # compatibility matrix spot-checks
  # ------------------------------------------------------------------
  testCompatHooksNetdev = {
    expr = nftlib.compatibility.hooksByFamily.netdev;
    expected = [
      "ingress"
      "egress"
    ];
  };

  testCompatHooksArp = {
    expr = nftlib.compatibility.hooksByFamily.arp;
    expected = [
      "input"
      "output"
    ];
  };

  # `inet` supports `ingress` (with devices = {…}) since kernel 5.10
  # — see `str2hooknum` in nftables `src/evaluate.c`.
  testCompatHooksInetIncludesIngress = {
    expr = builtins.elem "ingress" nftlib.compatibility.hooksByFamily.inet;
    expected = true;
  };

  testCompatNatExcludesBridge = {
    expr = builtins.elem "bridge" nftlib.compatibility.familiesByChainType.nat;
    expected = false;
  };

  testCompatNatExcludesNetdev = {
    expr = builtins.elem "netdev" nftlib.compatibility.familiesByChainType.nat;
    expected = false;
  };

  testCompatNatExcludesArp = {
    expr = builtins.elem "arp" nftlib.compatibility.familiesByChainType.nat;
    expected = false;
  };

  testCompatRouteFamilies = {
    expr = nftlib.compatibility.familiesByChainType.route;
    expected = [
      "ip"
      "ip6"
      "inet"
    ];
  };

  # Every family supports `filter`, in the order of `enums.family`.
  testCompatFamiliesByChainTypeFilterIsEveryFamily = {
    expr = nftlib.compatibility.familiesByChainType.filter;
    expected = [
      "ip"
      "ip6"
      "inet"
      "arp"
      "bridge"
      "netdev"
    ];
  };

  # The tables are keyed by, and list only, the families, chain types,
  # and hooks of `enums`, so they cannot drift from the schema.
  testCompatTablesStayWithinEnums =
    let
      inherit (nftlib) compatibility enums;
      sortedNames = attrs: lib.sort lib.lessThan (lib.attrNames attrs);
      sorted = lib.sort lib.lessThan;
      outside = enum: lists: lib.filter (value: !(lib.elem value enum)) (lib.concatLists lists);
    in
    {
      expr = {
        hooksByFamilyKeys = sortedNames compatibility.hooksByFamily;
        prioritiesByFamilyKeys = sortedNames compatibility.prioritiesByFamily;
        familiesByChainTypeKeys = sortedNames compatibility.familiesByChainType;
        hooksByChainTypeKeys = sortedNames compatibility.hooksByChainType;
        hooksOutsideEnum = outside enums.hook (
          lib.attrValues compatibility.hooksByFamily
          ++ lib.attrValues compatibility.hooksByChainType
          ++ map lib.attrNames (lib.attrValues compatibility.prioritiesByFamily)
        );
        familiesOutsideEnum = outside enums.family (lib.attrValues compatibility.familiesByChainType);
      };
      expected = {
        hooksByFamilyKeys = sorted enums.family;
        prioritiesByFamilyKeys = sorted enums.family;
        familiesByChainTypeKeys = sorted enums.chainType;
        hooksByChainTypeKeys = sorted enums.chainType;
        hooksOutsideEnum = [ ];
        familiesOutsideEnum = [ ];
      };
    };

  # ------------------------------------------------------------------
  # hooksByChainType — `filter` lists every hook in the schema's enum;
  # `nat` and `route` list fewer.
  # ------------------------------------------------------------------
  testCompatHooksByChainTypeFilterIsEveryHook = {
    expr = nftlib.compatibility.hooksByChainType.filter;
    expected = nftlib.enums.hook;
  };

  testCompatHooksByChainTypeNat = {
    expr = nftlib.compatibility.hooksByChainType.nat;
    expected = [
      "prerouting"
      "input"
      "output"
      "postrouting"
    ];
  };

  testCompatHooksByChainTypeRoute = {
    expr = nftlib.compatibility.hooksByChainType.route;
    expected = [ "output" ];
  };

  # ------------------------------------------------------------------
  # validChainPlacement — (family, chainType, hook) → bool. Cases
  # mirror the kernel-probed matrix on Linux 6.8 / nftables 1.0.9.
  # ------------------------------------------------------------------
  testValidChainPlacementIpFilterPrerouting = {
    expr = nftlib.compatibility.validChainPlacement "ip" "filter" "prerouting";
    expected = true;
  };

  testValidChainPlacementIpNatPrerouting = {
    expr = nftlib.compatibility.validChainPlacement "ip" "nat" "prerouting";
    expected = true;
  };

  testValidChainPlacementIpNatForward = {
    expr = nftlib.compatibility.validChainPlacement "ip" "nat" "forward";
    expected = false;
  };

  testValidChainPlacementIpRouteOutput = {
    expr = nftlib.compatibility.validChainPlacement "ip" "route" "output";
    expected = true;
  };

  testValidChainPlacementIpRoutePrerouting = {
    expr = nftlib.compatibility.validChainPlacement "ip" "route" "prerouting";
    expected = false;
  };

  # Verified on real kernel 6.8 / nftables 1.0.9: `inet route hook
  # output` is accepted (the kernel dispatches inet route via the
  # per-protocol implementations).
  testValidChainPlacementInetRouteOutput = {
    expr = nftlib.compatibility.validChainPlacement "inet" "route" "output";
    expected = true;
  };

  testValidChainPlacementNetdevFilterIngress = {
    expr = nftlib.compatibility.validChainPlacement "netdev" "filter" "ingress";
    expected = true;
  };

  testValidChainPlacementNetdevFilterEgress = {
    expr = nftlib.compatibility.validChainPlacement "netdev" "filter" "egress";
    expected = true;
  };

  testValidChainPlacementNetdevNatIngress = {
    expr = nftlib.compatibility.validChainPlacement "netdev" "nat" "ingress";
    expected = false;
  };

  testValidChainPlacementArpFilterInput = {
    expr = nftlib.compatibility.validChainPlacement "arp" "filter" "input";
    expected = true;
  };

  # A hook in the enum that the family lacks is an invalid placement.
  testValidChainPlacementArpFilterForward = {
    expr = nftlib.compatibility.validChainPlacement "arp" "filter" "forward";
    expected = false;
  };

  # A value outside its enum throws, so a typo doesn't read as an
  # invalid placement.
  testValidChainPlacementUnknownFamilyThrows = {
    expr = nftlib.compatibility.validChainPlacement "wat" "filter" "input";
    expectedError.msg = "nix-nftypes: compatibility.validChainPlacement: unknown family 'wat'. Valid families: ip, ip6, inet, arp, bridge, netdev.";
  };

  testValidChainPlacementUnknownChainTypeThrows = {
    expr = nftlib.compatibility.validChainPlacement "ip" "wat" "input";
    expectedError.msg = "nix-nftypes: compatibility.validChainPlacement: unknown chain type 'wat'. Valid chain types: filter, nat, route.";
  };

  testValidChainPlacementUnknownHookThrows = {
    expr = nftlib.compatibility.validChainPlacement "ip" "filter" "inptu";
    expectedError.msg = "nix-nftypes: compatibility.validChainPlacement: unknown hook 'inptu'. Valid hooks: prerouting, input, forward, output, postrouting, ingress, egress.";
  };

  # Read-back validation: the source-side checks validate each listed
  # command as a singleton ruleset. Bare listed objects with handles are
  # accepted; junk in read-back position is not.
  testRulesetAcceptsBareListing = {
    expr = builtins.isAttrs (readBack {
      table = {
        family = "inet";
        name = "t";
        handle = 1;
      };
    });
    expected = true;
  };

  testRulesetRejectsUnknownTopTag = {
    expr = readBack { gizmo = { }; };
    expectedError.msg = "validate\\.nftables\\..*is not of type";
  };

  testRulesetRejectsUnknownField = {
    expr = readBack {
      table = {
        family = "inet";
        name = "t";
        frobnicate = 1;
      };
    };
    expectedError.msg = "table\\.frobnicate.*does not exist";
  };

  testRulesetRejectsUnknownStatement = {
    expr = readBack {
      rule = {
        family = "inet";
        table = "t";
        chain = "c";
        handle = 2;
        expr = [ { not_a_stmt = { }; } ];
      };
    };
    expectedError.msg = "rule\\.expr\\..*is not of type";
  };

  # nft 1.1.6 lists an inet ct helper, timeout and expectation with
  # `l3proto: "inet"` (the table family, when none was given), and also
  # accepts it on input.
  testReadBackInetCtHelper = {
    expr = builtins.isAttrs (readBack {
      "ct helper" = {
        family = "inet";
        name = "h";
        table = "t";
        handle = 1;
        type = "ftp";
        protocol = "tcp";
        l3proto = "inet";
      };
    });
    expected = true;
  };

  testReadBackInetCtTimeout = {
    expr = builtins.isAttrs (readBack {
      "ct timeout" = {
        family = "inet";
        name = "to";
        table = "t";
        handle = 4;
        protocol = "tcp";
        l3proto = "inet";
        policy.established = 300;
      };
    });
    expected = true;
  };

  testReadBackInetCtExpectation = {
    expr = builtins.isAttrs (readBack {
      "ct expectation" = {
        family = "inet";
        name = "e";
        table = "t";
        handle = 1;
        protocol = "tcp";
        dport = 21;
        timeout = 1000;
        size = 1;
        l3proto = "inet";
      };
    });
    expected = true;
  };

  # inet is the only family added: nft's parser takes any family name,
  # but no listing emits the others.
  testCtL3protoRejectsBridge = {
    expr = readBack {
      "ct helper" = {
        family = "inet";
        name = "h";
        table = "t";
        l3proto = "bridge";
      };
    };
    expectedError.msg = "ct helper.\\.l3proto.*is not of type";
  };

  testReadBackCommentedSet = {
    expr = builtins.isAttrs (readBack {
      set = {
        family = "inet";
        name = "s";
        table = "t";
        type = "ipv4_addr";
        handle = 6;
        comment = "a set";
      };
    });
    expected = true;
  };

  testReadBackCommentedMap = {
    expr = builtins.isAttrs (readBack {
      map = {
        family = "inet";
        name = "m";
        table = "t";
        type = "ipv4_addr";
        handle = 7;
        comment = "a map";
        map = "verdict";
      };
    });
    expected = true;
  };

  # A set or map comment is a quoted string like every other comment.
  testSetCommentRejectsQuote = {
    expr = readBack {
      set = {
        family = "inet";
        name = "s";
        table = "t";
        type = "ipv4_addr";
        comment = "a \"set\"";
      };
    };
    expectedError.msg = "set\\.comment.*is not of type";
  };

  # A wrong value in an expression field is a type error naming the
  # field. The recursive `expression` type's description used to recurse
  # without end, so the error was "infinite recursion encountered".
  testWrongExpressionIsATypeError = {
    expr = builtins.deepSeq (helpers.validate nftlib.types.statement {
      match = {
        op = "==";
        left = 1.5;
        right = 1;
      };
    }) true;
    expectedError = {
      type = "ThrownError";
      msg = "validate\\.match\\.left' is not of type `nft expression";
    };
  };

  /*
    In one batch, nft (1.1.6 and 1.1.7, JSON and text) runs a reset of a
    counter, quota, set, map, or rule only when it is the batch's last
    command: followed by any other command, it resets nothing and nft
    exits 0. A reset of an element runs anywhere.
  */
  testResetOnlyAsLastCommand =
    let
      scope = {
        family = "ip";
        table = "t";
      };
      reset = kind: body: { reset.${kind} = scope // body; };
      counter = reset "counter" { name = "a"; };
      quota = reset "quota" {
        name = "q";
        bytes = 1;
      };
      set = reset "set" {
        name = "s";
        type = "ipv4_addr";
      };
      map = reset "map" {
        name = "m";
        type = "ipv4_addr";
        map = "mark";
      };
      rule = reset "rule" {
        chain = "c";
        handle = 2;
        expr = [ { accept = null; } ];
      };
      element = reset "element" {
        name = "s";
        elem = [ "10.0.0.1" ];
      };
      addTable.add.table = {
        family = "ip";
        name = "x";
      };
      accepts = commands: helpers.validates nftlib.types.ruleset { nftables = commands; };
    in
    {
      expr = {
        counterLast = accepts [
          addTable
          counter
        ];
        counterThenQuota = accepts [
          counter
          quota
        ];
        counterTwice = accepts [
          counter
          counter
        ];
        quotaThenTable = accepts [
          quota
          addTable
        ];
        setThenCounter = accepts [
          set
          counter
        ];
        mapThenElement = accepts [
          map
          element
        ];
        ruleThenTable = accepts [
          rule
          addTable
        ];
        elementThenTable = accepts [
          element
          addTable
        ];
        elementThenCounter = accepts [
          element
          counter
        ];
      };
      expected = {
        counterLast = true;
        counterThenQuota = false;
        counterTwice = false;
        quotaThenTable = false;
        setThenCounter = false;
        mapThenElement = false;
        ruleThenTable = false;
        elementThenTable = true;
        elementThenCounter = true;
      };
    };

  testResetNotLastNamesTheRule = {
    expr = builtins.deepSeq (helpers.validate nftlib.types.ruleset {
      nftables = [
        {
          reset.counter = {
            family = "ip";
            table = "t";
            name = "a";
          };
        }
        {
          add.table = {
            family = "ip";
            name = "x";
          };
        }
      ];
    }) true;
    expectedError.msg = "is not of type `nft ruleset whose reset of a counter, quota, set, map, or rule is its last command'";
  };
}
