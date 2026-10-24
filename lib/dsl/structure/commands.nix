/*
  Namespaced builders for commands that don't fit the declarative table
  tree: add, create, delete, destroy, flush, insert, list, rename, replace,
  reset. One namespace per command enumerates the object kinds nft runs as
  written for it (ADR 0009). That is the kinds its schema union accepts (see
  `lib/schema/commands.nix` and `lib/schema/objects.nix`), minus the ones
  nft's JSON parser rejects for the verb.

  Usage:
    dsl.add.rule { family; table; chain; statements; }
    dsl.create.counter { family; table; name; }
    dsl.delete.chain { family; table; name; }
    dsl.destroy.set { family; table; name; }
    dsl.flush.table { family; name; }
    dsl.flush.ruleset { }                         # every family
    dsl.insert.rule { family; table; chain; statements; }
    dsl.list.table { family; name; }
    dsl.rename.chain { family; table; name; newName; }
    dsl.replace.rule { family; table; chain; handle; statements; }
    dsl.reset.counter { family; table; name; }

  The reset statement is `dsl.resetStmt`, in ../actions/misc.nix.

  DSL idiomatic renames (elements → elem, gcInterval → gc-interval,
  statements → expr, …) are applied per kind so users never write a JSON
  key, even in command-builder positions; a JSON key throws, pointing to
  the DSL name.

  Every constructor runs the renamed body through the matching schema
  submodule before wrapping it in a command tag, so a type-mismatched
  field throws at eval time naming the verb, kind, and field
  (e.g. `dsl.create.chain.prio' is not of type `null or signed integer'`).
*/
{
  lib,
  objects,
  validate,
}:

let
  # DSL-key → JSON-key renames; distinct from the `rename` command below.
  keyRenames = import ../internal/rename.nix { inherit lib; };
  ruleBody = import ../internal/rule-body.nix { inherit lib; };
  inherit (import ../internal/location.nix { inherit lib; }) builder;

  # Shared object-kind registry (singular DSL keys → `{ tag; renameBody;
  # body; plural; }`). Drop the `plural` field — irrelevant here — and
  # add the three command-only kinds (table/chain/rule) that aren't
  # table-tree containers.
  objectKindRegistry = import ./object-kinds.nix { inherit lib objects; };
  sharedKinds = lib.mapAttrs (_: cfg: removeAttrs cfg [ "plural" ]) objectKindRegistry;
  addObjectKinds = sharedKinds // {
    table = {
      tag = "table";
      renameBody = keyRenames.none;
      body = objects.tableBody;
    };
    chain = {
      tag = "chain";
      renameBody = keyRenames.none;
      body = objects.chainBody;
    };
    # nft 1.1.6's JSON parser ignores a handle on `add rule`, so the body
    # has none.
    rule = {
      tag = "rule";
      renameBody = keyRenames.none;
      body = objects.addRuleBody;
    };
  };

  /*
    delete, destroy, list, flush, and reset select an object by family,
    table, and name (ADR 0009): nft ignores the datatypes, rate, hook, and
    mss that adding a set, map, limit, flowtable, or synproxy requires. A
    rule is selected by its chain and positive handle. `selecting kinds`
    gives each of these kinds in `kinds` its selection body.
  */
  selectBodies = {
    flowtable = objects.selectFlowtableBody;
    limit = objects.selectLimitBody;
    map = objects.selectMapBody;
    rule = objects.selectRuleBody;
    set = objects.selectSetBody;
    synproxy = objects.selectSynproxyBody;
  };
  selecting =
    kinds:
    kinds
    // lib.mapAttrs (kind: body: kinds.${kind} // { inherit body; }) (
      builtins.intersectAttrs kinds selectBodies
    );

  /*
    nft mishandles delete and destroy of a ct timeout or ct expectation
    (Known differences, ADR 0010): its JSON parser passes the kernel object
    number as the command object type, so deleting a ct expectation deletes
    its whole table. nft 1.1.7 aborts on delete and destroy of a ct count,
    which 1.1.6 has no object for. The schema rejects all six commands.
  */
  deleteObjectKinds = selecting (
    removeAttrs addObjectKinds [
      "ctCount"
      "ctExpectation"
      "ctTimeout"
    ]
  );

  /*
    nft's JSON `list` command has no singular rule, element, flowtable,
    synproxy, metainfo, or ct count selector ("Unknown object passed to list
    command"), lists the whole table for a ct expectation, and aborts on a
    ct timeout. `meter` lists the dynamic set a `meter` statement creates.
  */
  listObjectKinds = selecting (
    removeAttrs addObjectKinds [
      "ctCount"
      "ctExpectation"
      "ctTimeout"
      "element"
      "flowtable"
      "rule"
      "synproxy"
    ]
    // {
      meter = {
        tag = "meter";
        renameBody = keyRenames.none;
        body = objects.meterBody;
      };
    }
  );

  /*
    `create rule` is explicitly rejected by the nftables parser with
    "Create command not available for rules" — use `add.rule` instead (the
    table-tree `rules = [ … ]` path also produces `add rule`). Omitting
    `rule` from the `create` namespace turns the schema's
    over-permissiveness into a DSL-level error.
  */
  createObjectKinds = removeAttrs addObjectKinds [ "rule" ];

  /*
    `flush` accepts table, chain, set, map, meter, and ruleset
    (parser_json.c:4297-4304). `flush flowtable` is absent because the
    nftables parser rejects it ("Unknown object passed to flush command").

    The ruleset body is either `{ family; }` or the JSON `null` meaning
    every family. An empty attrset stands for `null`, so every flush kind
    takes an attrset: `flush.ruleset { }` flushes everything.
  */
  flushObjectKinds = {
    inherit (listObjectKinds)
      table
      chain
      set
      map
      meter
      ;
    ruleset = {
      tag = "ruleset";
      renameBody = _location: body: if body == { } then null else body;
      body = objects.flushRulesetBody;
    };
  };

  # nft's JSON path fails `reset rule` with "Operation not supported",
  # though text resets the rule.
  resetObjectKinds = selecting {
    inherit (addObjectKinds)
      counter
      quota
      set
      map
      element
      ;
  };

  /*
    The rule kind of a command that adds statements: `add`, `insert`, or
    `replace`. `body` is the verb's rule body. Its body needs statements,
    in `statements`, like a table tree's rule entry
    (../internal/rule-body.nix).
  */
  ruleCommandKind = body: {
    tag = "rule";
    renameBody = ruleBody.ruleBody;
    inherit body;
  };

  /*
    Build one command namespace. `command` is the command tag (`"create"`,
    `"delete"`, …) and `kinds` the registry of object kinds it accepts.

    Returns `{ <dslKey> = body: { <command> = { <jsonTag> = validated; }; };
    … }`. Each builder takes the object body with DSL spellings, renames it,
    and validates it against the kind's schema body; errors name the
    builder (`dsl.create.chain.prio`).
  */
  mkNamespace =
    command: kinds:
    lib.mapAttrs (
      kind: cfg: userBody:
      let
        location = builder [
          command
          kind
        ];
        validated = validate {
          type = cfg.body;
          value = cfg.renameBody location userBody;
          inherit location;
        };
      in
      {
        ${command} = {
          ${cfg.tag} = validated;
        };
      }
    ) kinds;
in
{
  /*
    Per-kind command builders; each `<command>.<kind>` takes an object body
    and returns the validated command (see `mkNamespace`). Each namespace
    offers only the kinds nft runs as written (ADR 0009): `add` accepts
    every add-object kind, `create` omits `rule`, `delete` and `destroy`
    omit the ct count, timeout, and expectation, `list` takes the listable
    kinds plus `meter`, `reset` the resettable kinds but `rule`, and
    `flush` the flushable kinds plus `ruleset`.
  */
  add = mkNamespace "add" (addObjectKinds // { rule = ruleCommandKind objects.addRuleBody; });
  create = mkNamespace "create" createObjectKinds;
  delete = mkNamespace "delete" deleteObjectKinds;
  destroy = mkNamespace "destroy" deleteObjectKinds;
  flush = mkNamespace "flush" flushObjectKinds;
  list = mkNamespace "list" listObjectKinds;
  reset = mkNamespace "reset" resetObjectKinds;

  # A verb with one object kind is a namespace like the others, named for
  # the kind nft names: `insert rule`, `replace rule`, `rename chain`.
  # `insert` and `replace` take a rule body like `add.rule`; `replace`
  # also requires the `handle` of the rule it replaces, and `rename` the
  # chain's `newName`.
  insert = mkNamespace "insert" { rule = ruleCommandKind objects.insertRuleBody; };
  replace = mkNamespace "replace" { rule = ruleCommandKind objects.replaceRuleBody; };
  rename = mkNamespace "rename" {
    chain = {
      tag = "chain";
      renameBody = keyRenames.renameChain;
      body = objects.renameChainBody;
    };
  };
}
