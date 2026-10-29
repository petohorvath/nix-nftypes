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
  compatibility,
  deleteBodiesByTag,
  lib,
  objects,
  selectBodiesByTag,
  validate,
}:

let
  # DSL-key → JSON-key renames; distinct from the `rename` command below.
  keyRenames = import ../internal/rename.nix { inherit lib; };
  ruleBody = import ../internal/rule-body.nix { inherit lib; };
  compact = import ../internal/compact.nix { inherit lib; };
  rejectHandle = import ../internal/reject-handle.nix { inherit lib; };
  chainPriority = import ../internal/chain-priority.nix { inherit compatibility lib; };
  reference = import ../internal/reference.nix { inherit lib; };
  inherit (import ../internal/location.nix { inherit lib; }) builder fail;
  inherit (import ../../word-list.nix { inherit lib; }) conjoin;

  # Shared object-kind registry (singular DSL keys → `{ tag; renameBody;
  # body; plural; }`). Drop the `plural` field — irrelevant here — and
  # add the four command-only kinds (table/chain/rule/element) that aren't
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
    # Adds elements to a set or map, which may be defined elsewhere. Its
    # `name` selects the set, so it takes the bare name
    # (../internal/reference.nix), and its Selector takes `elements` too.
    element = {
      tag = "element";
      renameBody = keyRenames.element;
      selectorRenameBody = keyRenames.element;
      body = objects.elementBody;
      takesBareName = true;
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
    delete, destroy, list, flush, and reset take a Selector (ADR 0009): the
    fields nft's JSON parser reads to pick one object, and no other, as
    `lib/schema/objects.nix` records per kind. A table, chain, set, map,
    meter, flowtable, or stateful object is selected by family, table, and
    name, a rule by its chain and positive handle, and elements by their
    set and values. `delete` selects a table, chain, set, map, flowtable,
    or stateful object by its name or its handle, but a ct helper by its
    name only (`deleteBodiesByTag`). `selecting kinds` gives each of the
    kinds in `kinds` the schema's Selector for its tag
    (`selectBodiesByTag`), so the DSL and `validate` take the same fields.
  */
  selecting = selectingWith { };
  # `selecting`, with the Selectors of `bodiesByTag` in place of those
  # kinds'. A Selector's `name` selects an object, so it takes the bare
  # name; only an element's Selector has a field the DSL spells
  # differently.
  selectingWith =
    bodiesByTag:
    lib.mapAttrs (
      _: cfg:
      cfg
      // {
        body = bodiesByTag.${cfg.tag} or selectBodiesByTag.${cfg.tag};
        renameBody = cfg.selectorRenameBody or keyRenames.none;
        selector = true;
        takesBareName = true;
      }
    );

  # "`a`", "`a` and `b`", or "`a`, `b`, and `c`".
  codeList = names: conjoin "and" (map (name: "`${name}`") names);

  # A Selector's fields in the order a message lists them, by their DSL
  # names.
  selectorFieldOrder = [
    "family"
    "table"
    "chain"
    "name"
    "handle"
    "elements"
  ];

  /*
    Throw when the DSL `userBody` of the Selector `body` of `kind`, whose
    tag is `tag`, for `verb`, gives a field the Selector doesn't take: one
    nft ignores for the verb, or a handle where a name selects the object.
    `location` is the builder's location. A set or map given elements
    points to the verb's element builder, where there is one: `delete set`
    with elements deletes the whole set. A destroy given a handle points
    to delete, which selects by one. A Selector that takes both `name` and
    `handle` throws unless given exactly one: nft ignores a handle beside a
    name. Returns `userBody` otherwise, and a value that isn't an attrset,
    for the schema to reject.
  */
  checkSelector =
    {
      location,
      verb,
      kind,
      tag,
      body,
      userBody,
    }:
    let
      fields = map (keyRenames.dslKey "element") (
        builtins.attrNames (removeAttrs (body.getSubOptions [ ]) [ "_module" ])
      );
      ordered =
        builtins.filter (field: builtins.elem field fields) selectorFieldOrder
        ++ lib.subtractLists selectorFieldOrder fields;
      # A Selector with both takes `name` or `handle`.
      eitherNameOrHandle = builtins.elem "name" fields && builtins.elem "handle" fields;
      listed = map (
        field: if eitherNameOrHandle && field == "name" then "`name` or `handle`" else "`${field}`"
      ) (if eitherNameOrHandle then lib.remove "handle" ordered else ordered);
      extra = lib.subtractLists fields (builtins.attrNames userBody);
      elementHint = lib.optionalString (
        builtins.elem kind [
          "set"
          "map"
        ]
        && builtins.elem "elements" extra
        && builtins.elem verb [
          "delete"
          "destroy"
          "reset"
        ]
      ) " To ${verb} elements, use dsl.${verb}.element.";
      handleHint = lib.optionalString (
        verb == "destroy" && deleteBodiesByTag ? ${tag} && builtins.elem "handle" extra
      ) " nft destroys by name only; dsl.delete.${kind} selects by handle.";
      given = field: (userBody.${field} or null) != null;
    in
    if !builtins.isAttrs userBody then
      userBody
    else if extra != [ ] then
      fail location "takes a Selector, with only ${conjoin "and" listed}; got ${codeList extra}.${elementHint}${handleHint}"
    else if eitherNameOrHandle && given "name" == given "handle" then
      fail location "selects by `name` or by `handle`; got ${
        if given "name" then "both, and nft ignores a handle beside a name" else "neither"
      }."
    else
      userBody;

  /*
    nft mishandles delete and destroy of a ct timeout or ct expectation
    (Known differences, ADR 0010): its JSON parser passes the kernel object
    number as the command object type, so deleting a ct expectation deletes
    its whole table. nft 1.1.7 aborts on delete and destroy of a ct count,
    which 1.1.6 has no object for. The schema rejects all six commands.
    `delete` takes the same kinds, and selects some by handle
    (`deleteBodiesByTag`).
  */
  destroyObjectKinds = removeAttrs addObjectKinds [
    "ctCount"
    "ctExpectation"
    "ctTimeout"
  ];
  deleteObjectKinds = selectingWith deleteBodiesByTag destroyObjectKinds;

  /*
    nft's JSON `list` command has no singular rule, element, flowtable,
    synproxy, metainfo, or ct count selector ("Unknown object passed to list
    command"), lists the whole table for a ct expectation, and aborts on a
    ct timeout. `meter` lists the dynamic set a `meter` statement creates.
  */
  listObjectKinds =
    selecting (
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
        meter.tag = "meter";
      }
    )
    // {
      ruleset = rulesetKind objects.listRulesetBody;
    };

  /*
    `create rule` is explicitly rejected by the nftables parser with
    "Create command not available for rules" — use `add.rule` instead (the
    table-tree `rules = [ … ]` path also produces `add rule`). Omitting
    `rule` from the `create` namespace turns the schema's
    over-permissiveness into a DSL-level error.
  */
  createObjectKinds = removeAttrs addObjectKinds [ "rule" ];

  # A chain that `add` or `create` declares takes a Symbolic priority, which
  # resolves for its family and hook (../internal/chain-priority.nix). The
  # other verbs select a chain and take its body as given.
  declaredChain = addObjectKinds.chain // {
    renameBody = location: body: chainPriority location (body.family or null) body;
  };

  /*
    The ruleset kind of `flush` and `list`, whose `body` is either
    `{ family; }` or the JSON `null` meaning every family. An empty attrset
    stands for `null`, so every flush and list kind takes an attrset:
    `flush.ruleset { }` flushes everything.
  */
  rulesetKind = body: {
    tag = "ruleset";
    renameBody = _location: value: if value == { } then null else value;
    inherit body;
  };

  /*
    `flush` accepts table, chain, set, map, meter, and ruleset
    (parser_json.c:4297-4304). `flush flowtable` is absent because the
    nftables parser rejects it ("Unknown object passed to flush command").
  */
  flushObjectKinds = {
    inherit (listObjectKinds)
      table
      chain
      set
      map
      meter
      ;
    ruleset = rulesetKind objects.flushRulesetBody;
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

  # `kinds`, whose bodies take no handle (../internal/reject-handle.nix),
  # as in `add`, `create`, and `rename`: each throws for one before its
  # renames.
  withoutHandle = lib.mapAttrs (
    _: cfg:
    cfg
    // {
      renameBody = location: body: cfg.renameBody location (rejectHandle location body);
    }
  );

  /*
    Build one command namespace. `command` is the command tag (`"create"`,
    `"delete"`, …) and `kinds` the registry of object kinds it accepts.

    Returns `{ <dslKey> = body: { <command> = { <jsonTag> = validated; }; };
    … }`. Each builder takes the object body with DSL spellings, renames it,
    and validates it against the kind's schema body; errors name the
    builder (`dsl.create.chain.prio`). Like a table tree's bodies, the
    command holds only the fields given, without a `null` for an unset or
    null field.
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
        # A JSON spelling throws first, pointing to the DSL name.
        checked = cfg.renameBody location userBody;
        selected =
          if cfg.selector or false then
            builtins.seq checked (
              builtins.seq (checkSelector {
                inherit location kind userBody;
                inherit (cfg) body tag;
                verb = command;
              }) checked
            )
          else
            checked;
        # A Selector's `name` and `add.element`'s select an object, so
        # they take the bare name (../internal/reference.nix).
        renamed =
          if (cfg.takesBareName or false) && builtins.isAttrs selected then
            reference.normaliseBareName location selected
          else
            selected;
        validated = validate {
          type = cfg.body;
          # A ruleset body can rename to the JSON null.
          value = if builtins.isAttrs renamed then compact renamed else renamed;
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
  add = mkNamespace "add" (
    withoutHandle (
      addObjectKinds
      // {
        chain = declaredChain;
        rule = ruleCommandKind objects.addRuleBody;
      }
    )
  );
  create = mkNamespace "create" (withoutHandle (createObjectKinds // { chain = declaredChain; }));
  delete = mkNamespace "delete" deleteObjectKinds;
  destroy = mkNamespace "destroy" (selecting destroyObjectKinds);
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
  rename = mkNamespace "rename" (withoutHandle {
    chain = {
      tag = "chain";
      renameBody = keyRenames.renameChain;
      body = objects.renameChainBody;
    };
  });
}
