/*
  Namespaced builders for commands that don't fit the declarative table
  tree: create, delete, destroy, list, rename, reset. Each command's schema
  accepts a specific subset of object kinds (see `lib/schema/commands.nix` and
  `lib/schema/objects.nix`), so one namespace per command enumerates exactly the
  kinds the schema allows.

  Usage:
    dsl.create.counter { family; table; name; }
    dsl.delete.chain { family; table; name; }
    dsl.destroy.set { family; table; name; type; }
    dsl.list.table { family; name; }
    dsl.rename.chain { family; table; name; newname; }
    dsl.reset.counter { family; table; name; }   # command (sub-attr)
    dsl.reset tcpOption                           # statement (__functor)

  The statement form of `reset` is wired in default.nix.

  `replace` and `insert` accept only rule bodies per the schema, so they're
  plain single-argument functions rather than namespaces.

  DSL idiomatic renames (elements → elem, srcIpv4 → src-ipv4, …) are
  applied per kind so users never have to write hyphenated keys even in
  command-builder positions.

  Every constructor runs the renamed body through the matching schema
  submodule before wrapping it in a command tag, so a type-mismatched
  field throws at eval time naming the verb, kind, and field
  (e.g. `create.chain.prio: not of type 'null or signed integer'`).
*/
{
  lib,
  objects,
  validate,
}:

let
  # Shared object-kind registry (singular DSL keys → `{ tag; renameBody;
  # body; plural; }`). Drop the `plural` field — irrelevant here — and
  # add the three command-only kinds (table/chain/rule) that aren't
  # table-tree containers.
  objectKindRegistry = import ./object-kinds.nix { inherit lib objects; };
  sharedKinds = lib.mapAttrs (_: cfg: removeAttrs cfg [ "plural" ]) objectKindRegistry;
  addObjectKinds = sharedKinds // {
    table = {
      tag = "table";
      renameBody = lib.id;
      body = objects.tableBody;
    };
    chain = {
      tag = "chain";
      renameBody = lib.id;
      body = objects.chainBody;
    };
    rule = {
      tag = "rule";
      renameBody = lib.id;
      body = objects.ruleBody;
    };
  };

  # `meter` listing (parser_json.c:4191) is supported even though there's no
  # `add meter` command — meters are anonymous sets created via the `meter`
  # *statement*. Listed via `dsl.list.meter { family; table; name; }`.
  listObjectKinds = addObjectKinds // {
    metainfo = {
      tag = "metainfo";
      renameBody = lib.id;
      body = objects.metainfoBody;
    };
    meter = {
      tag = "meter";
      renameBody = lib.id;
      body = objects.meterObjectBody;
    };
  };

  # `create rule` is explicitly rejected by the nftables parser with
  # "Create command not available for rules" — use `add.rule` / `dsl.rule`
  # instead (the existing table-tree `rules = [ … ]` path also produces
  # `add rule`). Omitting `rule` from the `create` namespace turns the
  # schema's over-permissiveness into a DSL-level error.
  createObjectKinds = removeAttrs addObjectKinds [ "rule" ];

  resetObjectKinds = {
    inherit (addObjectKinds)
      counter
      quota
      rule
      set
      map
      element
      ;
  };

  /*
    Build one command namespace. `command` is the command tag (`"create"`,
    `"delete"`, …) and `kinds` the registry of object kinds it accepts.

    Returns `{ <dslKey> = body: { <command> = { <jsonTag> = validated; }; };
    … }`. Each builder takes the object body with DSL spellings, renames it,
    and validates it against the kind's schema body; errors name the command
    and kind (`create.chain.prio: …`).
  */
  mkNamespace =
    command: kinds:
    lib.mapAttrs (
      _: cfg: userBody:
      let
        renamed = cfg.renameBody userBody;
        validated = validate {
          type = cfg.body;
          value = renamed;
          prefix = [
            command
            cfg.tag
          ];
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
  # Per-kind command builders; each `<command>.<kind>` takes an object body
  # and returns the validated command (see `mkNamespace`). `create` omits
  # `rule`, `list` adds `metainfo` and `meter`, and `delete` / `destroy`
  # accept every add-object kind.
  create = mkNamespace "create" createObjectKinds;
  delete = mkNamespace "delete" addObjectKinds;
  destroy = mkNamespace "destroy" addObjectKinds;
  list = mkNamespace "list" listObjectKinds;

  # Reset-as-command — merged with the reset-as-statement form (in
  # default.nix) via __functor, so the same `dsl.reset` works in both
  # positions.
  resetCommand = mkNamespace "reset" resetObjectKinds;

  # Rename is chain-only per the schema. Namespaced so the API mirrors
  # create/delete/… and tab completion surfaces the single valid object kind.
  rename = {
    /*
      Rename a chain. `body` is the chain body, carrying `newname`. Returns
      the tagged `{ rename = { chain = validated; }; }` command that the
      nftables JSON parser expects; throws when `body` fails the schema.
    */
    chain = body: {
      rename = {
        chain = validate {
          type = objects.chainBody;
          value = body;
          prefix = [
            "rename"
            "chain"
          ];
        };
      };
    };
  };

  /*
    Replace an existing rule; the schema accepts only rule bodies, so the
    object kind is fixed. `body` is the rule body, including its `handle`.
    Returns the tagged `{ replace = { rule = validated; }; }` command;
    throws when `body` fails the schema.
  */
  replace = body: {
    replace = {
      rule = validate {
        type = objects.ruleBody;
        value = body;
        prefix = [
          "replace"
          "rule"
        ];
      };
    };
  };

  /*
    Insert a rule before existing rules; the schema accepts only rule
    bodies, so the object kind is fixed. `body` is the rule body. Returns
    the tagged `{ insert = { rule = validated; }; }` command; throws when
    `body` fails the schema.
  */
  insert = body: {
    insert = {
      rule = validate {
        type = objects.ruleBody;
        value = body;
        prefix = [
          "insert"
          "rule"
        ];
      };
    };
  };
}
