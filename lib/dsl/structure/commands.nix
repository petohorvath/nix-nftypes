{
  lib,
  validate,
  objects,
}:

# Namespaced builders for commands that don't fit the declarative table
# tree: create, delete, destroy, list, rename, reset. Each command's schema
# accepts a specific subset of object kinds (see `lib/schema/commands.nix` and
# `lib/schema/objects.nix`), so one namespace per command enumerates exactly the
# kinds the schema allows.
#
# Usage:
#   dsl.create.counter { family; table; name; }
#   dsl.delete.chain { family; table; name; }
#   dsl.destroy.set { family; table; name; type; }
#   dsl.list.table { family; name; }
#   dsl.rename.chain { family; table; name; newname; }
#   dsl.reset.counter { family; table; name; }      # command (sub-attr)
#   dsl.reset tcpOption                              # statement (via __functor, wired in default.nix)
#
# `replace` and `insert` accept only rule bodies per the schema, so they're
# plain single-argument functions rather than namespaces.
#
# DSL idiomatic renames (elements → elem, srcIpv4 → src-ipv4, …) are
# applied per kind so users never have to write hyphenated keys even in
# command-builder positions.
#
# Every constructor runs the renamed body through the matching schema
# submodule before wrapping it in a command tag, so a type-mismatched
# field throws at eval time naming the verb, kind, and field
# (e.g. `create.chain.prio: not of type 'null or signed integer'`).

let
  rename = import ../internal/rename.nix { inherit lib; };

  # Per-object-kind configuration:
  #   tag         — the singular JSON command tag (`chain`, `ct helper`, …)
  #   renameBody  — DSL-key → JSON-key rename applied before validation
  #   body        — schema submodule the renamed body is validated against
  # Mirrors `structure/render.nix`'s `objectKinds`; here singular DSL names
  # match the command-builder surface (vs the table tree's plural keys).
  addObjectKinds = {
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
    set = {
      tag = "set";
      renameBody = rename.set;
      body = objects.setObjectBody;
    };
    map = {
      tag = "map";
      renameBody = rename.set;
      body = objects.mapObjectBody;
    };
    element = {
      tag = "element";
      renameBody = rename.element;
      body = objects.elementBody;
    };
    flowtable = {
      tag = "flowtable";
      renameBody = lib.id;
      body = objects.flowtableBody;
    };
    counter = {
      tag = "counter";
      renameBody = lib.id;
      body = objects.counterObjectBody;
    };
    quota = {
      tag = "quota";
      renameBody = lib.id;
      body = objects.quotaObjectBody;
    };
    ctHelper = {
      tag = "ct helper";
      renameBody = lib.id;
      body = objects.ctHelperObjectBody;
    };
    limit = {
      tag = "limit";
      renameBody = lib.id;
      body = objects.limitObjectBody;
    };
    ctTimeout = {
      tag = "ct timeout";
      renameBody = lib.id;
      body = objects.ctTimeoutObjectBody;
    };
    ctExpectation = {
      tag = "ct expectation";
      renameBody = lib.id;
      body = objects.ctExpectationObjectBody;
    };
    secmark = {
      tag = "secmark";
      renameBody = lib.id;
      body = objects.secmarkObjectBody;
    };
    synproxy = {
      tag = "synproxy";
      renameBody = lib.id;
      body = objects.synproxyObjectBody;
    };
    tunnel = {
      tag = "tunnel";
      renameBody = rename.tunnel;
      body = objects.tunnelObjectBody;
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

  # Build a namespace `{ dslKey = body: { cmdTag = { jsonTag = validated; }; }; … }`.
  # `validated` is the renamed user body run through evalModules against the
  # kind's schema body; the prefix names the verb and kind so error messages
  # read like `create.chain.prio: …`.
  mkNamespace =
    cmdTag: kinds:
    lib.mapAttrs (
      _: cfg: userBody:
      let
        renamed = cfg.renameBody userBody;
        validated = validate {
          type = cfg.body;
          value = renamed;
          prefix = [
            cmdTag
            cfg.tag
          ];
        };
      in
      {
        ${cmdTag} = {
          ${cfg.tag} = validated;
        };
      }
    ) kinds;
in
{
  create = mkNamespace "create" createObjectKinds;
  delete = mkNamespace "delete" addObjectKinds;
  destroy = mkNamespace "destroy" addObjectKinds;
  list = mkNamespace "list" listObjectKinds;

  # Reset-as-command — merged with the reset-as-statement form (in
  # default.nix) via __functor, so the same `dsl.reset` works in both
  # positions.
  resetCommand = mkNamespace "reset" resetObjectKinds;

  # Rename is chain-only per the schema. The nftables JSON parser expects
  # `{ rename: { chain: <chainBody> } }` — tagged, not direct. Namespaced
  # so the API mirrors create/delete/… and tab completion surfaces the
  # single valid object kind.
  rename = {
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

  # replace / insert accept only rule bodies per the schema, and the
  # nftables JSON parser expects `{ replace: { rule: <ruleBody> } }`
  # (tagged). Implemented as plain body-taking functions since the object
  # kind is fixed.
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
