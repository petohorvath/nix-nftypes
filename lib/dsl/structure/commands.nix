{ lib }:

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

let
  rename = import ../internal/rename.nix { inherit lib; };

  # Per-object-kind configuration: the JSON tag emitted and the body rename
  # applied before emission. Mirrors `structure/render.nix`'s `objectKinds`
  # (which uses plural keys for the table tree); here singular DSL names
  # match the command-builder surface.
  addObjectKinds = {
    table = {
      tag = "table";
      body = lib.id;
    };
    chain = {
      tag = "chain";
      body = lib.id;
    };
    rule = {
      tag = "rule";
      body = lib.id;
    };
    set = {
      tag = "set";
      body = rename.set;
    };
    map = {
      tag = "map";
      body = rename.set;
    };
    element = {
      tag = "element";
      body = rename.element;
    };
    flowtable = {
      tag = "flowtable";
      body = lib.id;
    };
    counter = {
      tag = "counter";
      body = lib.id;
    };
    quota = {
      tag = "quota";
      body = lib.id;
    };
    ctHelper = {
      tag = "ct helper";
      body = lib.id;
    };
    limit = {
      tag = "limit";
      body = lib.id;
    };
    ctTimeout = {
      tag = "ct timeout";
      body = lib.id;
    };
    ctExpectation = {
      tag = "ct expectation";
      body = lib.id;
    };
    secmark = {
      tag = "secmark";
      body = lib.id;
    };
    synproxy = {
      tag = "synproxy";
      body = lib.id;
    };
    tunnel = {
      tag = "tunnel";
      body = rename.tunnel;
    };
  };

  # `meter` listing (parser_json.c:4191) is supported even though there's no
  # `add meter` command — meters are anonymous sets created via the `meter`
  # *statement*. Listed via `dsl.list.meter { family; table; name; }`.
  listObjectKinds = addObjectKinds // {
    metainfo = {
      tag = "metainfo";
      body = lib.id;
    };
    meter = {
      tag = "meter";
      body = lib.id;
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

  # Build a namespace `{ dslKey = body: { cmdTag = { jsonTag = rename body; }; }; … }`.
  mkNamespace =
    cmdTag: kinds:
    lib.mapAttrs (_: cfg: body: {
      ${cmdTag} = {
        ${cfg.tag} = cfg.body body;
      };
    }) kinds;
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
        chain = body;
      };
    };
  };

  # replace / insert accept only rule bodies per the schema, and the
  # nftables JSON parser expects `{ replace: { rule: <ruleBody> } }`
  # (tagged). Implemented as plain body-taking functions since the object
  # kind is fixed.
  replace = body: {
    replace = {
      rule = body;
    };
  };
  insert = body: {
    insert = {
      rule = body;
    };
  };
}
