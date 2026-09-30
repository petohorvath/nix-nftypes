{
  lib,
  internal,
  objects,
}:

let
  inherit (lib) mkOption types;
  inherit (internal) taggedUnion;

  # attrTag for the command wrappers themselves. Each command wraps one of the
  # object-type unions.
  #
  # `replace`, `insert`, and `rename` take their object-kind tag inside the
  # command body — `{ replace: { rule: <ruleBody> } }`, not
  # `{ replace: <ruleBody> }`. The nftables JSON parser rejects the direct
  # form (verified with `nft -c -j -f`), so we use the single-tag wrappers
  # `objects.all.rule` / `.chain` here.
  command = taggedUnion {
    add = objects.addObject;
    replace = objects.all.rule;
    # parser_json.c rejects `create rule`; the object union deliberately
    # excludes that tag instead of reusing the broader `add` union.
    create = objects.createObject;
    insert = objects.all.rule;
    delete = objects.addObject;
    destroy = objects.addObject;
    list = objects.listObject;
    reset = objects.resetObject;
    flush = objects.flushObject;
    rename = objects.all.chain;
  };
in
{
  inherit command;

  ruleset = types.submodule {
    # Each entry is a command wrapper or a bare listed object (the shape
    # `nft -j list` emits).
    options.nftables = mkOption {
      type = types.listOf (
        types.oneOf [
          command
          objects.listObject
        ]
      );
      description = "ordered list of commands or listed ruleset objects";
    };
  };
}
