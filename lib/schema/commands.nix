{
  lib,
  internal,
  objects,
}:

let
  inherit (lib) mkOption types;
  inherit (internal) discriminatedSubmodule taggedUnion;

  # attrTag for the command wrappers themselves. Each command wraps one of the
  # object-type unions.
  #
  # `replace`, `insert`, and `rename` take their object-kind tag inside the
  # command body — `{ replace: { rule: <ruleBody> } }`, not
  # `{ replace: <ruleBody> }`. The nftables JSON parser rejects the direct
  # form (verified with `nft -c -j -f`), so we use the single-tag wrappers
  # `objects.all.rule`, `objects.replaceObject`, and `objects.renameObject`
  # here.
  command = taggedUnion {
    add = objects.addObject;
    replace = objects.replaceObject;
    # parser_json.c rejects `create rule`; the object union deliberately
    # excludes that tag instead of reusing the broader `add` union.
    create = objects.createObject;
    insert = objects.all.rule;
    delete = objects.deleteObject;
    destroy = objects.deleteObject;
    list = objects.listObject;
    reset = objects.resetObject;
    flush = objects.flushObject;
    rename = objects.renameObject;
  };

  /*
    In one batch, nft (1.1.6 and 1.1.7, JSON and text) runs a reset of a
    counter, quota, set, map, or rule only as the batch's last command:
    followed by any other command, it resets nothing and nft still exits
    0. A reset of an element runs anywhere.
  */
  resetsRunAsWritten =
    value:
    let
      entries = value.nftables or [ ];
      lastOnlyKinds = [
        "counter"
        "quota"
        "set"
        "map"
        "rule"
      ];
      isLastOnlyReset =
        entry:
        builtins.isAttrs entry
        && builtins.isAttrs (entry.reset or null)
        && lib.any (kind: entry.reset ? ${kind}) lastOnlyKinds;
    in
    !(builtins.isList entries) || entries == [ ] || !(lib.any isLastOnlyReset (lib.init entries));
in
{
  inherit command;

  ruleset = discriminatedSubmodule {
    extraCheck = resetsRunAsWritten;
    description = "nft ruleset whose reset of a counter, quota, set, map, or rule is its last command";
    # Each entry is a command wrapper or a bare listed object (the shape
    # `nft -j list` emits).
    options.nftables = mkOption {
      type = types.listOf (
        types.oneOf [
          command
          objects.readBackObject
        ]
      );
      description = "ordered list of commands or listed ruleset objects";
    };
  };
}
