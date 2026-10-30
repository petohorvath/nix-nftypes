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
  # command body — `{ replace: { rule: <replaceRuleBody> } }`, not
  # `{ replace: <replaceRuleBody> }`. The nftables JSON parser rejects the
  # direct form (verified with `nft -c -j -f`), so we use the single-tag
  # unions `objects.insertObject`, `objects.replaceObject`, and
  # `objects.renameObject` here.
  commandBodies = {
    add = objects.addObject;
    replace = objects.replaceObject;
    # parser_json.c rejects `create rule`; the object union deliberately
    # excludes that tag instead of reusing the broader `add` union.
    create = objects.createObject;
    insert = objects.insertObject;
    delete = objects.deleteObject;
    destroy = objects.destroyObject;
    list = objects.listObject;
    reset = objects.resetObject;
    flush = objects.flushObject;
    rename = objects.renameObject;
  };
  command = taggedUnion commandBodies;

  /*
    In one batch, nft (1.1.6 and 1.1.7, JSON and text) runs a reset of a
    counter, quota, set, map, or rule only as the batch's last command:
    followed by any other command, it resets nothing and nft still exits
    0. A reset of an element runs anywhere. `types.ruleset` and
    `dsl.ruleset` both apply this rule.
  */
  resetOrder =
    let
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
    {
      # The kinds in prose, "counter, …, or rule", for messages.
      kindsText = "${lib.concatStringsSep ", " (lib.init lastOnlyKinds)}, or ${lib.last lastOnlyKinds}";

      # Whether each such reset in the command list `entries` is its last.
      isRunAsWritten = entries: entries == [ ] || !(lib.any isLastOnlyReset (lib.init entries));
    };
in
{
  inherit command resetOrder;

  # The command verbs, for the renderers' entry check.
  verbs = builtins.attrNames commandBodies;

  ruleset = discriminatedSubmodule {
    invariant =
      value:
      let
        entries = value.nftables or [ ];
      in
      !(builtins.isList entries) || resetOrder.isRunAsWritten entries;
    description = "nft ruleset whose reset of a ${resetOrder.kindsText} is its last command";
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
