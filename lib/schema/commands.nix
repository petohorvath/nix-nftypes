{ lib, objects }:

let
  inherit (lib) types mkOption;
  inherit (objects) tagOpt;

  # The list-object bodies accepted at top level (bare, no command wrapper).
  bareListObject = objects.listObject;

  # attrTag for the command wrappers themselves. Each command wraps one of the
  # object-type unions.
  #
  # `replace`, `insert`, and `rename` take their object-kind tag inside the
  # command body — `{ replace: { rule: <ruleBody> } }`, not
  # `{ replace: <ruleBody> }`. The nftables JSON parser rejects the direct
  # form (verified with `nft -c -j -f`), so we use the single-tag wrappers
  # `objects.all.rule` / `.chain` here.
  command = types.attrTag (
    lib.mapAttrs (_: tagOpt) {
      add = objects.addObject;
      replace = objects.all.rule;
      create = objects.addObject;
      insert = objects.all.rule;
      delete = objects.addObject;
      destroy = objects.addObject;
      list = objects.listObject;
      reset = objects.resetObject;
      flush = objects.flushObject;
      rename = objects.all.chain;
    }
  );

  # Either a command wrapper or a bare listed object (for `nft -j list` output).
  topLevel = types.oneOf [
    command
    bareListObject
  ];

  ruleset = types.submodule {
    options.nftables = mkOption {
      type = types.listOf topLevel;
      description = "ordered list of commands or listed ruleset objects";
    };
  };
in
{
  inherit command ruleset;
}
