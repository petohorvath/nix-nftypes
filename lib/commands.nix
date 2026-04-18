{ lib, objects }:

let
  inherit (lib) types mkOption;

  # The list-object bodies accepted at top level (bare, no command wrapper).
  bareListObject = objects.listObject;

  tagOpt = type: mkOption { inherit type; };

  # attrTag for the command wrappers themselves. Each command wraps one of the
  # object-type unions.
  command = types.attrTag (
    lib.mapAttrs (_: tagOpt) {
      add = objects.addObject;
      replace = objects.all.ruleBody;
      create = objects.addObject;
      insert = objects.all.ruleBody;
      delete = objects.addObject;
      destroy = objects.addObject;
      list = objects.listObject;
      reset = objects.resetObject;
      flush = objects.flushObject;
      rename = objects.all.chainBody;
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
