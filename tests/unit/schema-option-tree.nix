{
  helpers,
  lib,
  nftlib,
  ...
}:

/*
  Schema tests generated from the option tree (tests/helpers/
  option-tree.nix). For every field of every body and every tag of every
  tagged union reachable from `nftlib.types`:

  - a value of the wrong type is rejected;
  - an optional field left out still validates, and declares its null
    default;
  - an integer field accepts its lowest value and rejects one below it,
    and a range also accepts its highest value and rejects one above it;
  - a field holding an enum accepts each of its members, and so does
    each public enum type.

  The ranges' ends come from the hand-written `expectedRanges`, so a
  changed bound fails. `testGeneratedCounts` pins how many tests each
  kind produced, so a generator that silently produces fewer fails.
*/
let
  inherit (helpers) optionTree;

  # Every public schema type, by its path under `nftlib.types`; the
  # namespaces `expressions`, `statements` and `objects` hold the bodies.
  roots = lib.concatMapAttrs (
    name: value:
    if value._type or null == "option-type" then
      { ${name} = value; }
    else if builtins.isAttrs value then
      lib.mapAttrs' (member: lib.nameValuePair "${name}.${member}") (
        lib.filterAttrs (_: member: member._type or null == "option-type") value
      )
    else
      { }
  ) nftlib.types;

  # The ends of every `types.ints.between` field, from nft and the kernel.
  expectedRanges = {
    # IPsec SA index: nft refuses spnum above 255.
    "expressions.ipsecBody.spnum" = [
      0
      255
    ];
    # An IPv6 prefix is at most 128 bits.
    "expressions.prefixBody.len" = [
      0
      128
    ];
    # TCP option kind: one byte.
    "expressions.rawTcpOptionBody.base" = [
      0
      255
    ];
    # Ports are 16 bits.
    "objects.ctExpectationBody.dport" = [
      0
      65535
    ];
    "objects.tunnelBody.dport" = [
      0
      65535
    ];
    "objects.tunnelBody.sport" = [
      0
      65535
    ];
    # IP header TOS and TTL: one byte each.
    "objects.tunnelBody.tos" = [
      0
      255
    ];
    "objects.tunnelBody.ttl" = [
      0
      255
    ];
  };

  # Fields the generator can't handle, each with its reason.
  notGenerated = { };

  fields = builtins.filter (field: !(notGenerated ? ${field.path})) (optionTree.fieldsFrom roots);

  testsByField = map (
    field:
    lib.mapAttrs' (kind: test: lib.nameValuePair "test_${kind}_${field.path}" test) (
      optionTree.fieldTests (field // { range = expectedRanges.${field.path} or null; })
    )
  ) fields;

  memberTests = map (
    field:
    lib.mapAttrs' (member: test: lib.nameValuePair "test_member_${field.path}.${member}" test) (
      optionTree.memberTests field
    )
  ) fields;

  enumTests = map (
    enum:
    lib.mapAttrs' (member: test: lib.nameValuePair "test_enum_${enum.path}.${member}" test) (
      optionTree.enumTests enum
    )
  ) (optionTree.enumsFrom roots);

  bodyTests = map (body: { "test_body_${body.path}" = optionTree.bodyTest body; }) (
    optionTree.bodiesFrom roots
  );

  generatedTests = lib.mergeAttrsList (bodyTests ++ testsByField ++ memberTests ++ enumTests);

  countByKind = lib.foldl' (
    counts: tests:
    lib.foldl' (
      counts: name:
      let
        kind = builtins.head (builtins.match "test_([^_]+)_.*" name);
      in
      counts // { ${kind} = (counts.${kind} or 0) + 1; }
    ) counts (builtins.attrNames tests)
  ) { } (bodyTests ++ testsByField ++ memberTests ++ enumTests);
in
generatedTests
// {
  testGeneratedCounts = {
    expr = countByKind // {
      fields = builtins.length fields;
    };
    expected = {
      fields = 548;
      body = 81;
      wrongType = 548;
      accepted = 171;
      omitted = 197;
      lowest = 99;
      belowLowest = 99;
      highest = 8;
      aboveHighest = 8;
      member = 401;
      enum = 164;
    };
  };

  testExpectedRangesAreTheRangeFields = {
    expr = map (field: field.path) (builtins.filter optionTree.isRange fields);
    expected = builtins.attrNames expectedRanges;
  };

  testNotGeneratedFieldsExist = {
    expr = builtins.attrNames (
      removeAttrs notGenerated (map (field: field.path) (optionTree.fieldsFrom roots))
    );
    expected = [ ];
  };
}
