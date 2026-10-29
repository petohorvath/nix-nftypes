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
  # namespaces `expressionBodies`, `statementBodies` and `objectBodies`
  # hold the bodies.
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
    "expressionBodies.ipsecBody.spnum" = [
      0
      255
    ];
    # An IPv6 prefix is at most 128 bits.
    "expressionBodies.prefixBody.len" = [
      0
      128
    ];
    # TCP option kind: one byte.
    "expressionBodies.tcpOptionRawBody.base" = [
      0
      255
    ];
    # Ports are 16 bits.
    "objectBodies.ctExpectationBody.dport" = [
      0
      65535
    ];
    # Read-back lists a ct expectation with its handle, a body of its own.
    "readBackObject.ct expectation.dport" = [
      0
      65535
    ];
    "objectBodies.tunnelBody.dport" = [
      0
      65535
    ];
    "objectBodies.tunnelBody.sport" = [
      0
      65535
    ];
    # IP header TOS and TTL: one byte each.
    "objectBodies.tunnelBody.tos" = [
      0
      255
    ];
    "objectBodies.tunnelBody.ttl" = [
      0
      255
    ];
  };

  # Optional fields the body's own check needs: nft fails a FIB lookup
  # without `saddr` or `daddr` among its flags, and an IPsec key without
  # a direction.
  requiredByCheck = [
    "expressionBodies.fibBody.flags"
    "expressionBodies.ipsecBody.dir"
  ];

  # For a field whose members the body's check accepts only beside
  # another value, the body each member is tested in.
  memberBodies = {
    # A direction needs a key that takes one.
    "expressionBodies.ctBody.dir" = dir: {
      key = "saddr";
      inherit dir;
    };
    # Any flag, beside the `saddr` a FIB lookup needs.
    "expressionBodies.fibBody.flags" = flag: {
      result = "oif";
      flags = lib.unique [
        flag
        "saddr"
      ];
    };
  };

  # Fields the generator can't handle, each with its reason.
  notGenerated = { };

  fields = builtins.filter (field: !(notGenerated ? ${field.path})) (optionTree.fieldsFrom roots);

  testsByField = map (
    field:
    lib.mapAttrs' (kind: test: lib.nameValuePair "test_${kind}_${field.path}" test) (
      optionTree.fieldTests (
        field
        // {
          range = expectedRanges.${field.path} or null;
          requiredByCheck = builtins.elem field.path requiredByCheck;
        }
      )
    )
  ) fields;

  memberTests = map (
    field:
    lib.mapAttrs' (member: test: lib.nameValuePair "test_member_${field.path}.${member}" test) (
      optionTree.memberTests (field // { memberBody = memberBodies.${field.path} or null; })
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
      fields = 655;
      body = 95;
      wrongType = 655;
      accepted = 170;
      omitted = 254;
      lowest = 116;
      belowLowest = 116;
      highest = 9;
      aboveHighest = 9;
      member = 597;
      enum = 195;
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
