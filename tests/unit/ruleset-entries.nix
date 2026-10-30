# Each entry of a ruleset is one command, a verb holding one object kind,
# or one listed object. nft's JSON parser runs only the first verb or kind
# of an entry with several and still exits 0, so `toJson` emitted a chain
# nft never added; text refused the same entry. The renderers and
# `dsl.ruleset` check the shape alone, so a raw command keeps its escape
# hatch for a kind the schema doesn't model.
{ nftlib, ... }:
let
  inherit (nftlib) dsl toJson toText;

  table = {
    family = "inet";
    name = "t";
  };
  chain = {
    family = "inet";
    table = "t";
    name = "c";
  };

  rendererCases = {
    twoKinds = {
      entry = {
        add = {
          inherit table chain;
        };
      };
      msg = "nftables\\.0: `add` holds chain, table, but nft runs only the first; give each its own command$";
    };
    twoVerbs = {
      entry = {
        add.table = table;
        delete.table = table;
      };
      msg = "nftables\\.0: holds add, delete, but nft runs only the first; give each command or listed object its own entry$";
    };
    statement = {
      entry = dsl.accept;
      msg = "nftables\\.0: expected a command, a verb such as `add` holding one object kind, or a listed object, such as `table`, got an attribute set with accept$";
    };
    tableTreeBody = {
      entry = {
        chains.c = { };
      };
      msg = "nftables\\.0: expected a command, .*got an attribute set with chains$";
    };
    empty = {
      entry = { };
      msg = "nftables\\.0: got an empty attribute set, which nft rejects; leave the entry out, as with lib\\.optional$";
    };
    verbWithoutKind = {
      entry = {
        add = { };
      };
      msg = "nftables\\.0: `add` takes one object kind, such as `add\\.table`, got an empty attribute set$";
    };
    notAnAttrset = {
      entry = "add table inet t";
      msg = "nftables\\.0: expected a command or a listed object, got a string$";
    };
  };

  rendererTests = builtins.listToAttrs (
    builtins.concatMap (
      name:
      let
        case = rendererCases.${name};
      in
      map (renderer: {
        name = "test${renderer.name}Rejects_${name}";
        value = {
          expr = renderer.render {
            nftables = [
              { add.table = table; }
              case.entry
            ];
          };
          expectedError = {
            type = "ThrownError";
            msg = "^nix-nftypes: ${renderer.name}: ${
              builtins.replaceStrings [ "nftables\\.0" ] [ "nftables\\.1" ] case.msg
            }";
          };
        };
      }) renderers
    ) (builtins.attrNames rendererCases)
  );

  renderers = [
    {
      name = "toJson";
      render = toJson;
    }
    {
      name = "toText";
      render = toText;
    }
  ];
in
rendererTests
// {
  testDslRulesetRejectsTwoKinds = {
    expr = dsl.ruleset [
      (dsl.add.table table)
      [ { add = { inherit table chain; }; } ]
    ];
    expectedError = {
      type = "ThrownError";
      msg = "^nix-nftypes: dsl\\.ruleset: 1\\.0: `add` holds chain, table, but nft runs only the first; give each its own command$";
    };
  };

  testDslRulesetRejectsStatement = {
    expr = dsl.ruleset [ dsl.accept ];
    expectedError = {
      type = "ThrownError";
      msg = "^nix-nftypes: dsl\\.ruleset: 0: expected a command, .*got an attribute set with accept$";
    };
  };

  testDslRulesetRejectsEmptyAttrset = {
    expr = dsl.ruleset [ { } ];
    expectedError = {
      type = "ThrownError";
      msg = "^nix-nftypes: dsl\\.ruleset: 0: got an empty attribute set, which nft rejects; leave the entry out, as with lib\\.optional$";
    };
  };

  # A spliced ruleset's entries are checked where they sit.
  testDslRulesetRejectsSplicedEntry = {
    expr = dsl.ruleset [ { nftables = [ dsl.drop ]; } ];
    expectedError = {
      type = "ThrownError";
      msg = "^nix-nftypes: dsl\\.ruleset: 0\\.nftables\\.0: expected a command, .*got an attribute set with drop$";
    };
  };

  # A listed object, as `nft -j list` emits it, is an entry.
  testListedObjectRenders = {
    expr = toJson {
      nftables = [
        { metainfo.json_schema_version = 1; }
        {
          table = table // {
            handle = 1;
          };
        }
      ];
    };
    expected = "{\"nftables\":[{\"metainfo\":{\"json_schema_version\":1}},{\"table\":{\"family\":\"inet\",\"handle\":1,\"name\":\"t\"}}]}";
  };

  # The kind under a verb is not checked, so a raw command reaches a form
  # the schema leaves out.
  testUnmodelledKindRenders = {
    expr = toJson (dsl.ruleset [ { list.sets.family = "inet"; } ]);
    expected = "{\"nftables\":[{\"list\":{\"sets\":{\"family\":\"inet\"}}}]}";
  };
}
