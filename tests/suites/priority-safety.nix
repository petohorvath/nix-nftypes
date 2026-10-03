{
  lib,
  nftlib,
  ...
}:

# Regression coverage for the chain/flowtable priority injection
# class. The schema types `prio` as `nullOr int`, but the text
# renderer's `primitives.priority` used to accept strings too —
# emitting them bare into the `priority <X>` clause. A raw attrset
# bypassing the schema could pass a string like
# `"filter\nadd chain inet fw pwned { … }"`, which `nft -f` parsed as
# two top-level statements (the second arbitrary attacker input).
#
# Renderer-level fix: `primitives.priority` now refuses anything that
# isn't an int and throws naming the value. Symbolic priorities
# (`filter`, `filter + 10`) flow through `nftlib.resolvePriority` to
# an int before reaching the renderer; the int path stays unchanged.

let
  inherit (nftlib) toText toTextPretty;

  rulesetWithChainPrio =
    prio:
    # Raw attrset: bypasses the DSL emit step and its schema check.
    # The text renderer is the only line of defence here.
    {
      nftables = [
        {
          add = {
            table = {
              family = "inet";
              name = "fw";
            };
          };
        }
        {
          add = {
            chain = {
              family = "inet";
              table = "fw";
              name = "input";
              type = "filter";
              hook = "input";
              prio = prio;
            };
          };
        }
      ];
    };

  rulesetWithFlowtablePrio = prio: {
    nftables = [
      {
        add = {
          table = {
            family = "inet";
            name = "fw";
          };
        };
      }
      {
        add = {
          flowtable = {
            family = "inet";
            table = "fw";
            name = "ft";
            hook = "ingress";
            prio = prio;
            dev = "eth0";
          };
        };
      }
    ];
  };

  badInputs = {
    newline = "filter\nadd chain inet fw pwned { type filter hook input priority -10; policy accept; }";
    semicolon = "filter; add chain inet fw pwned;";
    cleanString = "filter";
    cleanSymbolic = "filter + 10";
    bool = true;
    list = [ 0 ];
  };

  chainRejectionTests = lib.listToAttrs (
    lib.mapAttrsToList (badName: badValue: {
      name = "testRendererRejects_chain_${badName}";
      value = {
        expr = nftlib.toText (rulesetWithChainPrio badValue);
        expectedError.msg = "refusing to render a non-integer chain/flowtable priority";
      };
    }) badInputs
  );

  flowtableRejectionTests = lib.listToAttrs (
    lib.mapAttrsToList (badName: badValue: {
      name = "testRendererRejects_flowtable_${badName}";
      value = {
        expr = nftlib.toText (rulesetWithFlowtablePrio badValue);
        expectedError.msg = "refusing to render a non-integer chain/flowtable priority";
      };
    }) badInputs
  );

  acceptanceTests = {
    testRendererAccepts_chain_zero = {
      expr = builtins.isString (nftlib.toText (rulesetWithChainPrio 0));
      expected = true;
    };
    testRendererAccepts_chain_negative = {
      expr = builtins.isString (nftlib.toText (rulesetWithChainPrio (-200)));
      expected = true;
    };
    testRendererAccepts_chain_positive = {
      expr = builtins.isString (nftlib.toText (rulesetWithChainPrio 300));
      expected = true;
    };
    testRendererAccepts_flowtable_negative = {
      expr = builtins.isString (nftlib.toText (rulesetWithFlowtablePrio (-100)));
      expected = true;
    };
  };

  prettyTests = {
    testPrettyRejects_chain_newline = {
      expr = (toTextPretty (rulesetWithChainPrio badInputs.newline));
      expectedError.msg = "refusing to render a non-integer chain/flowtable priority";
    };
    testPrettyAccepts_chain_int = {
      expr = builtins.isString ((toTextPretty (rulesetWithChainPrio 0)));
      expected = true;
    };
  };

  # `resolvePriority` is the documented path for users who want named
  # priorities. Pin that its int result reaches the renderer; the schema
  # suite covers the resolved values.
  resolverTests = {
    testResolvedPriorityRenders = {
      expr = builtins.isString ((toText (rulesetWithChainPrio (nftlib.resolvePriority "ip" "mangle"))));
      expected = true;
    };
  };
in
chainRejectionTests // flowtableRejectionTests // acceptanceTests // prettyTests // resolverTests
