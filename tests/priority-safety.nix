{ lib, nftlib }:

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

  evalSucceeds = expr: (builtins.tryEval expr).success;

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

  rendererRejects = body: !(evalSucceeds (toText body));

  chainRejectionTests = lib.listToAttrs (
    lib.mapAttrsToList (badName: badValue: {
      name = "testRendererRejects_chain_${badName}";
      value = {
        expr = rendererRejects (rulesetWithChainPrio badValue);
        expected = true;
      };
    }) badInputs
  );

  flowtableRejectionTests = lib.listToAttrs (
    lib.mapAttrsToList (badName: badValue: {
      name = "testRendererRejects_flowtable_${badName}";
      value = {
        expr = rendererRejects (rulesetWithFlowtablePrio badValue);
        expected = true;
      };
    }) badInputs
  );

  acceptanceTests = {
    testRendererAccepts_chain_zero = {
      expr = rendererRejects (rulesetWithChainPrio 0);
      expected = false;
    };
    testRendererAccepts_chain_negative = {
      expr = rendererRejects (rulesetWithChainPrio (-200));
      expected = false;
    };
    testRendererAccepts_chain_positive = {
      expr = rendererRejects (rulesetWithChainPrio 300);
      expected = false;
    };
    testRendererAccepts_flowtable_negative = {
      expr = rendererRejects (rulesetWithFlowtablePrio (-100));
      expected = false;
    };
  };

  prettyTests = {
    testPrettyRejects_chain_newline = {
      expr = evalSucceeds (toTextPretty (rulesetWithChainPrio badInputs.newline));
      expected = false;
    };
    testPrettyAccepts_chain_int = {
      expr = evalSucceeds (toTextPretty (rulesetWithChainPrio 0));
      expected = true;
    };
  };

  # `resolvePriority` is the documented path for users who want named
  # priorities. Pin that it still works and yields an int the renderer
  # accepts, so the API hasn't regressed.
  resolverTests = {
    testResolvePriorityFilter = {
      expr = nftlib.resolvePriority "ip" "filter";
      expected = 0;
    };
    testResolvePriorityBridgeFilter = {
      expr = nftlib.resolvePriority "bridge" "filter";
      expected = -200;
    };
    testResolvedPriorityRenders = {
      expr = evalSucceeds (toText (rulesetWithChainPrio (nftlib.resolvePriority "ip" "mangle")));
      expected = true;
    };
  };

  tests =
    chainRejectionTests // flowtableRejectionTests // acceptanceTests // prettyTests // resolverTests;

  runTests = (import ./lib.nix { inherit lib; }).mkRunTests {
    name = "priority-safety-tests";
    inherit tests;
  };
in
{
  inherit tests runTests;
}
