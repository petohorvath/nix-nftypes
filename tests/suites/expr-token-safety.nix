{
  helpers,
  lib,
  nftlib,
  ...
}:

# Regression coverage for the bare-token injection class inside
# tagged expression bodies. Several expression kinds — payload,
# exthdr, ip/tcp/sctp option, ct — carry one or more `types.str`
# fields (protocol, field, name, key, …) that the text renderer
# interpolated bare into the surrounding clause:
#
#   tcp ${body.protocol} ${body.field}     payload
#   ip option ${body.name} ${body.field}   ipOption
#   sctp chunk ${body.name} ${body.field}  sctpChunk
#   ct ${body.key}                         ct
#
# A value like `"dport\nadd chain inet fw pwned { … }"` truncated the
# clause and dropped a fresh `add chain` into the rendered file,
# accepted by `nft -f` as a real chain at attacker-chosen priority.
#
# Renderer-level fix: a shared `safeToken` helper in
# lib/text/primitives.nix runs each value through the
# `nft-safe-scalar` predicate before interpolation. The JSON path is
# unaffected (libnftables receives literal bytes; the kernel rejects
# unknown protocol / field / key names at the syscall layer).

let
  inherit (helpers)
    rejectsText
    rejectsTextPretty
    ;
  dsl = nftlib.dsl;

  mkMatchRuleset =
    lhs:
    dsl.ruleset [
      (dsl.table "inet" "fw" {
        chains.input = {
          type = "filter";
          hook = "input";
          prio = 0;
          rules = [
            [
              (dsl.eq lhs 22)
              dsl.accept
            ]
          ];
        };
      })
    ];

  surfaces = {
    payloadProtocol =
      bad:
      mkMatchRuleset {
        payload = {
          protocol = bad;
          field = "dport";
        };
      };
    payloadField =
      bad:
      mkMatchRuleset {
        payload = {
          protocol = "tcp";
          field = bad;
        };
      };
    payloadTunnelInner =
      bad:
      mkMatchRuleset {
        payload = {
          tunnel = "vxlan";
          protocol = bad;
          field = "dport";
        };
      };
    exthdrName =
      bad:
      mkMatchRuleset {
        exthdr = {
          name = bad;
          field = "value";
        };
      };
    exthdrField =
      bad:
      mkMatchRuleset {
        exthdr = {
          name = "frag";
          field = bad;
        };
      };
    tcpOptionName =
      bad:
      mkMatchRuleset {
        "tcp option" = {
          name = bad;
          field = "size";
        };
      };
    tcpOptionField =
      bad:
      mkMatchRuleset {
        "tcp option" = {
          name = "maxseg";
          field = bad;
        };
      };
    ipOptionName =
      bad:
      mkMatchRuleset {
        "ip option" = {
          name = bad;
          field = "value";
        };
      };
    ipOptionField =
      bad:
      mkMatchRuleset {
        "ip option" = {
          name = "lsrr";
          field = bad;
        };
      };
    sctpChunkName =
      bad:
      mkMatchRuleset {
        "sctp chunk" = {
          name = bad;
          field = "type";
        };
      };
    sctpChunkField =
      bad:
      mkMatchRuleset {
        "sctp chunk" = {
          name = "data";
          field = bad;
        };
      };
    ctKey =
      bad:
      mkMatchRuleset {
        ct = {
          key = bad;
        };
      };
  };

  badInputs = {
    newline = "dport\nadd chain inet fw pwned { type filter hook input priority -10; policy accept; }";
    semicolon = "dport; add chain inet fw pwned;";
    brace = "dport}";
    quote = ''dport"'';
    backslash = ''dport\'';
    space = "dport extra";
    hash = "dport#";
    comma = "dport,extra";
    empty = "";
  };

  rejectionTests = lib.listToAttrs (
    lib.concatMap (
      surface:
      lib.mapAttrsToList (badName: badValue: {
        name = "testRendererRejects_${surface}_${badName}";
        value = {
          expr = rejectsText (surfaces.${surface} badValue);
          expected = true;
        };
      }) badInputs
    ) (builtins.attrNames surfaces)
  );

  # Pretty-mode smoke: pin the same render path through the
  # multi-line entry, covering both compact and pretty.
  prettyTests = {
    testPrettyRejects_payloadField_newline = {
      expr = rejectsTextPretty (surfaces.payloadField badInputs.newline);
      expected = true;
    };
    testPrettyRejects_ctKey_newline = {
      expr = rejectsTextPretty (surfaces.ctKey badInputs.newline);
      expected = true;
    };
  };

  # Clean values for every surface — proves the assert doesn't
  # false-positive on legitimate identifier-shaped tokens.
  acceptanceTests = {
    testAccepts_payload = {
      expr = rejectsText (surfaces.payloadProtocol "tcp");
      expected = false;
    };
    testAccepts_exthdr = {
      expr = rejectsText (surfaces.exthdrName "frag");
      expected = false;
    };
    testAccepts_tcpOption = {
      expr = rejectsText (surfaces.tcpOptionName "maxseg");
      expected = false;
    };
    testAccepts_ipOption = {
      expr = rejectsText (surfaces.ipOptionName "lsrr");
      expected = false;
    };
    testAccepts_sctpChunk = {
      expr = rejectsText (surfaces.sctpChunkName "data");
      expected = false;
    };
    testAccepts_ctKey = {
      expr = rejectsText (surfaces.ctKey "state");
      expected = false;
    };
  };
in
rejectionTests // prettyTests // acceptanceTests
