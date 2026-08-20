{ lib, nftlib }:

# End-to-end integration test cases. Each case renders to JSON and is fed
# to `unshare -rn nft -c -j -f`, which invokes the real nftables parser
# against a kernel netfilter instance in a fresh network namespace. This
# is stricter than schema validation: the parser resolves cross-references
# (chains referenced by verdict-map elements, rules referring to named
# objects, handles), rejects the library's occasional divergences from the
# parser's own expectations, and catches any shape mismatch evalModules
# couldn't.
#
# # Scope of what we can test in check mode
#
# `nft -c` inside a private netns parses the batch and validates cross-
# references WITHIN the batch, but it can't observe *prior* kernel state.
# That means commands whose semantics require a pre-existing object
# (e.g. `rename.chain`, `replace`, `insert` with handle references,
# `list.<kind>` for anything other than table, `delete` for ct-timeout /
# ct-expectation / secmark / tunnel in a sandbox without the relevant
# kernel features) are not covered here. Their JSON shapes are verified
# by the schema-tests suite; real-kernel validation is left for manual
# `nft -f` runs in a live environment.
#
# The schema-validating test suite (tests/dsl-parity.nix) exercises every
# command × object-kind combo the DSL exposes at the JSON-shape level.
# This suite exists to catch the categories of bug the schema can't:
# forward-reference resolution, argument formats libnftables actually
# accepts, subtle divergences from the adoc.

let
  dsl = nftlib.dsl;
  inherit (dsl)
    ruleset
    flush
    accept
    drop
    create
    delete
    destroy
    list
    reset
    flushRuleset
    flushTable
    flushChain
    flushSet
    flushMap
    ;

  tbl = {
    family = "ip";
    table = "t";
  };
  tbl4 = {
    family = "ip";
    name = "t";
  };
in
rec {
  cases = [
    # -- create: supported object kinds ------------------------------------
    # `create.rule` is excluded from the DSL (nftables rejects it).
    # `tunnel` and `secmark` kinds need kernel features the sandbox may
    # lack, so they're exercised only via the schema-tests.
    {
      name = "create-supported-kinds";
      ruleset = ruleset [
        flush
        (create.table tbl4)
        (create.chain (
          tbl
          // {
            name = "c";
            type = "filter";
            hook = "input";
            prio = 0;
          }
        ))
        (create.counter (tbl // { name = "ctr"; }))
        (create.quota (
          tbl
          // {
            name = "q";
            bytes = 1000000;
          }
        ))
        (create.limit (
          tbl
          // {
            name = "lim";
            rate = 5;
            per = "second";
          }
        ))
        (create.set (
          tbl
          // {
            name = "s";
            type = "ipv4_addr";
          }
        ))
        (create.map (
          tbl
          // {
            name = "m";
            type = "inet_service";
            map = "inet_service";
          }
        ))
        (create.element (
          tbl
          // {
            name = "s";
            elements = [ "1.2.3.4" ];
          }
        ))
        (create.flowtable (
          tbl
          // {
            name = "ft";
            hook = "ingress";
            prio = 0;
            dev = [ "lo" ];
          }
        ))
        (create.ctHelper (
          tbl
          // {
            name = "h";
            type = "ftp";
            protocol = "tcp";
            l3proto = "ip";
          }
        ))
        (create.ctTimeout (
          tbl
          // {
            name = "cto";
            protocol = "tcp";
            l3proto = "ip";
            policy = {
              established = 300;
            };
          }
        ))
        (create.ctExpectation (
          tbl
          // {
            name = "cte";
            protocol = "tcp";
            l3proto = "ip";
            dport = 8080;
            timeout = 60;
            size = 1;
          }
        ))
        (create.synproxy (
          tbl
          // {
            name = "sp";
            mss = 1460;
            wscale = 7;
          }
        ))
      ];
    }

    # -- add (via table tree + dsl.rule) -----------------------------------
    # `add.rule` is the canonical way to add a rule; the declarative table
    # tree emits `add rule` commands for every entry in `chains.*.rules`.
    # Also exercises `dsl.rule` for a standalone rule with an explicit
    # handle.
    {
      name = "add-rule-via-tree-and-standalone";
      ruleset = ruleset [
        flush
        (dsl.table "ip" "t" {
          chains.c = {
            rules = [
              [ accept ]
              [ drop ]
            ];
          };
        })
        (dsl.rule {
          family = "ip";
          table = "t";
          chain = "c";
          handle = 42;
          expr = [ accept ];
        })
      ];
    }

    # -- delete: supported kinds ------------------------------------------
    # Prelude adds each object, then the same kind is deleted in the same
    # batch. Skipped kinds (ct timeout, ct expectation, secmark, tunnel)
    # trigger "Invalid argument" / "missing options" / environment-specific
    # failures — their JSON shapes are covered by dsl-parity.nix instead.
    {
      name = "delete-supported-kinds";
      ruleset = ruleset [
        flush
        (create.table tbl4)
        (create.chain (tbl // { name = "c"; }))
        (create.counter (tbl // { name = "ctr"; }))
        (create.quota (
          tbl
          // {
            name = "q";
            bytes = 1;
          }
        ))
        (create.limit (
          tbl
          // {
            name = "lim";
            rate = 1;
            per = "second";
          }
        ))
        (create.set (
          tbl
          // {
            name = "s";
            type = "ipv4_addr";
          }
        ))
        (create.map (
          tbl
          // {
            name = "m";
            type = "inet_service";
            map = "inet_service";
          }
        ))
        (create.flowtable (
          tbl
          // {
            name = "ft";
            hook = "ingress";
            prio = 0;
            dev = [ "lo" ];
          }
        ))
        (create.ctHelper (
          tbl
          // {
            name = "h";
            type = "ftp";
            protocol = "tcp";
            l3proto = "ip";
          }
        ))
        (create.synproxy (
          tbl
          // {
            name = "sp";
            mss = 1460;
            wscale = 7;
          }
        ))
        # Now delete. set/map still need `type` per the shared schema.
        (delete.counter (tbl // { name = "ctr"; }))
        (delete.quota (
          tbl
          // {
            name = "q";
            bytes = 1;
          }
        ))
        (delete.limit (
          tbl
          // {
            name = "lim";
            rate = 1;
            per = "second";
          }
        ))
        (delete.set (
          tbl
          // {
            name = "s";
            type = "ipv4_addr";
          }
        ))
        (delete.map (
          tbl
          // {
            name = "m";
            type = "inet_service";
            map = "inet_service";
          }
        ))
        (delete.flowtable (
          tbl
          // {
            name = "ft";
            hook = "ingress";
            prio = 0;
            dev = [ "lo" ];
          }
        ))
        (delete.ctHelper (
          tbl
          // {
            name = "h";
            type = "ftp";
            protocol = "tcp";
            l3proto = "ip";
          }
        ))
        (delete.synproxy (
          tbl
          // {
            name = "sp";
            mss = 1460;
            wscale = 7;
          }
        ))
        (delete.chain (tbl // { name = "c"; }))
        (delete.table tbl4)
      ];
    }

    # -- destroy (idempotent) --------------------------------------------
    # Destroy succeeds whether the object exists or not.
    {
      name = "destroy-idempotent";
      ruleset = ruleset [
        flush
        (create.table tbl4)
        (create.chain (tbl // { name = "c"; }))
        (create.counter (tbl // { name = "ctr"; }))
        (destroy.counter (tbl // { name = "ctr"; }))
        (destroy.counter (tbl // { name = "never_existed"; }))
        (destroy.chain (tbl // { name = "c"; }))
        (destroy.chain (tbl // { name = "also_never"; }))
        (destroy.table tbl4)
        (destroy.table {
          family = "ip";
          name = "never";
        })
      ];
    }

    # -- flush variants --------------------------------------------------
    # `flush.flowtable` is not supported by nftables and is not exposed
    # by the DSL.
    {
      name = "flush-variants";
      ruleset = ruleset [
        flush
        (create.table tbl4)
        (create.chain (tbl // { name = "c"; }))
        (create.set (
          tbl
          // {
            name = "s";
            type = "ipv4_addr";
          }
        ))
        (create.map (
          tbl
          // {
            name = "m";
            type = "inet_service";
            map = "inet_service";
          }
        ))
        (flushChain (tbl // { name = "c"; }))
        (flushSet (
          tbl
          // {
            name = "s";
            type = "ipv4_addr";
          }
        ))
        (flushMap (
          tbl
          // {
            name = "m";
            type = "inet_service";
            map = "inet_service";
          }
        ))
        (flushTable tbl4)
      ];
    }

    # -- flushRuleset with family scope ---------------------------------
    {
      name = "flush-ruleset-by-family";
      ruleset = ruleset [
        (flushRuleset { family = "ip"; })
        (flushRuleset { family = "inet"; })
      ];
    }

    # -- standalone elements after set ----------------------------------
    # The element command must be emitted after the set it names; nft reports
    # ENOENT when the commands are reversed.
    {
      name = "standalone-elements-after-set";
      ruleset = ruleset [
        (dsl.table "inet" "element_order" {
          sets.blocked = {
            type = "ipv4_addr";
          };
          elements.blocked = {
            elements = [ "192.0.2.1" ];
          };
        })
      ];
    }

    # -- list.table ------------------------------------------------------
    # Only `list.table` works in check mode; other kinds require an
    # existing kernel state that the sandboxed netns doesn't have.
    {
      name = "list-table";
      ruleset = ruleset [
        flush
        (create.table tbl4)
        (list.table tbl4)
      ];
    }

    # -- reset counters / quotas -----------------------------------------
    # Reset works for counter, quota, set (zero elements), map. Rule reset
    # needs an existing rule handle from the kernel.
    {
      name = "reset-counters-and-quotas";
      ruleset = ruleset [
        flush
        (create.table tbl4)
        (create.counter (tbl // { name = "ctr"; }))
        (create.quota (
          tbl
          // {
            name = "q";
            bytes = 1;
          }
        ))
        (reset.counter (tbl // { name = "ctr"; }))
        (reset.quota (
          tbl
          // {
            name = "q";
            bytes = 1;
          }
        ))
      ];
    }

    # -- both example firewalls -----------------------------------------
    {
      name = "example-basic-firewall-dsl";
      ruleset = import ../examples/basic-firewall-dsl.nix { inherit nftlib; };
    }
    {
      name = "example-home-router-dsl";
      ruleset = import ../examples/home-router-dsl.nix { inherit nftlib; };
      # The home-router flowtable binds to eth0/eth1; nft -c validates
      # those device references against the netns's link table, so the
      # runner pre-creates dummy interfaces of those names.
      interfaces = [
        "eth0"
        "eth1"
      ];
    }
  ];

  # Parser-negative cases pin distinctions that the schema must not erase.
  # These raw attrsets intentionally bypass the schema so the selected
  # channel's live JSON parser remains the behavioral oracle.
  rejectionCases = [
    {
      name = "create-rule";
      # The prelude makes the table and chain valid in the same batch, while
      # the diagnostic assertion pins rejection to the unsupported command
      # rather than an unrelated missing-state error.
      expectedError = "Create command not available for rules";
      ruleset = {
        nftables = [
          {
            add.table = {
              family = "inet";
              name = "filter";
            };
          }
          {
            add.chain = {
              family = "inet";
              table = "filter";
              name = "input";
            };
          }
          {
            create.rule = {
              family = "inet";
              table = "filter";
              chain = "input";
              expr = [ ];
            };
          }
        ];
      };
    }
  ];

  # Build a derivation that writes each case's JSON to a file and runs
  # `unshare -rn nft -c -j -f` against it. The Nix sandbox permits nested
  # user/network namespaces on Linux, so nft gets a private netfilter
  # instance and can exercise its real parser without root.
  #
  # Parameterized over the `nft` package so the same case set is instantiated
  # against the stable and unstable nixpkgs channels by flake.nix.
  mkIntegrationTests =
    { name, nft }:
    pkgs: cases:
    pkgs.runCommandLocal name
      {
        nativeBuildInputs = [
          nft
          pkgs.util-linux
          pkgs.iproute2
        ];
      }
      ''
        set +e
        failed=0
        ${lib.concatMapStringsSep "\n" (c: ''
          printf '=== %s ===\n' ${lib.escapeShellArg c.name}
          # Capture the rendered JSON once; reuse for nft input and (on
          # failure) diagnostic output. No scratch files needed.
          ruleset=$(cat <<'RULESET_EOF'
          ${nftlib.toJson c.ruleset}
          RULESET_EOF
          )
          # Per-case dummy interfaces. `nft -c` resolves device names in
          # flowtable.dev / chain.dev against the netns's link table, so
          # rules referencing real-NIC names need stand-ins. Cases without
          # the field expand to an empty for-loop.
          ifaces=${lib.escapeShellArg (lib.concatStringsSep " " (c.interfaces or [ ]))}
          # `$out` is Nix's output path — use a different name for the
          # captured stderr.
          if nft_err=$(unshare -rn bash -c "
            for dev in $ifaces; do
              ip link add \"\$dev\" type dummy 2>/dev/null || true
            done
            exec nft -c -j -f -
          " <<<"$ruleset" 2>&1); then
            echo "PASS"
          else
            echo "FAIL:"
            echo "$nft_err" | sed 's/^/    /'
            echo "$ruleset" | sed 's/^/    | /'
            failed=$((failed + 1))
          fi
        '') cases}
        ${lib.concatMapStringsSep "\n" (c: ''
          printf '=== reject %s ===\n' ${lib.escapeShellArg c.name}
          ruleset=$(cat <<'RULESET_EOF'
          ${nftlib.toJson c.ruleset}
          RULESET_EOF
          )
          expected_error=${lib.escapeShellArg c.expectedError}
          if nft_err=$(unshare -rn nft -c -j -f - <<<"$ruleset" 2>&1); then
            echo "FAIL: parser accepted a case that must be rejected"
            echo "$ruleset" | sed 's/^/    | /'
            failed=$((failed + 1))
          elif [[ "$nft_err" == *"$expected_error"* ]]; then
            echo "PASS (rejected for expected reason)"
          else
            echo "FAIL: parser rejected the case for an unexpected reason"
            echo "    expected diagnostic substring: $expected_error"
            echo "$nft_err" | sed 's/^/    /'
            echo "$ruleset" | sed 's/^/    | /'
            failed=$((failed + 1))
          fi
        '') rejectionCases}
        if [ "$failed" -gt 0 ]; then
          echo "$failed integration test(s) failed"
          exit 1
        fi
        echo "All ${toString (builtins.length cases)} acceptance and ${toString (builtins.length rejectionCases)} rejection cases passed"
        touch $out
      '';

  # Channel oracle: the exact nftables package from the selected nixpkgs input.
  runIntegrationTests =
    pkgs: cases:
    mkIntegrationTests {
      name = "dsl-integration-tests";
      nft = pkgs.nftables;
    } pkgs cases;
}
