/*
  Rulesets for the live-parser probes and their nix-unit suites. Each case
  renders to JSON (and, unless excluded, to text) and is fed to the
  package set's real `nft` inside a private network namespace.

  `nft -c` inside a private netns parses the batch and validates
  cross-references WITHIN the batch, but it can't observe *prior* kernel
  state. Commands whose semantics require a pre-existing object (e.g.
  `rename.chain`, `replace`, `insert` with handle references, `list.<kind>`
  for anything other than table, `delete` for ct-timeout / ct-expectation /
  secmark / tunnel in a sandbox without the relevant kernel features) are
  not covered here. Their JSON shapes are verified by the schema and
  DSL-parity suites; real-kernel validation is left for manual `nft -f`
  runs in a live environment.

  These cases exist to catch the categories of bug the schema can't:
  forward-reference resolution, argument formats libnftables actually
  accepts, subtle divergences from the adoc.
*/
{ dsl, examples }:
let
  inherit (dsl)
    accept
    create
    delete
    destroy
    drop
    flush
    flushChain
    flushMap
    flushRuleset
    flushSet
    flushTable
    list
    reset
    ruleset
    ;

  tableScope = {
    family = "ip";
    table = "t";
  };
  tableIdentity = {
    family = "ip";
    name = "t";
  };
in
rec {
  cases = [
    # -- create: supported object kinds ------------------------------------
    # `create.rule` is excluded from the DSL (nftables rejects it).
    # `tunnel` and `secmark` kinds need kernel features the sandbox may
    # lack, so they're exercised only via the schema unit suite.
    {
      name = "create-supported-kinds";
      ruleset = ruleset [
        flush
        (create.table tableIdentity)
        (create.chain (
          tableScope
          // {
            name = "c";
            type = "filter";
            hook = "input";
            prio = 0;
          }
        ))
        (create.counter (tableScope // { name = "ctr"; }))
        (create.quota (
          tableScope
          // {
            name = "q";
            bytes = 1000000;
          }
        ))
        (create.limit (
          tableScope
          // {
            name = "lim";
            rate = 5;
            per = "second";
            inv = true;
            burst = 10;
          }
        ))
        (create.set (
          tableScope
          // {
            name = "s";
            type = "ipv4_addr";
          }
        ))
        (create.map (
          tableScope
          // {
            name = "m";
            type = "inet_service";
            map = "inet_service";
          }
        ))
        (create.element (
          tableScope
          // {
            name = "s";
            elements = [ "1.2.3.4" ];
          }
        ))
        (create.flowtable (
          tableScope
          // {
            name = "ft";
            hook = "ingress";
            prio = 0;
            dev = [ "lo" ];
          }
        ))
        (create.ctHelper (
          tableScope
          // {
            name = "h";
            type = "ftp";
            protocol = "tcp";
            l3proto = "ip";
          }
        ))
        (create.ctTimeout (
          tableScope
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
          tableScope
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
          tableScope
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
        (create.table tableIdentity)
        (create.chain (tableScope // { name = "c"; }))
        (create.counter (tableScope // { name = "ctr"; }))
        (create.quota (
          tableScope
          // {
            name = "q";
            bytes = 1;
          }
        ))
        (create.limit (
          tableScope
          // {
            name = "lim";
            rate = 1;
            per = "second";
          }
        ))
        (create.set (
          tableScope
          // {
            name = "s";
            type = "ipv4_addr";
          }
        ))
        (create.map (
          tableScope
          // {
            name = "m";
            type = "inet_service";
            map = "inet_service";
          }
        ))
        (create.flowtable (
          tableScope
          // {
            name = "ft";
            hook = "ingress";
            prio = 0;
            dev = [ "lo" ];
          }
        ))
        (create.ctHelper (
          tableScope
          // {
            name = "h";
            type = "ftp";
            protocol = "tcp";
            l3proto = "ip";
          }
        ))
        (create.synproxy (
          tableScope
          // {
            name = "sp";
            mss = 1460;
            wscale = 7;
          }
        ))
        # Now delete. set/map still need `type` per the shared schema.
        (delete.counter (tableScope // { name = "ctr"; }))
        (delete.quota (
          tableScope
          // {
            name = "q";
            bytes = 1;
          }
        ))
        (delete.limit (
          tableScope
          // {
            name = "lim";
            rate = 1;
            per = "second";
          }
        ))
        (delete.set (
          tableScope
          // {
            name = "s";
            type = "ipv4_addr";
          }
        ))
        (delete.map (
          tableScope
          // {
            name = "m";
            type = "inet_service";
            map = "inet_service";
          }
        ))
        (delete.flowtable (
          tableScope
          // {
            name = "ft";
            hook = "ingress";
            prio = 0;
            dev = [ "lo" ];
          }
        ))
        (delete.ctHelper (
          tableScope
          // {
            name = "h";
            type = "ftp";
            protocol = "tcp";
            l3proto = "ip";
          }
        ))
        (delete.synproxy (
          tableScope
          // {
            name = "sp";
            mss = 1460;
            wscale = 7;
          }
        ))
        (delete.chain (tableScope // { name = "c"; }))
        (delete.table tableIdentity)
      ];
    }

    # -- destroy (idempotent) --------------------------------------------
    # Destroy succeeds whether the object exists or not.
    {
      name = "destroy-idempotent";
      ruleset = ruleset [
        flush
        (create.table tableIdentity)
        (create.chain (tableScope // { name = "c"; }))
        (create.counter (tableScope // { name = "ctr"; }))
        (destroy.counter (tableScope // { name = "ctr"; }))
        (destroy.counter (tableScope // { name = "never_existed"; }))
        (destroy.chain (tableScope // { name = "c"; }))
        (destroy.chain (tableScope // { name = "also_never"; }))
        (destroy.table tableIdentity)
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
        (create.table tableIdentity)
        (create.chain (tableScope // { name = "c"; }))
        (create.set (
          tableScope
          // {
            name = "s";
            type = "ipv4_addr";
          }
        ))
        (create.map (
          tableScope
          // {
            name = "m";
            type = "inet_service";
            map = "inet_service";
          }
        ))
        (flushChain (tableScope // { name = "c"; }))
        (flushSet (
          tableScope
          // {
            name = "s";
            type = "ipv4_addr";
          }
        ))
        (flushMap (
          tableScope
          // {
            name = "m";
            type = "inet_service";
            map = "inet_service";
          }
        ))
        (flushTable tableIdentity)
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
        (create.table tableIdentity)
        (list.table tableIdentity)
      ];
    }

    # -- reset counters / quotas -----------------------------------------
    # Reset works for counter, quota, set (zero elements), map. Rule reset
    # needs an existing rule handle from the kernel.
    {
      name = "reset-counters-and-quotas";
      ruleset = ruleset [
        flush
        (create.table tableIdentity)
        (create.counter (tableScope // { name = "ctr"; }))
        (create.quota (
          tableScope
          // {
            name = "q";
            bytes = 1;
          }
        ))
        (reset.counter (tableScope // { name = "ctr"; }))
        (reset.quota (
          tableScope
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
      ruleset = examples.basicFirewallDsl;
    }
    {
      name = "example-home-router-dsl";
      ruleset = examples.homeRouterDsl;
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
  # package set's live JSON parser remains the behavioral oracle.
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
  # against the stable and unstable nixpkgs package sets by tests/default.nix.

  # Cases the nft text grammar can't represent. The JSON renderer
  # accepts them; this is a hard text-grammar limitation in nftables.
  knownTextLimitations = [
    # `offload` is a reserved keyword in flowtable name and `flow add`
    # reference positions. The home-router example's flowtable is named
    # "offload" and is referenced from `flow add @offload`; nft -c -f
    # rejects both. Verified against the upstream parser_bison.y
    # grammar.
    "example-home-router-dsl"

    # `add rule … handle 42 …` resolves the handle against existing
    # kernel state. Inside the unprivileged sandbox there's no rule
    # with handle 42, so nft fails with "Could not process rule: No
    # such file or directory". The JSON path works because nft -c -j
    # tolerates the dangling handle in check-only mode while nft -c
    # (text) doesn't.
    "add-rule-via-tree-and-standalone"
  ];
  textCases = builtins.filter (c: !(builtins.elem c.name knownTextLimitations)) cases;

  # Cases where actual loading (`nft -f` instead of `nft -c -f`) needs
  # kernel state the unprivileged netns lacks, or whose `nft list
  # ruleset` produces non-deterministic output (rule order, counter
  # ordering, etc.). These are above and beyond the text-only
  # limitations.
  knownLoadLimitations = [
    # `list table` can't be loaded — it's a query, not a definition.
    "list-table"
    # ct timeout / ct expectation / synproxy in create require kernel
    # features the sandbox often lacks; skip rather than chase
    # environment-specific failures.
    "create-supported-kinds"
    "delete-supported-kinds"
  ];
  equivalenceCases = builtins.filter (
    c: !(builtins.elem c.name (knownTextLimitations ++ knownLoadLimitations))
  ) cases;

  # Text cases that only `nft -c -f` can check. A real load (render
  # equivalence) runs every check-mode validation before committing, so
  # check mode adds nothing for the cases render equivalence loads.
  textCheckOnlyCases = builtins.filter (c: builtins.elem c.name knownLoadLimitations) textCases;

  /*
    Cases that cannot be really loaded (as opposed to `nft -c` checked)
    in an unprivileged netns, with the observed reason. Everything not
    listed here is expected to load; an unexpected load failure fails the
    round trip instead of silently reducing its coverage.
  */
  knownNoLoad = {
    "add-rule-via-tree-and-standalone" =
      "uses `handle 42`, which real-load validates against live kernel state";
    "example-home-router-dsl" =
      "flowtable `flags offload` is rejected on dummy devices — real-load fails with 'Operation not supported'";
  };
  roundtripCases = builtins.filter (c: !(knownNoLoad ? ${c.name})) cases;
}
