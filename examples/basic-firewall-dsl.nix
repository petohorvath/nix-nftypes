{ nftlib }:

# basic-firewall.nix rewritten against the DSL. Renders byte-identical JSON
# to the hand-written form (the parity test in tests/default.nix asserts
# this).

let
  inherit (nftlib.dsl) expr stmt;
  inherit (nftlib.dsl)
    mkRuleset
    mkTable
    mkChain
    declareChain
    mkRule
    mkSet
    mkMap
    inChain
    flushRuleset
    ;

  tableName = "main";
in
mkRuleset [
  flushRuleset

  (mkTable { family = "inet"; name = tableName; } [
    # Named set of trusted IPv4 subnets
    (mkSet {
      name = "trusted_v4";
      type = "ipv4_addr";
      flags = [ "interval" ];
      elem = [
        (expr.prefix "10.0.0.0" 8)
        (expr.prefix "192.168.0.0" 16)
      ];
    })

    # Named map: external-port → internal-port (same host)
    (mkMap {
      name = "port_forward";
      type = "inet_service";
      map = "inet_service";
      elem = [
        [ 80 8080 ]
        [ 443 8443 ]
      ];
    })

    # Input chain with all its rules
    (mkChain
      {
        name = "input";
        type = "filter";
        hook = "input";
        prio = 0;
        policy = "drop";
      }
      [
        # Established connections bypass everything
        (mkRule [
          (stmt.matchIn (expr.ct { key = "state"; }) (expr.set [
            "established"
            "related"
          ]))
          stmt.accept
        ])

        # Trusted subnets → accept
        (mkRule [
          (stmt.matchEq (expr.payload "ip" "saddr") "@trusted_v4")
          (stmt.counter {
            packets = 0;
            bytes = 0;
          })
          stmt.accept
        ])

        # Rate-limited SSH
        (mkRule [
          (stmt.matchEq (expr.payload "tcp" "dport") 22)
          (stmt.limit {
            rate = 10;
            per = "minute";
            burst = 5;
          })
          stmt.accept
        ])

        # Reject everything else from the outside with an icmp code
        (mkRule [
          (stmt.log {
            prefix = "DROPPED: ";
            level = "info";
          })
          (stmt.rejectIcmpx "admin-prohibited")
        ])
      ]
    )

    # NAT chains declared up-front; rules appended below so the emitted order
    # matches the hand-written example (chain adds, then rule adds).
    (declareChain {
      name = "prerouting";
      type = "nat";
      hook = "prerouting";
      prio = -100;
      policy = "accept";
    })

    (declareChain {
      name = "postrouting";
      type = "nat";
      hook = "postrouting";
      prio = 100;
      policy = "accept";
    })

    # DNAT: forward external port → internal port via map lookup
    (inChain "prerouting" [
      (mkRule [
        (stmt.matchEq (expr.payload "ip" "daddr") "203.0.113.1")
        (stmt.dnat {
          family = "ip";
          addr = "10.0.0.10";
          port = expr.map {
            key = expr.payload "tcp" "dport";
            data = "@port_forward";
          };
        })
      ])
    ])

    # SNAT on egress
    (inChain "postrouting" [
      (mkRule [
        (stmt.matchEq (expr.meta "oifname") "eth0")
        (stmt.snat {
          family = "ip";
          addr = "203.0.113.1";
        })
      ])
    ])
  ])
]
