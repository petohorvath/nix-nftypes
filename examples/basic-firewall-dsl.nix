{ nftlib }:

# Realistic inet-family firewall written against the `dsl` layer.
# Demonstrates: path-based field access, top-level operators, variant
# namespaces (counter, log, reject), and the declarative table structure
# (no context threading, chains live under `chains.<name>`).
#
# Compare with `examples/basic-firewall.nix` for the hand-written raw-attrset
# equivalent, and `examples/home-router-dsl.nix` for a more comprehensive DSL
# showcase.

let
  inherit (nftlib.dsl)
    ruleset
    flush
    table
    eq
    inSet
    accept
    counter
    limit
    log
    reject
    dnat
    snat
    ;
  inherit (nftlib.dsl.fields)
    tcp
    ip
    ct
    meta
    ;
  inherit (nftlib.dsl.expr) prefix map;
in
ruleset [
  flush

  (table "inet" "main" {
    sets.trusted_v4 = {
      type = "ipv4_addr";
      flags = [ "interval" ];
      elements = [
        (prefix "10.0.0.0" 8)
        (prefix "192.168.0.0" 16)
      ];
    };

    maps.port_forward = {
      type = "inet_service";
      map = "inet_service";
      elements = [
        [
          80
          8080
        ]
        [
          443
          8443
        ]
      ];
    };

    chains.input = {
      type = "filter";
      hook = "input";
      prio = 0;
      policy = "drop";
      rules = [
        # Established connections bypass everything
        [
          (inSet ct.state [
            "established"
            "related"
          ])
          accept
        ]

        # Trusted subnets → accept (with a counter)
        [
          (eq ip.saddr "@trusted_v4")
          (counter {
            packets = 0;
            bytes = 0;
          })
          accept
        ]

        # Rate-limited SSH
        [
          (eq tcp.dport 22)
          (limit {
            rate = 10;
            per = "minute";
            burst = 5;
          })
          accept
        ]

        # Log and reject everything else
        [
          (log {
            prefix = "DROPPED: ";
            level = "info";
          })
          (reject.icmpx "admin-prohibited")
        ]
      ];
    };

    chains.prerouting = {
      type = "nat";
      hook = "prerouting";
      prio = -100;
      policy = "accept";
      rules = [
        # DNAT: forward external port → internal port via map lookup
        [
          (eq ip.daddr "203.0.113.1")
          (dnat {
            family = "ip";
            addr = "10.0.0.10";
            port = map {
              key = tcp.dport;
              data = "@port_forward";
            };
          })
        ]
      ];
    };

    chains.postrouting = {
      type = "nat";
      hook = "postrouting";
      prio = 100;
      policy = "accept";
      rules = [
        # SNAT on egress
        [
          (eq meta.oifname "eth0")
          (snat {
            family = "ip";
            addr = "203.0.113.1";
          })
        ]
      ];
    };
  })
]
