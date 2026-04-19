{ nftlib }:

# Realistic home-router firewall demonstrating the `dsl` layer under load:
#
#   - Two tables in one atomic submission (inet filter + ip nat)
#   - Named sets with three flag combinations: interval, interval+timeout,
#     dynamic+timeout
#   - Named counters referenced from rules by name
#   - Named limit object reused across rules
#   - Flowtable for kernel flow-offload, referenced by a `flow` statement
#   - Verdict map dispatching input by interface to per-zone sub-chains
#   - Five base chains across both tables plus two regular sub-chains
#   - Concatenated-key port-forward map: (ext-ip, dport) → (int-ip, dport)
#   - Rate-limited SSH, ICMP shaping, anti-bruteforce blocklist, logging
#
# This renders byte-identical JSON to a hand-written form and is accepted by
# `nft -c -j -f`. Compare with examples/basic-firewall-dsl.nix for the
# minimal version.

let
  inherit (nftlib.dsl)
    ruleset
    flush
    table
    eq
    inSet
    accept
    drop
    jump
    counter
    limit
    log
    reject
    masquerade
    dnat
    flow
    vmap
    ;
  inherit (nftlib.dsl.fields)
    tcp
    ip
    icmp
    ct
    meta
    ;
  inherit (nftlib.dsl.expr)
    concat
    prefix
    ;

  mapLookup = nftlib.dsl.expr.map;
in
ruleset [
  flush

  # -------------------------------------------------------------------------
  # Filter table (inet family) — packet acceptance/rejection
  # -------------------------------------------------------------------------
  (table "inet" "firewall" {
    comment = "main packet filter";

    # Named sets ------------------------------------------------------------

    # Static list of trusted LAN subnets.
    sets.trusted_lan = {
      type = "ipv4_addr";
      flags = [ "interval" ];
      elements = [
        (prefix "10.0.0.0" 8)
        (prefix "192.168.0.0" 16)
      ];
    };

    # Manually-populated blocklist with per-entry TTL.
    sets.blocked_v4 = {
      type = "ipv4_addr";
      flags = [
        "interval"
        "timeout"
      ];
      timeout = 3600;
      elements = [ "198.51.100.7" ];
    };

    # Dynamic set populated by a `set` statement on bruteforce hits; entries
    # expire automatically after 1 minute.
    sets.ssh_bruteforce = {
      type = "ipv4_addr";
      flags = [
        "dynamic"
        "timeout"
      ];
      timeout = 60;
      size = 65536;
    };

    # Named counters -------------------------------------------------------

    counters.pkts_accepted = { };
    counters.pkts_dropped = { };

    # Named limit object (shared between several rules) --------------------

    limits.slow = {
      rate = 5;
      per = "second";
      burst = 10;
    };

    # Flowtable for kernel flow-offload ------------------------------------

    flowtables.offload = {
      hook = "ingress";
      prio = 0;
      dev = [ "eth0" "eth1" ];
    };

    # Verdict map: iifname → per-zone sub-chain ---------------------------

    maps.iif_zone = {
      type = "ifname";
      map = "verdict";
      elements = [
        [ "eth0" (jump "zone_wan") ]
        [ "eth1" (jump "zone_lan") ]
      ];
    };

    # Chains ---------------------------------------------------------------

    chains.input = {
      type = "filter";
      hook = "input";
      prio = 0;
      policy = "drop";
      rules = [
        # Fast path: established/related with kernel flow-offload
        [
          (inSet ct.state [
            "established"
            "related"
          ])
          (flow { flowtable = "@offload"; })
          (counter.ref "pkts_accepted")
          accept
        ]

        # Loopback always allowed
        [
          (eq meta.iifname "lo")
          accept
        ]

        # Hard-blocked source IPs
        [
          (inSet ip.saddr "@blocked_v4")
          (counter.ref "pkts_dropped")
          drop
        ]

        # ICMP: rate-limited
        [
          (eq ip.protocol "icmp")
          (limit.ref "slow")
          accept
        ]

        # Per-interface dispatch
        [ (vmap meta.iifname "@iif_zone") ]

        # Default: log and reject
        [
          (log {
            prefix = "DROP-IN: ";
            level = "info";
          })
          (reject.icmpx "admin-prohibited")
        ]
      ];
    };

    chains.zone_lan = {
      rules = [
        # Trusted subnets → accept anything
        [
          (inSet ip.saddr "@trusted_lan")
          accept
        ]
        # SSH from LAN
        [
          (eq tcp.dport 22)
          accept
        ]
      ];
    };

    chains.zone_wan = {
      rules = [
        # SSH bruteforce guard: already-flagged source IPs get dropped
        [
          (eq tcp.dport 22)
          (inSet ip.saddr "@ssh_bruteforce")
          (log {
            prefix = "SSH-BF: ";
            level = "warn";
          })
          drop
        ]

        # SSH with a shared rate limit
        [
          (eq tcp.dport 22)
          (limit.ref "slow")
          accept
        ]

        # Public web
        [
          (inSet tcp.dport [ 80 443 ])
          accept
        ]
      ];
    };

    chains.forward = {
      type = "filter";
      hook = "forward";
      prio = 0;
      policy = "drop";
      rules = [
        # Established flows bypass the filter via offload
        [
          (inSet ct.state [
            "established"
            "related"
          ])
          (flow { flowtable = "@offload"; })
          accept
        ]
        # Outbound from LAN
        [
          (eq meta.iifname "eth1")
          accept
        ]
      ];
    };

    chains.output = {
      type = "filter";
      hook = "output";
      prio = 0;
      policy = "accept";
      rules = [ ];
    };
  })

  # -------------------------------------------------------------------------
  # NAT table (ip family) — address translation
  # -------------------------------------------------------------------------
  (table "ip" "nat" {
    # Port-forward: (external addr, tcp dport) → (internal addr, dport)
    maps.port_forward = {
      type = [
        "ipv4_addr"
        "inet_service"
      ];
      map = [
        "ipv4_addr"
        "inet_service"
      ];
      flags = [ "interval" ];
      elements = [
        [
          (concat [ "203.0.113.1" 80 ])
          (concat [ "192.168.1.10" 8080 ])
        ]
        [
          (concat [ "203.0.113.1" 443 ])
          (concat [ "192.168.1.10" 8443 ])
        ]
      ];
    };

    chains.prerouting = {
      type = "nat";
      hook = "prerouting";
      prio = -100;
      policy = "accept";
      rules = [
        # DNAT any matching (daddr, dport) pair to the mapped internal host
        [
          (eq ip.protocol "tcp")
          (dnat {
            family = "ip";
            addr = mapLookup {
              key = concat [
                ip.daddr
                tcp.dport
              ];
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
        # SNAT egress from all non-WAN interfaces
        [
          (eq meta.oifname "eth0")
          (masquerade { })
        ]
      ];
    };
  })
]
