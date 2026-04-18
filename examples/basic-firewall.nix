{ nftlib }:

# A realistic inet-family firewall demonstrating: table/chain, named set of
# IPv4 prefixes, named map for port forwarding, SNAT+DNAT, reject with icmp
# code, logging, and a vmap dispatching on input interface.
let
  tableName = "main";

  match = lhs: op: rhs: {
    match = {
      left = lhs;
      right = rhs;
      inherit op;
    };
  };

  payload = protocol: field: { payload = { inherit protocol field; }; };
  meta = key: { meta = { inherit key; }; };
  prefix = addr: len: { prefix = { inherit addr len; }; };
in
{
  nftables = [
    {
      flush = {
        ruleset = null;
      };
    }

    {
      add = {
        table = {
          family = "inet";
          name = tableName;
        };
      };
    }

    # Named set of trusted IPv4 subnets
    {
      add = {
        set = {
          family = "inet";
          table = tableName;
          name = "trusted_v4";
          type = "ipv4_addr";
          flags = [ "interval" ];
          elem = [
            (prefix "10.0.0.0" 8)
            (prefix "192.168.0.0" 16)
          ];
        };
      };
    }

    # Named map: external-port → internal-port (same host)
    {
      add = {
        map = {
          family = "inet";
          table = tableName;
          name = "port_forward";
          type = "inet_service";
          map = "inet_service";
          elem = [
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
      };
    }

    # Input chain
    {
      add = {
        chain = {
          family = "inet";
          table = tableName;
          name = "input";
          type = "filter";
          hook = "input";
          prio = 0;
          policy = "drop";
        };
      };
    }

    # Established connections bypass everything
    {
      add = {
        rule = {
          family = "inet";
          table = tableName;
          chain = "input";
          expr = [
            (match
              {
                ct = {
                  key = "state";
                };
              }
              "in"
              {
                set = [
                  "established"
                  "related"
                ];
              }
            )
            { accept = null; }
          ];
        };
      };
    }

    # Trusted subnets → accept
    {
      add = {
        rule = {
          family = "inet";
          table = tableName;
          chain = "input";
          expr = [
            (match (payload "ip" "saddr") "==" "@trusted_v4")
            {
              counter = {
                packets = 0;
                bytes = 0;
              };
            }
            { accept = null; }
          ];
        };
      };
    }

    # Rate-limited SSH
    {
      add = {
        rule = {
          family = "inet";
          table = tableName;
          chain = "input";
          expr = [
            (match (payload "tcp" "dport") "==" 22)
            {
              limit = {
                rate = 10;
                per = "minute";
                burst = 5;
              };
            }
            { accept = null; }
          ];
        };
      };
    }

    # Reject everything else from the outside with an icmp code
    {
      add = {
        rule = {
          family = "inet";
          table = tableName;
          chain = "input";
          expr = [
            {
              log = {
                prefix = "DROPPED: ";
                level = "info";
              };
            }
            {
              reject = {
                type = "icmpx";
                expr = "admin-prohibited";
              };
            }
          ];
        };
      };
    }

    # NAT chains
    {
      add = {
        chain = {
          family = "inet";
          table = tableName;
          name = "prerouting";
          type = "nat";
          hook = "prerouting";
          prio = -100;
          policy = "accept";
        };
      };
    }

    {
      add = {
        chain = {
          family = "inet";
          table = tableName;
          name = "postrouting";
          type = "nat";
          hook = "postrouting";
          prio = 100;
          policy = "accept";
        };
      };
    }

    # DNAT: forward external port → internal port via map lookup
    {
      add = {
        rule = {
          family = "inet";
          table = tableName;
          chain = "prerouting";
          expr = [
            (match (payload "ip" "daddr") "==" "203.0.113.1")
            {
              dnat = {
                family = "ip";
                addr = "10.0.0.10";
                port = {
                  map = {
                    key = payload "tcp" "dport";
                    data = "@port_forward";
                  };
                };
              };
            }
          ];
        };
      };
    }

    # SNAT on egress
    {
      add = {
        rule = {
          family = "inet";
          table = tableName;
          chain = "postrouting";
          expr = [
            (match (meta "oifname") "==" "eth0")
            {
              snat = {
                family = "ip";
                addr = "203.0.113.1";
              };
            }
          ];
        };
      };
    }
  ];
}
