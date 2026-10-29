/*
  Rulesets for the live-parser probes and their nix-unit suites. Each case
  renders to JSON (and, unless excluded, to text) and is fed to the
  package set's real `nft` inside a private network namespace.

  Each namespace starts empty. A command that names an object loaded
  before its batch, such as `rename chain`, `replace rule`, or `list set`,
  takes it from the case's `state`.

  These cases exist to catch the categories of bug the schema can't:
  forward-reference resolution, argument formats libnftables actually
  accepts, subtle divergences from the adoc.
*/
{
  blockTables,
  dsl,
  exampleChildren,
  examples,
  lib,
}:
let
  inherit (dsl)
    accept
    create
    delete
    destroy
    drop
    flush
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
  # A table that a case creates only to delete or destroy it.
  goneTable = tableIdentity // {
    name = "gone";
  };

  inherit (dsl.fields)
    ct
    ip
    meta
    tcp
    ;

  # Sets and a map whose elements count, and a meter, for the reset cases.
  counterSets = ''
    table ip t {
      set a {
        type ipv4_addr
        counter
        elements = { 10.0.0.1 counter packets 1 bytes 2,
                     10.0.0.2 counter packets 3 bytes 4 }
      }
      set b {
        type ipv4_addr
        counter
        elements = { 10.0.0.3 counter packets 5 bytes 6 }
      }
      map m {
        type ipv4_addr : mark
        counter
        elements = { 10.0.0.4 counter packets 7 bytes 8 : 1 }
      }
      chain c {
        meter flood { ip saddr limit rate 10/second }
      }
    }
  '';

  # `==` matches on every right-hand shape except a bitmask.
  shapeMatches =
    let
      inherit (dsl.expr)
        concat
        prefix
        range
        set
        setRef
        ;
    in
    [
      (dsl.eq tcp.dport 22)
      (dsl.eq ip.saddr (prefix "10.0.0.0" 8))
      (dsl.eq tcp.dport (range 1024 65535))
      (dsl.eq tcp.dport (set [
        22
        80
      ]))
      (dsl.eq ip.saddr (setRef "allowed"))
      (dsl.eq
        (concat [
          ip.saddr
          tcp.dport
        ])
        (set [
          (concat [
            "192.0.2.1"
            22
          ])
        ])
      )
    ];

  # Bitmask matches, each written with both `==` and `in`.
  bitmaskMatches = [
    {
      left = tcp.flags;
      right = "syn";
    }
    {
      left = tcp.flags;
      right = dsl.expr.bitOr "syn" "ack";
    }
    {
      left = ct.state;
      right = "established";
    }
    {
      left = ct.state;
      right = dsl.expr.bitOr "established" "related";
    }
    {
      left = ct.status;
      right = "dnat";
    }
  ];

  # A TCP rule: NAT and tproxy to a port need a transport protocol match.
  tcpRule = statement: [
    (dsl.eq meta.l4proto "tcp")
    statement
  ];

  # `meta mark set <value>` for each binary-operator nesting.
  markValues =
    let
      inherit (dsl.expr)
        bitAnd
        bitOr
        bitXor
        shiftLeft
        shiftRight
        ;
      inherit (meta) mark;
    in
    [
      # A right operand at the parent's precedence, for every operator.
      (shiftLeft mark (shiftLeft 1 2))
      (shiftRight mark (shiftRight 8 1))
      (shiftLeft mark (shiftRight 4 2))
      (shiftRight mark (shiftLeft 4 2))
      (bitAnd mark (bitAnd 255 15))
      (bitXor mark (bitXor 1 2))
      (bitOr mark (bitOr 1 2))
      # A left operand at the parent's precedence.
      (shiftRight (shiftLeft mark 4) 2)
      # An operand list folds left, so only the first operand shares it.
      {
        "<<" = [
          mark
          1
          (shiftRight 4 1)
        ];
      }
      # Each pair of adjacent levels, the lower one inside, on either side.
      (bitXor (bitOr mark 1) 3)
      (bitXor mark (bitOr 1 2))
      (bitAnd (bitXor mark 1) 3)
      (bitAnd mark (bitXor 1 2))
      (shiftLeft (bitAnd mark 255) 1)
      (shiftLeft mark (bitAnd 7 3))
      # The higher one inside, which needs no parentheses.
      (bitOr (bitXor mark 1) 3)
      (bitXor (bitAnd mark 3) 1)
      (bitAnd (shiftLeft mark 1) 255)
    ];

  # Interface names that bare text loaded as something else or couldn't
  # parse: `010` loaded as 8, `0x10` as 16, `a|b` as `c`, `$lan` took a
  # `define`, and `1e5` and `-x` didn't parse.
  ifnameValues = [
    "eth0"
    "010"
    "0x10"
    "a|b"
    "$lan"
    "1e5"
    "-x"
  ];

  # Each interface name paired with an address, for concatenations.
  ifnameAddressPairs = map (
    name:
    dsl.expr.concat [
      name
      "192.0.2.1"
    ]
  ) ifnameValues;

  # Each interface name mapped to its position, for maps.
  ifnameMarks = lib.imap1 (index: name: [
    name
    index
  ]) ifnameValues;
in
rec {
  /*
    Each case has a `name` and either `children`, the list `dsl.ruleset`
    takes, or a finished `ruleset`. `children` also gives the case a block
    form in Render equivalence (./render-equivalence.nix). Optional
    attributes:
    - `interfaces`: dummy links the namespace needs, for device references;
    - `rejectedBefore`: the first nft version that accepts the case; the
      live suites expect older versions to reject it (ADR 0010);
    - `textDefines`: nft `define`s that each text form starts with, as a
      host's surrounding text might (JSON has none);
    - `state`: nft text that every run of the case loads first, for an
      object no form can create, such as a tunnel, whose ports nft's JSON
      parser loads wrongly. Its listing is part of every form's.
  */
  cases = map (case: { ruleset = ruleset case.children; } // case) (
    caseDefinitions ++ blockTableCases
  );

  # The block-form parity tables, loaded in all four forms.
  blockTableCases = map (name: {
    inherit name;
    children = [ blockTables.integrationTables.${name} ];
  }) (builtins.attrNames blockTables.integrationTables);

  caseDefinitions = [
    # -- create: supported object kinds ------------------------------------
    # `create.rule` is excluded from the DSL (nftables rejects it).
    # The `secmark` kind needs kernel features the sandbox may lack, so
    # it's exercised only via the schema unit suite. The DSL has no tunnel
    # builder.
    {
      name = "create-supported-kinds";
      ruleset = ruleset [
        (flush.ruleset { })
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

    # -- add (via table tree + add.rule) -----------------------------------
    # The declarative table tree emits `add rule` commands for every entry
    # in `chains.*.rules`. Also exercises `add.rule` for a standalone rule.
    # It has no explicit handle: nft resolves `handle N` against live
    # kernel state, and no rule exists to resolve it against. The parity
    # suites cover handles.
    {
      name = "add-rule-via-tree-and-standalone";
      children = [
        (flush.ruleset { })
        (dsl.table "ip" "t" {
          chains.c = {
            rules = [
              [ accept ]
              [ drop ]
            ];
          };
        })
        (dsl.add.rule {
          family = "ip";
          table = "t";
          chain = "c";
          statements = [ accept ];
        })
      ];
    }

    # -- delete: supported kinds ------------------------------------------
    # Prelude adds each object, then the same kind is deleted in the same
    # batch. Table `t` and set `kept` stay, so the listing shows what the
    # deletes left. The schema rejects delete of a ct timeout or ct
    # expectation, which nft mishandles, and a secmark loads only on an
    # SELinux kernel (docs/spec-coverage.md).
    {
      name = "delete-supported-kinds";
      ruleset = ruleset [
        (flush.ruleset { })
        (create.table tableIdentity)
        (create.table goneTable)
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
        (create.set (
          tableScope
          // {
            name = "kept";
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
        # Now delete. Each object is selected by name alone.
        (delete.counter (tableScope // { name = "ctr"; }))
        (delete.quota (tableScope // { name = "q"; }))
        (delete.limit (tableScope // { name = "lim"; }))
        (delete.set (tableScope // { name = "s"; }))
        (delete.map (tableScope // { name = "m"; }))
        (delete.flowtable (tableScope // { name = "ft"; }))
        (delete.ctHelper (tableScope // { name = "h"; }))
        (delete.synproxy (tableScope // { name = "sp"; }))
        (delete.chain (tableScope // { name = "c"; }))
        (delete.table goneTable)
      ];
    }

    # -- destroy (idempotent) --------------------------------------------
    # Destroy succeeds whether the object exists or not. Table `t` and
    # counter `kept` stay, so the listing shows what the destroys left.
    {
      name = "destroy-idempotent";
      ruleset = ruleset [
        (flush.ruleset { })
        (create.table tableIdentity)
        (create.table goneTable)
        (create.chain (tableScope // { name = "c"; }))
        (create.counter (tableScope // { name = "ctr"; }))
        (create.counter (tableScope // { name = "kept"; }))
        (create.quota (
          tableScope
          // {
            name = "q";
            bytes = 1;
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
        (destroy.counter (tableScope // { name = "ctr"; }))
        (destroy.quota (tableScope // { name = "q"; }))
        (destroy.map (tableScope // { name = "m"; }))
        (destroy.flowtable (tableScope // { name = "ft"; }))
        (destroy.ctHelper (tableScope // { name = "h"; }))
        (destroy.synproxy (tableScope // { name = "sp"; }))
        (destroy.counter (tableScope // { name = "never_existed"; }))
        (destroy.set (tableScope // { name = "never_set"; }))
        (destroy.limit (tableScope // { name = "never_limit"; }))
        # Absent, so no SELinux context is needed (docs/spec-coverage.md).
        (destroy.secmark (tableScope // { name = "never_secmark"; }))
        (destroy.chain (tableScope // { name = "c"; }))
        (destroy.chain (tableScope // { name = "also_never"; }))
        (destroy.table goneTable)
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
        (flush.ruleset { })
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
        (flush.chain (tableScope // { name = "c"; }))
        (flush.set (tableScope // { name = "s"; }))
        (flush.map (tableScope // { name = "m"; }))
        (flush.table tableIdentity)
      ];
    }

    # -- flush.ruleset with family scope ---------------------------------
    # Only the ip6 table, of another family, stays.
    {
      name = "flush-ruleset-by-family";
      ruleset = ruleset [
        (flush.ruleset { })
        (create.table tableIdentity)
        (create.table (tableIdentity // { family = "inet"; }))
        (create.table (tableIdentity // { family = "ip6"; }))
        (flush.ruleset { family = "ip"; })
        (flush.ruleset { family = "inet"; })
      ];
    }

    # -- standalone elements after set ----------------------------------
    # `add.element` adds an element to a set that the table tree before it
    # defines; nft reports ENOENT when the commands are reversed.
    {
      name = "standalone-elements-after-set";
      children = [
        (dsl.table "inet" "element_order" {
          sets.blocked = {
            type = "ipv4_addr";
          };
        })
        (dsl.add.element {
          family = "inet";
          table = "element_order";
          name = "blocked";
          elements = [ "192.0.2.1" ];
        })
      ];
    }

    # -- list.table ------------------------------------------------------
    # A table the same batch creates. `list-commands` lists loaded objects
    # of the other kinds.
    {
      name = "list-table";
      ruleset = ruleset [
        (flush.ruleset { })
        (create.table tableIdentity)
        (list.table tableIdentity)
      ];
    }

    # -- reset counters / quotas -----------------------------------------
    # nft runs a reset of a stateful object only as a batch's last command
    # (docs/spec-coverage.md), so each reset is a case of its own. The
    # state's counts show it ran.
    {
      name = "reset-counter";
      state = ''
        add table ip t
        add counter ip t ctr { packets 1 bytes 2; }
      '';
      ruleset = ruleset [ (reset.counter (tableScope // { name = "ctr"; })) ];
    }
    {
      name = "reset-quota";
      state = ''
        add table ip t
        add quota ip t q { 100 bytes used 10 bytes; }
      '';
      ruleset = ruleset [
        (reset.quota (
          tableScope
          // {
            name = "q";
            bytes = 100;
          }
        ))
      ];
    }

    # -- stateful statements selecting a named object by map -------------
    # `counter`/`quota`/`limit` reference their object through a map
    # lookup (`counter name tcp dport map { … }`).
    {
      name = "stateful-map-references";
      children =
        let
          byPort = names: {
            map = {
              key.payload = {
                protocol = "tcp";
                field = "dport";
              };
              data.set = [
                [
                  22
                  (builtins.elemAt names 0)
                ]
                [
                  80
                  (builtins.elemAt names 1)
                ]
              ];
            };
          };
        in
        [
          (dsl.table "ip" "stateful_maps" {
            counters = {
              ssh = { };
              http = { };
            };
            quotas = {
              ssh.bytes = 1000;
              http.bytes = 2000;
            };
            limits = {
              ssh = {
                rate = 5;
                per = "second";
              };
              http = {
                rate = 10;
                per = "second";
              };
            };
            chains.input = {
              type = "filter";
              hook = "input";
              prio = 0;
              rules = [
                [
                  {
                    counter = byPort [
                      "ssh"
                      "http"
                    ];
                  }
                ]
                [
                  {
                    quota = byPort [
                      "ssh"
                      "http"
                    ];
                  }
                ]
                [
                  {
                    limit = byPort [
                      "ssh"
                      "http"
                    ];
                  }
                ]
              ];
            };
          })
        ];
    }

    # -- table options -------------------------------------------------
    # Block form must keep the table's flags and comment: without
    # `flags dormant`, the table would load active.
    {
      name = "dormant-table-with-comment";
      children = [
        (dsl.table "ip" "t" {
          flags = [ "dormant" ];
          comment = "kept";
          chains.c = {
            type = "filter";
            hook = "input";
            prio = 0;
            rules = [ [ accept ] ];
          };
        })
      ];
    }

    # -- match operators -------------------------------------------------
    # JSON `==` is an exact match and `in` an any-bit test. They differ
    # only on bitmasks, where text must write `==` to keep the exact
    # match, so every bitmask rule comes in both ops.
    {
      name = "match-eq-bitmask";
      children = [
        (dsl.table "inet" "t" {
          chains.c.rules = map (match: [
            (dsl.eq match.left match.right)
            accept
          ]) bitmaskMatches;
        })
      ];
    }
    {
      name = "match-in-bitmask";
      children = [
        (dsl.table "inet" "t" {
          chains.c.rules = map (match: [
            (dsl.hasAnyFlag match.left match.right)
            accept
          ]) bitmaskMatches;
        })
      ];
    }
    # Every other right-hand shape loads the same with `==` written out.
    {
      name = "match-eq-shapes";
      children = [
        (dsl.table "inet" "t" {
          sets.allowed.type = "ipv4_addr";
          chains.c.rules = map (match: [
            match
            accept
          ]) shapeMatches;
        })
      ];
    }

    # -- NAT and tproxy targets ------------------------------------------
    # An IPv6 address before a port is bracketed in text; without the
    # brackets, `2001:db8::1:80` loads as another address with no port.
    {
      name = "nat-ipv6-targets";
      children = [
        (dsl.table "ip6" "t" {
          chains = {
            pre = {
              type = "nat";
              hook = "prerouting";
              prio = -100;
              rules = map tcpRule [
                (dsl.dnat {
                  addr = "2001:db8::1";
                  port = 80;
                })
                (dsl.dnat { addr = "2001:db8::2"; })
                (dsl.dnat {
                  addr = dsl.expr.range "2001:db8::10" "2001:db8::1f";
                  port = dsl.expr.range 8080 8089;
                })
                (dsl.dnat {
                  addr = dsl.expr.prefix "2001:db8:1::" 64;
                  port = 443;
                })
              ];
            };
            post = {
              type = "nat";
              hook = "postrouting";
              prio = 100;
              rules = map tcpRule [
                (dsl.snat {
                  addr = "2001:db8::1";
                  port = 1024;
                })
                (dsl.snat { addr = "2001:db8::2"; })
              ];
            };
          };
        })
        (dsl.table "inet" "n" {
          chains.pre = {
            type = "nat";
            hook = "prerouting";
            prio = -100;
            rules = map tcpRule [
              (dsl.dnat {
                family = "ip6";
                addr = "2001:db8::1";
                port = 80;
              })
              (dsl.dnat {
                family = "ip6";
                addr = "2001:db8::2";
              })
            ];
          };
        })
      ];
    }
    {
      name = "tproxy-ipv6-targets";
      children = [
        (dsl.table "ip6" "t" {
          chains.pre = {
            type = "filter";
            hook = "prerouting";
            prio = -150;
            rules = map tcpRule [
              (dsl.tproxy {
                addr = "2001:db8::1";
                port = 80;
              })
              (dsl.tproxy { addr = "2001:db8::2"; })
            ];
          };
        })
        (dsl.table "inet" "n" {
          chains.pre = {
            type = "filter";
            hook = "prerouting";
            prio = -150;
            rules = map tcpRule [
              (dsl.tproxy {
                family = "ip6";
                addr = "2001:db8::1";
                port = 80;
              })
              (dsl.tproxy {
                family = "ip6";
                addr = "2001:db8::2";
              })
            ];
          };
        })
      ];
    }

    # -- statement bodies ------------------------------------------------
    # A seeded and an unseeded counter, the null bodies nft lists for
    # statements with no options, and port-only translations.
    {
      name = "statement-bodies";
      children = [
        (dsl.table "ip" "t" {
          chains = {
            input = {
              type = "filter";
              hook = "input";
              prio = 0;
              rules = [
                [
                  (dsl.counter {
                    packets = 0;
                    bytes = 0;
                  })
                ]
                [ dsl.counter.auto ]
                [ { log = null; } ]
                [ { queue = null; } ]
                [ { reject = null; } ]
              ];
            };
            divert = {
              type = "filter";
              hook = "prerouting";
              prio = -150;
              rules = [ (tcpRule (dsl.tproxy { port = 8080; })) ];
            };
            pre = {
              type = "nat";
              hook = "prerouting";
              prio = -100;
              rules = [
                [ { redirect = null; } ]
                (tcpRule (dsl.redirect { port = 8082; }))
                (tcpRule (dsl.dnat { port = 8080; }))
                # Without an address, the family is the table's either way.
                (tcpRule (
                  dsl.dnat {
                    family = "ip";
                    port = 8081;
                  }
                ))
              ];
            };
            post = {
              type = "nat";
              hook = "postrouting";
              prio = 100;
              rules = [
                [ { masquerade = null; } ]
                (tcpRule (dsl.masquerade { port = 1026; }))
                (tcpRule (dsl.snat { port = 1024; }))
                (tcpRule (
                  dsl.snat {
                    family = "ip";
                    port = 1025;
                  }
                ))
              ];
            };
          };
        })
      ];
    }

    # -- binary operators ------------------------------------------------
    # Every level of the precedence table, and nesting at equal
    # precedence: `mark << 1 << 2` would load as `mark << 3`.
    {
      name = "binop-precedence";
      children = [
        (dsl.table "inet" "t" {
          chains.c.rules = map (value: [ (dsl.mangle meta.mark value) ]) markValues;
        })
      ];
    }

    # -- ct expectation --------------------------------------------------
    # The JSON timeout is milliseconds, so every text form must load
    # `timeout 60ms`, not 60 seconds.
    {
      name = "ct-expectation-timeout";
      children = [
        (dsl.table "ip" "t" {
          ctExpectations.e = {
            protocol = "tcp";
            l3proto = "ip";
            dport = 22;
            timeout = 60;
            size = 2;
          };
        })
      ];
    }

    # -- ordinary configs read back ---------------------------------------
    # nft lists an inet ct helper or timeout with `l3proto: "inet"`, given
    # or not; the round trip checks that the schema accepts it. The kernel
    # refuses an inet expectation without `ip` or `ip6`.
    {
      name = "inet-ct-objects";
      children = [
        (dsl.table "inet" "t" {
          ctHelpers.h = {
            type = "ftp";
            protocol = "tcp";
            l3proto = "inet";
          };
          ctTimeouts.cto = {
            protocol = "tcp";
            policy.established = 300;
          };
          ctExpectations.cte = {
            protocol = "tcp";
            l3proto = "ip";
            dport = 21;
            timeout = 1000;
            size = 1;
          };
        })
      ];
    }
    # nft's JSON parser ignores a set or map comment, so JSON loads them
    # without it and every text form refuses it.
    {
      name = "commented-set-and-map";
      children = [
        (dsl.table "inet" "t" {
          sets.hosts = {
            type = "ipv4_addr";
            comment = "blocked hosts";
          };
          maps.actions = {
            type = "ipv4_addr";
            map = "verdict";
            comment = "per-host verdicts";
          };
        })
      ];
    }

    # Set-level statements give each element its own instance, which nft
    # lists as a statement key beside the element's `val`, so the round
    # trip validates element statements too.
    {
      name = "set-statements";
      children = [
        (dsl.table "ip" "t" {
          sets =
            let
              quota = {
                val = 100;
                val_unit = "kbytes";
              };
              withStatements = statements: element: {
                type = "ipv4_addr";
                inherit statements;
                elements = [ element ];
              };
            in
            {
              counted = withStatements [ { counter = null; } ] "10.0.0.1";
              quoted = withStatements [ { inherit quota; } ] "10.0.0.2";
              limited = withStatements [
                {
                  limit = {
                    rate = 5;
                    per = "second";
                    burst = 10;
                  };
                }
              ] "10.0.0.3";
              seen = withStatements [ { last = null; } ] "10.0.0.4";
              both = withStatements [
                { counter = null; }
                { inherit quota; }
              ] "10.0.0.5";
            };
        })
      ];
    }

    # -- ct count objects (nftables 1.1.7) -------------------------------
    {
      name = "ct-count-objects";
      rejectedBefore = "1.1.7";
      children = [
        (dsl.table "inet" "t" {
          ctCounts = {
            above = {
              val = 5;
              inv = true;
              comment = "over five";
            };
            below.val = 3;
          };
        })
        (create.ctCount {
          family = "inet";
          table = "t";
          name = "created";
          val = 4;
        })
      ];
    }

    # -- object spellings -------------------------------------------------
    # Every object line text writes: counter counts (text needs both),
    # synproxy values and flags, set and map policy/size/timeout/auto-merge,
    # and each ct expectation clause.
    {
      name = "object-spellings";
      children = [
        (dsl.table "inet" "t" {
          counters = {
            packetsOnly.packets = 5;
            bytesOnly = {
              bytes = 7;
              comment = "bytes only";
            };
            both = {
              packets = 1;
              bytes = 2;
            };
          };
          synproxies = {
            bothFlags = {
              mss = 1460;
              wscale = 7;
              flags = [
                "timestamp"
                "sack-perm"
              ];
            };
            oneFlag = {
              mss = 1400;
              wscale = 5;
              flags = [ "timestamp" ];
              comment = "timestamp only";
            };
            noFlags = {
              mss = 1300;
              wscale = 3;
            };
          };
          sets.timedHosts = {
            type = "ipv4_addr";
            flags = [ "timeout" ];
            policy = "memory";
            size = 128;
            timeout = 90;
            gcInterval = 30;
          };
          sets.mergedRanges = {
            type = "ipv4_addr";
            flags = [ "interval" ];
            autoMerge = true;
            elements = [
              (dsl.expr.prefix "192.0.2.0" 25)
              (dsl.expr.prefix "192.0.2.128" 25)
            ];
          };
          maps.timedMarks = {
            type = "ipv4_addr";
            map = "mark";
            flags = [ "timeout" ];
            policy = "performance";
            size = 64;
            timeout = 3600;
          };
          ctExpectations.everyLine = {
            protocol = "udp";
            dport = 69;
            timeout = 2500;
            size = 3;
            l3proto = "ip";
            comment = "tftp";
          };
        })
        (create.synproxy {
          family = "inet";
          table = "t";
          name = "created";
          mss = 1200;
          wscale = 2;
          flags = [ "sack-perm" ];
        })
        (create.counter {
          family = "inet";
          table = "t";
          name = "created";
          packets = 9;
        })
      ];
    }

    # -- object maps ------------------------------------------------------
    # Maps whose elements name stateful objects, which expansion adds
    # before the maps. nft's text declares a map of ct helpers only with a
    # typeof key. No secmark map: a secmark object needs SELinux, which the
    # test kernel lacks.
    {
      name = "object-maps";
      children = [
        (dsl.table "inet" "t" {
          counters.hits = { };
          quotas.monthly.bytes = 1000;
          limits.slow = {
            rate = 10;
            per = "second";
          };
          synproxies.web = {
            mss = 1460;
            wscale = 7;
          };
          ctHelpers.ftpHelper = {
            type = "ftp";
            protocol = "tcp";
            l3proto = "ip";
          };
          maps =
            let
              byAddress = kind: name: {
                type = "ipv4_addr";
                map = kind;
                elements = [
                  [
                    "192.0.2.1"
                    name
                  ]
                ];
              };
            in
            {
              counterByAddress = byAddress "counter" "hits";
              quotaByAddress = byAddress "quota" "monthly";
              limitByAddress = byAddress "limit" "slow";
              synproxyByAddress = byAddress "synproxy" "web";
              helperByPort = {
                type.typeof = tcp.dport;
                map = "ct helper";
                elements = [
                  [
                    21
                    "ftpHelper"
                  ]
                ];
              };
            };
        })
      ];
    }

    # -- interface names ------------------------------------------------
    # Text quotes each interface name, so every name loads the JSON
    # string, and a `define` around the text can't change `$lan`.
    {
      name = "ifname-quoting";
      textDefines.lan = "eth1";
      children = [
        (dsl.table "inet" "t" {
          sets = {
            names = {
              type = "ifname";
              elements = ifnameValues;
            };
            # In an interval set, `eth*` is a wildcard, as in JSON. It
            # covers `eth0`, which would conflict with it.
            wildcards = {
              type = "ifname";
              flags = [ "interval" ];
              elements = lib.remove "eth0" ifnameValues ++ [ "eth*" ];
            };
            pairs = {
              type = [
                "ifname"
                "ipv4_addr"
              ];
              elements = ifnameAddressPairs;
            };
          };
          maps = {
            marks = {
              type = "ifname";
              map = "mark";
              elements = ifnameMarks;
            };
            byMark = {
              type = "mark";
              map = "ifname";
              elements = map lib.reverseList ifnameMarks;
            };
          };
          chains = {
            c.rules =
              map (name: [
                (dsl.eq meta.iifname name)
                accept
              ]) (ifnameValues ++ [ "eth*" ])
              ++ [
                [
                  (dsl.ne meta.oifname (dsl.expr.set ifnameValues))
                  accept
                ]
                [
                  (dsl.eq (dsl.expr.concat [
                    meta.iifname
                    ip.saddr
                  ]) (dsl.expr.set ifnameAddressPairs))
                  accept
                ]
                [
                  (dsl.vmap meta.iifname (
                    dsl.expr.set (
                      map (name: [
                        name
                        accept
                      ]) ifnameValues
                    )
                  ))
                ]
                [ (dsl.mangle meta.mark (dsl.expr.map meta.iifname (dsl.expr.set ifnameMarks))) ]
              ];
            pre = {
              type = "filter";
              hook = "prerouting";
              prio = 0;
              rules = map (name: [
                (dsl.eq (dsl.expr.fib {
                  result = "oifname";
                  flags = [
                    "daddr"
                    "iif"
                  ];
                }) name)
                accept
              ]) ifnameValues;
            };
          };
        })
      ];
    }
    # typeof keys, apart because typeof sets don't load through text
    # until #34.
    {
      name = "ifname-quoting-typeof";
      textDefines.lan = "eth1";
      children = [
        (dsl.table "inet" "t" {
          sets = {
            names = {
              type.typeof = meta.iifname;
              elements = ifnameValues;
            };
            pairs = {
              type.typeof = dsl.expr.concat [
                meta.iifname
                ip.saddr
              ];
              elements = ifnameAddressPairs;
            };
          };
        })
      ];
    }

    # -- typeof declarations and statement references ---------------------
    # typeof sets and maps, with single and concatenated keys. A map
    # declares both sides with typeof, or takes an object kind as its
    # value type.
    {
      name = "typeof-sets-and-maps";
      children =
        let
          addressPort = dsl.expr.concat [
            ip.saddr
            tcp.dport
          ];
          endpoint =
            address: port:
            dsl.expr.concat [
              address
              port
            ];
        in
        [
          (dsl.table "inet" "t" {
            counters.hits = { };
            sets = {
              addresses = {
                type.typeof = ip.saddr;
                elements = [ "192.0.2.1" ];
              };
              endpoints = {
                type.typeof = addressPort;
                elements = [ (endpoint "192.0.2.1" 22) ];
              };
            };
            maps = {
              marks = {
                type.typeof = ip.saddr;
                map.typeof = meta.mark;
                elements = [
                  [
                    "192.0.2.1"
                    1
                  ]
                ];
              };
              endpointMarks = {
                type.typeof = addressPort;
                map.typeof = meta.mark;
                elements = [
                  [
                    (endpoint "192.0.2.1" 22)
                    2
                  ]
                ];
              };
              counted = {
                type.typeof = ip.saddr;
                map = "counter";
                elements = [
                  [
                    "192.0.2.1"
                    "hits"
                  ]
                ];
              };
            };
          })
        ];
    }

    # A typeof map with a verdict value: nft's JSON parser declares it
    # with `type`, text with `typeof` (a Known difference).
    {
      name = "typeof-verdict-map";
      children = [
        (dsl.table "inet" "t" {
          maps.byAddress = {
            type.typeof = ip.saddr;
            map = "verdict";
            elements = [
              [
                "192.0.2.1"
                accept
              ]
            ];
          };
        })
      ];
    }

    # Set, map and flow statements with each reference spelled with and
    # without its `@`.
    {
      name = "statement-references";
      interfaces = [ "eth0" ];
      children = [
        (dsl.table "inet" "t" {
          sets.blocked = {
            type = "ipv4_addr";
            flags = [ "dynamic" ];
          };
          maps.cache = {
            type = "ipv4_addr";
            map = "mark";
            flags = [ "dynamic" ];
          };
          flowtables.ft = {
            hook = "ingress";
            prio = 0;
            dev = [ "eth0" ];
          };
          chains.forward = {
            type = "filter";
            hook = "forward";
            prio = 0;
            rules =
              lib.concatMap
                (reference: [
                  [
                    (dsl.setStmt {
                      op = "add";
                      elem = ip.saddr;
                      set = reference "blocked";
                    })
                  ]
                  [
                    (dsl.mapStmt {
                      op = "update";
                      elem = ip.saddr;
                      data = 1;
                      map = reference "cache";
                    })
                  ]
                  [ (dsl.flow (reference "ft")) ]
                ])
                [
                  (name: name)
                  (name: "@${name}")
                ];
          };
        })
      ];
    }

    # References to named objects, each built from the name and from
    # `@name`: nft's JSON looks a stateful object up by its bare name and
    # reads a bare set or map name as a hostname.
    {
      name = "object-references";
      children = [
        (dsl.table "inet" "t" {
          counters.hits = { };
          quotas.budget.bytes = 1000;
          limits.slow = {
            rate = 10;
            per = "second";
          };
          synproxies.web = {
            mss = 1460;
            wscale = 7;
          };
          ctHelpers.ftpHelper = {
            type = "ftp";
            protocol = "tcp";
            l3proto = "ip";
          };
          ctTimeouts.shortTcp = {
            protocol = "tcp";
            l3proto = "ip";
            policy.established = 300;
          };
          ctExpectations.sshExpectation = {
            protocol = "tcp";
            l3proto = "ip";
            dport = 22;
            timeout = 60;
            size = 2;
          };
          sets.allowed.type = "ipv4_addr";
          maps.marks = {
            type = "ipv4_addr";
            map = "mark";
          };
          maps.verdicts = {
            type = "ipv4_addr";
            map = "verdict";
          };
          chains.input = {
            type = "filter";
            hook = "input";
            prio = 0;
            rules =
              lib.concatMap
                (reference: [
                  [ (dsl.counter.ref (reference "hits")) ]
                  [ (dsl.quota.ref (reference "budget")) ]
                  [ (dsl.limit.ref (reference "slow")) ]
                  (tcpRule (dsl.synproxy.ref (reference "web")))
                  (tcpRule (dsl.ctHelper.ref (reference "ftpHelper")))
                  (tcpRule (dsl.ctTimeout.ref (reference "shortTcp")))
                  (tcpRule (dsl.ctExpectation.ref (reference "sshExpectation")))
                  [ (dsl.eq ip.saddr (dsl.expr.setRef (reference "allowed"))) ]
                  [ (dsl.mangle meta.mark (dsl.expr.map ip.saddr (reference "marks"))) ]
                  [ (dsl.vmap ip.saddr (reference "verdicts")) ]
                ])
                [
                  (name: name)
                  (name: "@${name}")
                ];
          };
        })
      ];
    }

    # -- statement spellings (#35) --------------------------------------
    # Units, bursts and inversion of limit and quota, in every form each
    # has: inline, named object, and positional `create`. Object names
    # avoid nft keywords such as `packets` and `over`.
    {
      name = "limit-and-quota-spellings";
      children = [
        (dsl.table "inet" "t" {
          limits = {
            packetRate = {
              rate = 10;
              per = "second";
              rateUnit = "packets";
              burst = 7;
              burstUnit = "bytes";
            };
            byteRate = {
              rate = 10;
              per = "minute";
              rateUnit = "kbytes";
              burst = 5;
            };
            zeroBurst = {
              rate = 10;
              per = "hour";
              burst = 0;
            };
          };
          quotas = {
            unset = { };
            inverted = {
              bytes = 1000;
              used = 5;
              inv = true;
            };
          };
          chains.input = {
            type = "filter";
            hook = "input";
            prio = 0;
            rules = map (statement: [ statement ]) [
              (dsl.limit {
                rate = 10;
                per = "second";
                rateUnit = "packets";
                burst = 7;
                burstUnit = "bytes";
              })
              (dsl.limit {
                rate = 10;
                per = "second";
                burst = 0;
              })
              (dsl.limit {
                rate = 10;
                per = "minute";
                rateUnit = "kbytes";
                burst = 5;
              })
              (dsl.limit {
                rate = 1;
                per = "second";
                rateUnit = "mbytes";
                burst = 0;
                burstUnit = "kbytes";
                inv = true;
              })
              (dsl.limit {
                rate = 10;
                per = "day";
                inv = true;
              })
              (dsl.quota { val = 100; })
              (dsl.quota {
                val = 2;
                valUnit = "mbytes";
                used = 1;
                inv = true;
              })
              (dsl.quota {
                val = 2;
                valUnit = "kbytes";
                used = 1;
                usedUnit = "kbytes";
              })
            ];
          };
        })
        (create.limit {
          family = "inet";
          table = "t";
          name = "created";
          rate = 1;
          per = "second";
          rateUnit = "kbytes";
          burst = 0;
        })
        (create.quota {
          family = "inet";
          table = "t";
          name = "created";
          used = 0;
        })
      ];
    }
    # NAT address types: `prefix to` (the netmap flag), `addr . port to`
    # (the concat type flag), and the type flags text needn't write.
    {
      name = "nat-address-types";
      children = [
        (dsl.table "ip" "t" {
          chains.post = {
            type = "nat";
            hook = "postrouting";
            prio = 100;
            rules = map tcpRule [
              (dsl.snat {
                family = "ip";
                addr = dsl.expr.prefix "10.0.0.0" 24;
                flags = "netmap";
                typeFlags = "prefix";
              })
              (dsl.snat {
                addr = dsl.expr.prefix "10.0.1.0" 24;
                flags = [ "netmap" ];
              })
              (dsl.snat {
                family = "ip";
                addr = dsl.expr.prefix "10.0.2.0" 24;
                typeFlags = [ "prefix" ];
              })
              (dsl.snat {
                family = "ip";
                addr = dsl.expr.map ip.saddr (
                  dsl.expr.set [
                    [
                      "192.0.2.1"
                      (dsl.expr.concat [
                        "10.0.3.1"
                        80
                      ])
                    ]
                  ]
                );
                typeFlags = "concat";
                flags = [ "persistent" ];
              })
              (dsl.snat {
                family = "ip";
                addr = dsl.expr.map ip.saddr (
                  dsl.expr.set [
                    [
                      "192.0.2.2"
                      (dsl.expr.range "10.0.4.1" "10.0.4.9")
                    ]
                  ]
                );
                typeFlags = "interval";
              })
              (dsl.snat {
                addr = "10.0.5.1";
                port = 1024;
                flags = [
                  "random"
                  "persistent"
                ];
              })
            ];
          };
        })
      ];
    }
    # Log flags, `last`, extension header existence, queue numbers, and
    # negative integers. `last used` lists the time since the rule last
    # matched, so the probe drops its seconds (../helpers/probes/nft.nix).
    {
      name = "statement-spellings";
      children = [
        (dsl.table "inet" "t" {
          chains.input = {
            type = "filter";
            hook = "input";
            prio = 0;
            rules = map (statement: [ statement ]) [
              (dsl.log {
                flags = [
                  "tcp sequence"
                  "ip options"
                  "tcp options"
                  "skuid"
                ];
              })
              (dsl.log { flags = "ether"; })
              (dsl.log {
                group = 2;
                snaplen = 64;
              })
              (dsl.log {
                flags = [
                  "all"
                  "tcp options"
                ];
              })
              dsl.last.auto
              (dsl.last { used = -1; })
              (dsl.last { used = 0; })
              (dsl.last { used = 86400000; })
              (dsl.eq (dsl.expr.exthdr { name = "frag"; }) true)
              (dsl.ne (dsl.expr.exthdr { name = "hbh"; }) false)
              (dsl.eq (dsl.expr.exthdr { name = "rt"; }) true)
              (dsl.eq (dsl.expr.exthdr { name = "dst"; }) true)
              (dsl.eq (dsl.expr.exthdr { name = "mh"; }) true)
              (dsl.eq meta.mark (-1))
              (dsl.eq meta.mark (
                dsl.expr.set [
                  (-2)
                  3
                ]
              ))
              (dsl.mangle meta.mark (-5))
              (dsl.queue { })
              (dsl.queue { num = 3; })
              (dsl.queue {
                num = dsl.expr.range 1 3;
                flags = [
                  "bypass"
                  "fanout"
                ];
              })
              (dsl.queue {
                num = dsl.expr.symhash {
                  mod = 2;
                  offset = 1;
                };
                flags = "bypass";
              })
              (dsl.queue { flags = "bypass"; })
            ];
          };
        })
      ];
    }
    # fwd to a device, and to a next hop through it.
    {
      name = "fwd-next-hop";
      interfaces = [ "eth0" ];
      children = [
        (dsl.table "netdev" "t" {
          chains.ingress = {
            type = "filter";
            hook = "ingress";
            prio = 0;
            dev = "eth0";
            rules = map (statement: [ statement ]) [
              (dsl.fwd { dev = "eth0"; })
              (dsl.fwd {
                dev = "eth0";
                family = "ip";
                addr = "192.0.2.1";
              })
              (dsl.fwd {
                dev = "eth0";
                family = "ip6";
                addr = "2001:db8::1";
              })
            ];
          };
        })
      ];
    }

    # -- statement reach (#50) -------------------------------------------
    # Each verdict statement, in a rule of its own.
    {
      name = "verdict-statements";
      children = [
        (dsl.table "inet" "t" {
          chains = {
            input = {
              type = "filter";
              hook = "input";
              prio = 0;
              rules = [
                [ (dsl.jump "counted") ]
                [ (dsl.goto "passed") ]
              ];
            };
            counted.rules = [
              [
                dsl.counter.auto
                dsl.return
              ]
            ];
            passed.rules = [ [ dsl.continue ] ];
          };
        })
      ];
    }
    # Conntrack statements: a connection limit, the assignment of each ct
    # object kind, and `notrack` before conntrack sees the packet.
    {
      name = "conntrack-statements";
      children = [
        (dsl.table "inet" "t" {
          ctHelpers.ftpHelper = {
            type = "ftp";
            protocol = "tcp";
            l3proto = "ip";
          };
          ctTimeouts.shortTcp = {
            protocol = "tcp";
            l3proto = "ip";
            policy.established = 300;
          };
          ctExpectations.sshExpectation = {
            protocol = "tcp";
            l3proto = "ip";
            dport = 22;
            timeout = 60;
            size = 2;
          };
          chains = {
            raw = {
              type = "filter";
              hook = "prerouting";
              prio = -300;
              rules = [
                [
                  (dsl.eq tcp.dport 9)
                  dsl.notrack
                ]
              ];
            };
            input = {
              type = "filter";
              hook = "input";
              prio = 0;
              rules = [
                [ (dsl.ctCount { val = 5; }) ]
                [
                  (dsl.ctCount {
                    val = 10;
                    inv = true;
                  })
                ]
                (tcpRule (dsl.ctHelper.ref "ftpHelper"))
                (tcpRule (dsl.ctTimeout.ref "shortTcp"))
                (tcpRule (dsl.ctExpectation.ref "sshExpectation"))
              ];
            };
          };
        })
      ];
    }
    # Statements that act on the packet: dup with and without a device,
    # synproxy in each body form, a meter, and a TCP option reset.
    {
      name = "packet-statements";
      interfaces = [ "eth0" ];
      children = [
        (dsl.table "ip" "t" {
          synproxies.web = {
            mss = 1460;
            wscale = 7;
          };
          chains = {
            pre = {
              type = "filter";
              hook = "prerouting";
              prio = 0;
              rules = [
                [ (dsl.dup { addr = "192.0.2.1"; }) ]
                [
                  (dsl.dup {
                    addr = "192.0.2.2";
                    dev = "eth0";
                  })
                ]
              ];
            };
            input = {
              type = "filter";
              hook = "input";
              prio = 0;
              rules = [
                (tcpRule (
                  dsl.synproxy {
                    mss = 1460;
                    wscale = 7;
                    flags = [
                      "timestamp"
                      "sack-perm"
                    ];
                  }
                ))
                (tcpRule (dsl.synproxy.ref "web"))
                [
                  (dsl.meter {
                    name = "perSource";
                    key = ip.saddr;
                    statement = dsl.limit {
                      rate = 10;
                      per = "second";
                    };
                  })
                ]
                [
                  (dsl.meter {
                    name = "perDestination";
                    size = 128;
                    key = ip.daddr;
                    statement = dsl.counter.auto;
                  })
                ]
                (tcpRule (dsl.resetStmt (dsl.expr.tcpOption { name = "sack"; })))
              ];
            };
          };
        })
      ];
    }
    # A tunnel assignment. nft's JSON parser loads a tunnel object's ports
    # wrongly, so the object comes from text state.
    {
      name = "tunnel-statement";
      interfaces = [ "eth0" ];
      state = ''
        table netdev t {
          tunnel vxlan0 {
            id 42
            ip saddr 192.0.2.1
            ip daddr 192.0.2.2
            sport 4789
            dport 4789
            ttl 64
            tos 0
          }
        }
      '';
      children = [
        (dsl.table "netdev" "t" {
          chains.ingress = {
            type = "filter";
            hook = "ingress";
            prio = 0;
            dev = "eth0";
            rules = [
              [ (dsl.tunnel.ref "vxlan0") ]
              [ (dsl.tunnel.ref "@vxlan0") ]
            ];
          };
        })
      ];
    }

    # -- expression reach (#51) ------------------------------------------
    # Each verdict as verdict-map data, where it is an expression.
    {
      name = "verdict-expressions";
      children = [
        (dsl.table "inet" "t" {
          chains = {
            input = {
              type = "filter";
              hook = "input";
              prio = 0;
              rules = [
                [
                  (dsl.vmap meta.mark (
                    dsl.expr.set [
                      [
                        1
                        accept
                      ]
                      [
                        2
                        drop
                      ]
                      [
                        3
                        dsl.continue
                      ]
                      [
                        4
                        dsl.return
                      ]
                      [
                        5
                        (dsl.jump "other")
                      ]
                      [
                        6
                        (dsl.goto "other")
                      ]
                    ]
                  ))
                ]
              ];
            };
            other.rules = [ [ dsl.counter.auto ] ];
          };
        })
      ];
    }
    # A list as the data of a vmap and of a map lookup, which the builders
    # wrap in an anonymous map; nft rejects the bare list.
    {
      name = "anonymous-maps-from-lists";
      children = [
        (dsl.table "inet" "t" {
          chains.input = {
            type = "filter";
            hook = "input";
            prio = 0;
            rules = [
              [
                (dsl.vmap tcp.dport [
                  [
                    22
                    accept
                  ]
                  [
                    80
                    drop
                  ]
                ])
              ]
              [
                (dsl.mangle meta.mark (
                  dsl.expr.map tcp.dport [
                    [
                      22
                      1
                    ]
                    [
                      80
                      2
                    ]
                  ]
                ))
              ]
            ];
          };
        })
      ];
    }
    # Hashes and number generators, with and without their options.
    {
      name = "generator-expressions";
      children = [
        (dsl.table "inet" "t" {
          chains.input = {
            type = "filter";
            hook = "input";
            prio = 0;
            rules = map (value: [ (dsl.mangle meta.mark value) ]) [
              (dsl.expr.jhash {
                mod = 2;
                expr = ip.saddr;
              })
              (dsl.expr.jhash {
                mod = 4;
                expr = dsl.expr.concat [
                  ip.saddr
                  tcp.dport
                ];
                seed = 57005;
                offset = 100;
              })
              (dsl.expr.numgen {
                mode = "inc";
                mod = 2;
              })
              (dsl.expr.numgen {
                mode = "random";
                mod = 10;
                offset = 5;
              })
            ];
          };
        })
      ];
    }
    # IPv4 option and SCTP chunk matches: existence and a field each.
    {
      name = "header-option-expressions";
      children = [
        (dsl.table "inet" "t" {
          chains.input = {
            type = "filter";
            hook = "input";
            prio = 0;
            rules = map (match: [ match ]) [
              (dsl.eq (dsl.expr.ipOption { name = "rr"; }) true)
              (dsl.eq (dsl.expr.ipOption {
                name = "ra";
                field = "value";
              }) 0)
              (dsl.eq (dsl.expr.sctpChunk { name = "init"; }) true)
              (dsl.eq (dsl.expr.sctpChunk {
                name = "data";
                field = "flags";
              }) 2)
            ];
          };
        })
      ];
    }
    # Matches on what the host knows about a packet: its route, socket,
    # IPsec state, and OS fingerprint, each in a hook that allows it.
    {
      name = "packet-context-expressions";
      children = [
        (dsl.table "inet" "t" {
          chains = {
            output = {
              type = "filter";
              hook = "output";
              prio = 0;
              rules = map (match: [ match ]) [
                (dsl.eq (dsl.expr.rt { key = "mtu"; }) 1500)
                (dsl.eq (dsl.expr.rt { key = "classid"; }) 10)
                (dsl.eq (dsl.expr.rt {
                  key = "nexthop";
                  family = "ip";
                }) "192.0.2.1")
                (dsl.eq (dsl.expr.rt { key = "ipsec"; }) false)
                (dsl.eq (dsl.expr.ipsec {
                  key = "reqid";
                  dir = "out";
                }) 1)
              ];
            };
            pre = {
              type = "filter";
              hook = "prerouting";
              prio = 0;
              rules = map (match: [ match ]) [
                (dsl.eq dsl.fields.socket.transparent 1)
                (dsl.eq dsl.fields.socket.mark 5)
                (dsl.eq dsl.fields.socket.wildcard 0)
              ];
            };
            input = {
              type = "filter";
              hook = "input";
              prio = 0;
              rules = map (match: [ match ]) [
                (dsl.eq (dsl.expr.ipsec {
                  key = "spi";
                  dir = "in";
                }) 5)
                (dsl.eq (dsl.expr.ipsec {
                  key = "saddr";
                  family = "ip";
                  dir = "in";
                  spnum = 1;
                }) "192.0.2.1")
                (dsl.eq (dsl.expr.osf { key = "name"; }) "Linux")
                (dsl.eq (dsl.expr.osf {
                  key = "version";
                  ttl = "loose";
                }) "Linux:3.0")
              ];
            };
          };
        })
      ];
    }
    # Set elements with their own timeout, expiry, and comment. The
    # listings keep an expiry's minutes, so each time sits mid-minute: on
    # a whole minute, it could list a minute less in one form.
    {
      name = "element-options";
      children = [
        (dsl.table "inet" "t" {
          sets.hosts = {
            type = "ipv4_addr";
            flags = [ "timeout" ];
            elements = [
              (dsl.expr.elem {
                val = "192.0.2.1";
                timeout = 90;
              })
              (dsl.expr.elem {
                val = "192.0.2.2";
                timeout = 150;
                expires = 130;
              })
              (dsl.expr.elem {
                val = "192.0.2.3";
                comment = "a host";
              })
            ];
          };
        })
      ];
    }
    # Tunnel metadata matches, which need no tunnel object. After a tunnel
    # match, nft's text lexer reads `ingress` as a keyword in the next
    # command, so the chain has another name (docs/text-coverage.md).
    {
      name = "tunnel-expressions";
      interfaces = [ "eth0" ];
      children = [
        (dsl.table "netdev" "t" {
          chains.decap = {
            type = "filter";
            hook = "ingress";
            prio = 0;
            dev = "eth0";
            rules = [
              [ (dsl.eq dsl.fields.tunnel.id 42) ]
              [ (dsl.eq dsl.fields.tunnel.path true) ]
            ];
          };
        })
      ];
    }

    # -- command reach (#52) ---------------------------------------------
    # nft resolves the object a command names, or a rule's handle, against
    # what is loaded, so these cases take it from their `state`.

    # Rules selected by handle. The table numbers its objects in load
    # order, so chain `c` is handle 1 and its rules 2 to 5.
    {
      name = "rule-commands";
      state = ''
        table ip t {
          chain c {
            meta mark 1 accept
            meta mark 2 accept
            meta mark 3 accept
            meta mark 4 accept
          }
        }
      '';
      ruleset =
        let
          ruleScope = tableScope // {
            chain = "c";
          };
        in
        ruleset [
          (dsl.insert.rule (
            ruleScope
            // {
              statements = [
                (dsl.eq meta.mark 10)
                accept
              ];
            }
          ))
          (dsl.insert.rule (
            ruleScope
            // {
              handle = 3;
              statements = [
                (dsl.eq meta.mark 11)
                accept
              ];
            }
          ))
          (dsl.replace.rule (
            ruleScope
            // {
              handle = 2;
              statements = [
                (dsl.eq meta.mark 12)
                drop
              ];
            }
          ))
          (delete.rule (ruleScope // { handle = 4; }))
          (destroy.rule (ruleScope // { handle = 5; }))
        ];
    }
    # Each listable kind but table (`list-table`) and secmark, listed by
    # name. `meter` lists the set its statement creates.
    {
      name = "list-commands";
      state = ''
        table ip t {
          counter ctr { packets 1 bytes 2 }
          quota q { 100 bytes }
          limit lim { rate 10/second }
          ct helper h { type "ftp" protocol tcp; l3proto ip; }
          set s { type ipv4_addr; elements = { 10.0.0.1 } }
          map m { type ipv4_addr : mark; elements = { 10.0.0.1 : 1 } }
          chain c {
            meter flood { ip saddr limit rate 10/second }
          }
        }
      '';
      ruleset = ruleset [
        (list.chain (tableScope // { name = "c"; }))
        (list.counter (tableScope // { name = "ctr"; }))
        (list.quota (tableScope // { name = "q"; }))
        (list.limit (tableScope // { name = "lim"; }))
        (list.ctHelper (tableScope // { name = "h"; }))
        (list.set (tableScope // { name = "s"; }))
        (list.map (tableScope // { name = "m"; }))
        (list.meter (tableScope // { name = "flood"; }))
      ];
    }
    /*
      Resets zero the counters of one element, a set's elements, and a
      map's elements; the listing shows which. nft runs a reset of a set or
      map only as a batch's last command (docs/spec-coverage.md), so each
      of those is its own case.
    */
    {
      name = "reset-element-and-flush-meter";
      state = counterSets;
      ruleset = ruleset [
        (reset.element (
          tableScope
          // {
            name = "a";
            elements = [ "10.0.0.1" ];
          }
        ))
        (flush.meter (tableScope // { name = "flood"; }))
      ];
    }
    {
      name = "reset-set";
      state = counterSets;
      ruleset = ruleset [
        (reset.set (tableScope // { name = "b"; }))
      ];
    }
    {
      name = "reset-map";
      state = counterSets;
      ruleset = ruleset [
        (reset.map (tableScope // { name = "m"; }))
      ];
    }
    # Elements deleted and destroyed, the last one absent, and a chain
    # renamed.
    {
      name = "element-and-chain-commands";
      state = ''
        table ip t {
          set s { type ipv4_addr; elements = { 10.0.0.1, 10.0.0.2, 10.0.0.3 } }
          chain old { }
        }
      '';
      ruleset = ruleset [
        (delete.element (
          tableScope
          // {
            name = "s";
            elements = [ "10.0.0.1" ];
          }
        ))
        (destroy.element (
          tableScope
          // {
            name = "s";
            elements = [
              "10.0.0.2"
              "10.0.0.9"
            ];
          }
        ))
        (dsl.rename.chain (
          tableScope
          // {
            name = "old";
            newName = "renamed";
          }
        ))
      ];
    }

    # -- a Read-back ------------------------------------------------------
    # nftables 1.1.6's `nft -j list ruleset` of a table, as listed:
    # `metainfo` first, and a handle on every object. Text drops the
    # metainfo and the rules' handles, which nft's JSON parser ignores.
    # Given as `children`, the listed objects also load in block form.
    {
      name = "readback-listing";
      children =
        let
          inTable =
            attrs:
            {
              family = "inet";
              table = "t";
            }
            // attrs;
        in
        [
          {
            metainfo = {
              version = "1.1.6";
              release_name = "Commodore Bullmoose #7";
              json_schema_version = 1;
            };
          }
          {
            table = {
              family = "inet";
              name = "t";
              handle = 1;
            };
          }
          {
            chain = inTable {
              name = "input";
              handle = 1;
              type = "filter";
              hook = "input";
              prio = 0;
              policy = "drop";
            };
          }
          {
            chain = inTable {
              name = "allowed";
              handle = 2;
            };
          }
          {
            counter = inTable {
              name = "hits";
              handle = 3;
              packets = 5;
              bytes = 300;
            };
          }
          {
            quota = inTable {
              name = "budget";
              handle = 4;
              bytes = 104857600;
              used = 0;
              inv = true;
            };
          }
          {
            set = inTable {
              name = "blocked";
              type = "ipv4_addr";
              handle = 5;
              flags = [ "interval" ];
              elem = [
                {
                  prefix = {
                    addr = "192.0.2.0";
                    len = 24;
                  };
                }
                "198.51.100.7"
              ];
            };
          }
          {
            map = inTable {
              name = "ports";
              type = "inet_service";
              handle = 6;
              map = "verdict";
              elem = [
                [
                  22
                  { accept = null; }
                ]
                [
                  80
                  { drop = null; }
                ]
              ];
            };
          }
          {
            rule = inTable {
              chain = "input";
              handle = 7;
              expr = [
                {
                  match = {
                    op = "==";
                    left.payload = {
                      protocol = "ip";
                      field = "saddr";
                    };
                    right = "@blocked";
                  };
                }
                { counter = "hits"; }
                { drop = null; }
              ];
            };
          }
          {
            rule = inTable {
              chain = "input";
              handle = 8;
              expr = [
                {
                  vmap = {
                    key.payload = {
                      protocol = "tcp";
                      field = "dport";
                    };
                    data = "@ports";
                  };
                }
              ];
            };
          }
          {
            rule = inTable {
              chain = "input";
              handle = 9;
              comment = "rest";
              expr = [ { jump.target = "allowed"; } ];
            };
          }
          {
            rule = inTable {
              chain = "allowed";
              handle = 10;
              expr = [
                { quota = "budget"; }
                { accept = null; }
              ];
            };
          }
        ];
    }

    # -- the shipped example firewalls ----------------------------------
    {
      name = "example-basic-firewall";
      ruleset = examples.basicFirewall;
    }
    # The DSL examples are built from table nodes, so they load in block
    # form too.
    {
      name = "example-basic-firewall-dsl";
      children = exampleChildren.basicFirewallDsl;
    }
    {
      name = "example-home-router-dsl";
      children = exampleChildren.homeRouterDsl;
      # The home-router flowtable binds to eth0/eth1; nft -c validates
      # those device references against the netns's link table, so the
      # runner pre-creates dummy interfaces of those names.
      interfaces = [
        "eth0"
        "eth1"
      ];
    }
  ];

  /*
    Negative cases: one wrong value that the schema and nft both reject.
    Each case is `{ name; expectedError; withValue; rejected; accepted; }`:
    `withValue` builds the raw ruleset around a value, `rejected` is the
    wrong one and `accepted` its correction. The suite checks that nft
    rejects `withValue rejected` with `expectedError`, and that the schema
    rejects it but accepts `withValue accepted`. The rulesets bypass the
    schema, so nft's live JSON parser stays the oracle.
  */
  rejectionCases =
    let
      table = {
        family = "inet";
        name = "filter";
      };
      chain = {
        family = "inet";
        table = "filter";
        name = "input";
      };
      baseChain = chain // {
        type = "filter";
        hook = "input";
        prio = 0;
      };
      ruleScope = {
        family = "inet";
        table = "filter";
        chain = "input";
      };
      rule = expr: {
        add.rule = ruleScope // {
          inherit expr;
        };
      };
      commands = list: { nftables = list; };
    in
    map (case: case // { ruleset = case.withValue case.rejected; }) [
      {
        # The prelude makes the table and chain valid in the same batch.
        name = "create-rule";
        expectedError = "Create command not available for rules";
        withValue =
          verb:
          commands [
            { add.table = table; }
            { add.chain = chain; }
            {
              ${verb}.rule = ruleScope // {
                expr = [ ];
              };
            }
          ];
        rejected = "create";
        accepted = "add";
      }
      {
        name = "unknown-family";
        expectedError = "Unknown family 'ip4'.";
        withValue =
          family:
          commands [
            {
              add.table = table // {
                inherit family;
              };
            }
          ];
        rejected = "ip4";
        accepted = "ip";
      }
      {
        name = "unknown-hook";
        expectedError = "Invalid chain hook 'inputx'.";
        withValue =
          hook:
          commands [
            { add.table = table; }
            {
              add.chain = baseChain // {
                inherit hook;
              };
            }
          ];
        rejected = "inputx";
        accepted = "input";
      }
      {
        name = "unknown-chain-policy";
        expectedError = "Unknown policy 'maybe'.";
        withValue =
          policy:
          commands [
            { add.table = table; }
            {
              add.chain = baseChain // {
                inherit policy;
              };
            }
          ];
        rejected = "maybe";
        accepted = "drop";
      }
      {
        name = "unknown-log-level";
        expectedError = "Invalid log level 'loud'.";
        withValue =
          level:
          commands [
            { add.table = table; }
            { add.chain = baseChain; }
            (rule [ { log = { inherit level; }; } ])
          ];
        rejected = "loud";
        accepted = "info";
      }
      {
        name = "unknown-relational-op";
        expectedError = "Invalid relational op '=~'.";
        withValue =
          op:
          commands [
            { add.table = table; }
            { add.chain = baseChain; }
            (rule [
              {
                match = {
                  inherit op;
                  left.meta.key = "mark";
                  right = 1;
                };
              }
            ])
          ];
        rejected = "=~";
        accepted = "!=";
      }
      {
        /*
          nft keeps a ct expectation's port in 16 bits, so 65536 reads as 0,
          which it reports as a missing option. Past that, it truncates
          silently: 70000 loads as port 4464. Only the schema rejects the
          whole range.
        */
        name = "port-out-of-range";
        expectedError = "missing options";
        withValue =
          dport:
          commands [
            { add.table = table; }
            {
              add."ct expectation" = {
                family = "inet";
                table = "filter";
                name = "e";
                l3proto = "ip";
                protocol = "tcp";
                inherit dport;
                timeout = 1000;
                size = 1;
              };
            }
          ];
        rejected = 65536;
        accepted = 65535;
      }
      # A Reference is a name or a map expression (ADR 0010).
      {
        name = "boolean-object-reference";
        expectedError = "Boolean values not allowed in this context";
        withValue =
          secmark:
          commands [
            { add.table = table; }
            { add.chain = baseChain; }
            (rule [ { inherit secmark; } ])
          ];
        rejected = true;
        accepted = "s";
      }
      {
        name = "reset-other-than-tcp-option";
        expectedError = "Illegal TCP optstrip argument";
        withValue =
          reset:
          commands [
            { add.table = table; }
            { add.chain = baseChain; }
            (rule [ { inherit reset; } ])
          ];
        rejected.ct.key = "mark";
        accepted."tcp option".name = "maxseg";
      }
      # nft evaluates a flowtable's hook as a netdev hook, whatever the
      # table's family.
      {
        name = "flowtable-hook-other-than-ingress";
        expectedError = "invalid hook";
        withValue =
          hook:
          commands [
            { add.table = table; }
            {
              add.flowtable = {
                family = "inet";
                table = "filter";
                name = "ft";
                inherit hook;
                prio = 0;
              };
            }
          ];
        rejected = "input";
        accepted = "ingress";
      }
    ];

  # Round-trip states loaded through nft text, `{ name; text; }`: Read-back
  # shapes that nft lists but its JSON parser ignores on input.
  textReadbacks = [
    {
      name = "commented-set-and-map-text";
      text = ''
        table inet t {
          set hosts {
            type ipv4_addr
            comment "blocked hosts"
          }
          map actions {
            type ipv4_addr : verdict
            comment "per-host verdicts"
          }
        }
      '';
    }
    # Elements whose statements hold state, which JSON input can't seed.
    {
      name = "element-statements-text";
      text = ''
        table ip t {
          set counted {
            type ipv4_addr
            counter
            elements = { 10.0.0.1 counter packets 1 bytes 2 }
          }
          set quoted {
            type ipv4_addr
            quota 100 kbytes
            elements = { 10.0.0.2 quota 100 kbytes used 40 kbytes }
          }
          set limited {
            type ipv4_addr
            limit rate over 5/second burst 10 packets
            elements = { 10.0.0.3 limit rate over 5/second burst 10 packets }
          }
          set seen {
            type ipv4_addr
            last
            elements = { 10.0.0.4 last used 1s }
          }
        }
      '';
    }
  ];
}
