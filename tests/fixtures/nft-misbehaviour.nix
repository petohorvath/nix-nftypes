/*
  "Still misbehaves" cases: forms nft accepts but loads as something other
  than they say. Each is a Known difference (ADR 0010) that the schema or
  the text renderer refuses. The probe (../helpers/probes/nft.nix) loads
  each raw `ruleset` through JSON, unvalidated, and runs `inspect`; the
  suite asserts that the output is still `misbehaviour`, so a fixed nft
  fails it and the form can return.

  Each case has `name`, `knownDifference` (where it is documented),
  `ruleset`, `inspect` (a shell command), and `misbehaviour`. A case may
  add a `subject` ruleset, which the probe writes to the file named by
  `$subject` for `inspect` to load after `ruleset`. A case for a form that
  an older nft rejects sets `rejectedBefore` (a version) and `rejection`,
  the output expected on that nft instead. A case that a newer nft no
  longer misbehaves on, while an older tested one still does, sets
  `fixedFrom` (a version) and `fixed`, the output expected from that nft
  on.
*/
_:
let
  table = {
    family = "inet";
    name = "t";
  };

  /*
    The chain parser unpacks `type`, `hook`, and `prio` as one optional
    group, so a chain with only some of them (`placement`) loads as a
    regular chain that sees no packets. The schema takes all three or
    none.
  */
  partialChainCase = name: placement: {
    inherit name;
    knownDifference = "docs/adr/0010-accept-what-nft-loads-as-written.md";
    ruleset.nftables = [
      {
        add.table = {
          family = "ip";
          name = "t";
        };
      }
      {
        add.chain = {
          family = "ip";
          table = "t";
          name = "c";
        }
        // placement;
      }
    ];
    inspect = "nft list chain ip t c";
    misbehaviour = "table ip t {\n\tchain c {\n\t}\n}\n";
  };

  /*
    nft's rule parser takes handle 0 as no handle, and the kernel deletes
    every rule in a chain for a delete without one, so `verb` with handle
    0 empties chain `c`. The schema requires a positive handle. `destroy`
    also requires an `expr`, which it ignores.
  */
  ruleHandleZeroCase = verb: {
    name = "${verb}-rule-handle-zero-deletes-every-rule";
    knownDifference = "docs/spec-coverage.md";
    ruleset.nftables =
      let
        rule = {
          add.rule = {
            family = "ip";
            table = "t";
            chain = "c";
            expr = [ { counter = null; } ];
          };
        };
      in
      [
        {
          add.table = {
            family = "ip";
            name = "t";
          };
        }
        {
          add.chain = {
            family = "ip";
            table = "t";
            name = "c";
          };
        }
        rule
        rule
      ];
    subject.nftables = [
      {
        ${verb}.rule = {
          family = "ip";
          table = "t";
          chain = "c";
          handle = 0;
          expr = [ ];
        };
      }
    ];
    inspect = ''
      nft -j -f "$subject"
      nft list chain ip t c
    '';
    misbehaviour = "table ip t {\n\tchain c {\n\t}\n}\n";
  };

  resetCounter = name: {
    reset.counter = {
      family = "ip";
      table = "t";
      inherit name;
    };
  };

  # Two seeded counters; `subject` (commands) runs against them in one
  # batch, and the listing shows which reset ran.
  resetCase =
    {
      name,
      subject,
      misbehaviour,
    }:
    {
      inherit name misbehaviour;
      knownDifference = "docs/spec-coverage.md";
      ruleset.nftables =
        let
          counter = name: packets: bytes: {
            add.counter = {
              family = "ip";
              table = "t";
              inherit name packets bytes;
            };
          };
        in
        [
          {
            add.table = {
              family = "ip";
              name = "t";
            };
          }
          (counter "first" 1 2)
          (counter "second" 3 4)
        ];
      subject.nftables = subject;
      inspect = ''
        nft -j -f "$subject" >/dev/null
        nft -j list counters \
          | jq -c '.nftables[] | select(.counter) | .counter
            | { name, packets, bytes }'
      '';
    };

  # A table holding a chain, a ct expectation, and a ct timeout.
  ctObjects.nftables = [
    { add.table = table; }
    {
      add.chain = {
        family = "inet";
        table = "t";
        name = "c";
      };
    }
    {
      add."ct expectation" = {
        family = "inet";
        table = "t";
        name = "ce";
        protocol = "tcp";
        dport = 21;
        timeout = 1000;
        size = 10;
        l3proto = "ip";
      };
    }
    {
      add."ct timeout" = {
        family = "inet";
        table = "t";
        name = "cto";
        protocol = "tcp";
        l3proto = "ip";
        policy.established = 100;
      };
    }
  ];

  # One `verb` command naming the object `name` of `kind` in table t.
  command = verb: kind: name: {
    nftables = [
      {
        ${verb}.${kind} = {
          family = "inet";
          table = "t";
          inherit name;
        };
      }
    ];
  };

  /*
    Loads `$subject` through JSON, then prints its exit status and nft's
    error, BUG, and assertion lines, without their version-specific source
    locations. The braces keep bash's own report of an abort out of the
    output.
  */
  loadSubject = ''
    status=0
    { nft -j -f "$subject" > subject.out 2>&1 || status=$?; } 2>/dev/null
    echo "exit status $status"
    grep -o -e 'Error: .*' -e 'BUG: .*' -e '[a-z_]*: Assertion .* failed' \
      subject.out || true
  '';

  # For delete, list, and destroy, the JSON object-command path passes the
  # kernel object number as nft's command object type: a ct expectation (9)
  # is a table and a ct timeout (7) a chain.
  objectNumberCase = verb: kind: name: description: {
    name = "${verb}-${description}";
    knownDifference = "docs/spec-coverage.md";
    ruleset = ctObjects;
    subject = command verb kind name;
  };

  # A netdev table holding a tunnel; the kernel supports tunnels only in
  # netdev. Its ports differ, so a swapped or dropped port shows in the
  # listing.
  tunnelObjects.nftables = [
    {
      add.table = {
        family = "netdev";
        name = "t";
      };
    }
    {
      add.tunnel = {
        family = "netdev";
        table = "t";
        name = "tun";
        id = 10;
        "src-ipv4" = "192.0.2.1";
        "dst-ipv4" = "192.0.2.2";
        sport = 1111;
        dport = 2222;
        tos = 0;
        ttl = 64;
      };
    }
  ];

  # A tunnel (6) is nft's rules object type, which delete, list, and
  # destroy evaluation doesn't expect, so nft aborts.
  tunnelCommandCase = verb: evaluation: {
    name = "${verb}-tunnel-aborts";
    knownDifference = "docs/spec-coverage.md";
    ruleset = tunnelObjects;
    subject.nftables = [
      {
        ${verb}.tunnel = {
          family = "netdev";
          table = "t";
          name = "tun";
        };
      }
    ];
    inspect = loadSubject;
    misbehaviour = "exit status 134\nBUG: invalid command object type 6\n${evaluation}: Assertion `0' failed\n";
  };

  # nft 1.1.7's delete evaluation falls through from the ct count case to
  # its BUG(); destroy evaluates as delete. 1.1.6 has no ct count object.
  ctCountCase = verb: {
    name = "${verb}-ct-count-aborts";
    knownDifference = "docs/spec-coverage.md";
    ruleset.nftables = [ { add.table = table; } ];
    subject = command verb "ct count" "cc";
    inspect = loadSubject;
    misbehaviour = "exit status 134\nBUG: invalid command object type 39\ncmd_evaluate_delete: Assertion `0' failed\n";
    rejectedBefore = "1.1.7";
    rejection = "exit status 1\nError: Unknown object passed to add command.\nError: Parsing command array at index 0 failed.\n";
  };
in
{
  cases = [
    (partialChainCase "chain-hook-without-type" { hook = "input"; })
    (partialChainCase "chain-type-without-hook" { type = "filter"; })
    (partialChainCase "chain-prio-without-hook" { prio = 0; })
    (partialChainCase "chain-without-prio" {
      type = "filter";
      hook = "input";
    })
    (partialChainCase "chain-without-type" {
      hook = "input";
      prio = 0;
    })
    (partialChainCase "chain-without-hook" {
      type = "filter";
      prio = 0;
    })
    # The set parser never reads `comment`, so JSON loads a commented set
    # or map without it. nft lists the comment of one loaded through text,
    # so the schema accepts it and text refuses it.
    {
      name = "set-comment-ignored-on-json";
      knownDifference = "docs/spec-coverage.md";
      ruleset.nftables = [
        {
          add.table = {
            family = "inet";
            name = "t";
          };
        }
        {
          add.set = {
            family = "inet";
            table = "t";
            name = "s";
            type = "ipv4_addr";
            comment = "a set";
          };
        }
        {
          add.map = {
            family = "inet";
            table = "t";
            name = "m";
            type = "ipv4_addr";
            map = "verdict";
            comment = "a map";
          };
        }
      ];
      inspect = "nft list table inet t";
      misbehaviour = "table inet t {\n\tset s {\n\t\ttype ipv4_addr\n\t}\n\n\tmap m {\n\t\ttype ipv4_addr : verdict\n\t}\n}\n";
    }
    # The element parser reads only `val`, `timeout`, `expires`, and
    # `comment`, so JSON drops element statements, both the keys nft lists
    # and a `stmt` list: set `c`'s seeded counters load as fresh ones, and
    # set `o`, which declares no statement, loads plain elements. Text
    # loads them, so input commands reject the listed keys, Read-back
    # accepts them, and text refuses them.
    {
      name = "element-statements-ignored-on-json";
      knownDifference = "docs/spec-coverage.md";
      ruleset.nftables =
        let
          seededCounter = {
            packets = 1;
            bytes = 2;
          };
          set = name: body: {
            add.set = {
              family = "ip";
              table = "t";
              inherit name;
              type = "ipv4_addr";
            }
            // body;
          };
        in
        [
          {
            add.table = {
              family = "ip";
              name = "t";
            };
          }
          (set "c" {
            stmt = [ { counter = null; } ];
            elem = [
              {
                elem = {
                  val = "10.0.0.1";
                  counter = seededCounter;
                };
              }
              {
                elem = {
                  val = "10.0.0.2";
                  stmt = [ { counter = seededCounter; } ];
                };
              }
            ];
          })
          (set "o" {
            elem = [
              {
                elem = {
                  val = "10.0.0.3";
                  quota = {
                    val = 100;
                    val_unit = "bytes";
                  };
                };
              }
              {
                elem = {
                  val = "10.0.0.4";
                  limit = {
                    rate = 5;
                    per = "second";
                  };
                };
              }
              {
                elem = {
                  val = "10.0.0.5";
                  last.used = 1000;
                };
              }
            ];
          })
        ];
      inspect = "nft list table ip t";
      misbehaviour = "table ip t {\n\tset c {\n\t\ttype ipv4_addr\n\t\tcounter\n\t\telements = { 10.0.0.1 counter packets 0 bytes 0,\n\t\t\t     10.0.0.2 counter packets 0 bytes 0 }\n\t}\n\n\tset o {\n\t\ttype ipv4_addr\n\t\telements = { 10.0.0.3, 10.0.0.4,\n\t\t\t     10.0.0.5 }\n\t}\n}\n";
    }
    /*
      nft 1.1.6's JSON parser ignores a handle on `add rule`, so the rule
      lands at the end of the chain instead of after rule 3. nft 1.1.7, like
      text, places it after rule 3. The schema rejects the handle while a
      tested nft ignores it, and text refuses it.
    */
    {
      name = "add-rule-handle-ignored-on-json";
      knownDifference = "docs/spec-coverage.md";
      ruleset.nftables =
        let
          rule = comment: {
            add.rule = {
              family = "inet";
              table = "t";
              chain = "c";
              expr = [ { accept = null; } ];
              inherit comment;
            };
          };
        in
        [
          { add.table = table; }
          {
            add.chain = {
              family = "inet";
              table = "t";
              name = "c";
            };
          }
          (rule "handle 2")
          (rule "handle 3")
          (rule "handle 4")
        ];
      subject.nftables = [
        {
          add.rule = {
            family = "inet";
            table = "t";
            chain = "c";
            handle = 3;
            expr = [ { accept = null; } ];
            comment = "added";
          };
        }
      ];
      inspect = ''
        nft -j -f "$subject"
        nft -j list chain inet t c \
          | jq -c '[.nftables[] | select(.rule) | .rule.comment]'
      '';
      misbehaviour = ''
        ["handle 2","handle 3","handle 4","added"]
      '';
      fixedFrom = "1.1.7";
      fixed = ''
        ["handle 2","handle 3","added","handle 4"]
      '';
    }
    /*
      nft's JSON parser ignores a handle on `add` and `create`: each object
      loads with the handle the kernel assigns, not the 1000 it was given.
      Text has no spelling for one, so JSON and text disagreed about it.
      The add and create bodies reject a handle, which appears in Read-back
      (ADR 0009). The `add rule` case above covers rules.
    */
    {
      name = "add-handle-ignored";
      knownDifference = "docs/adr/0010-accept-what-nft-loads-as-written.md";
      ruleset.nftables =
        let
          handle = 1000;
          object = kind: body: {
            add.${kind} = {
              family = "inet";
              table = "t";
              inherit handle;
            }
            // body;
          };
        in
        [
          {
            add.table = table // {
              inherit handle;
            };
          }
          (object "chain" { name = "c"; })
          (object "set" {
            name = "s";
            type = "ipv4_addr";
          })
          (object "counter" { name = "k"; })
          (object "flowtable" {
            name = "f";
            hook = "ingress";
            prio = 0;
          })
          {
            create.quota = {
              family = "inet";
              table = "t";
              name = "q";
              inherit handle;
            };
          }
        ];
      inspect = ''
        nft -j list ruleset \
          | jq -r '.nftables[] | to_entries[] | select(.key != "metainfo")
            | (if .value.handle == 1000 then "kept" else "ignored" end)
              as $handle
            | "\(.key) handle \($handle)"'
      '';
      misbehaviour = ''
        table handle ignored
        chain handle ignored
        counter handle ignored
        quota handle ignored
        set handle ignored
        flowtable handle ignored
      '';
    }
    /*
      nft's JSON parser takes a number where a stateful object Reference
      names its object, and loads it as the object named by the number's
      digits: `{ "ct helper" = 5; }` references the helper named "5". The
      schema takes a name, such as "5", or a map. A secmark Reference loads
      the same way, but a secmark object needs SELinux, so the case leaves
      it out.
    */
    {
      name = "number-reference-loads-as-name";
      knownDifference = "docs/adr/0010-accept-what-nft-loads-as-written.md";
      ruleset.nftables =
        let
          object = kind: body: {
            add.${kind} = {
              family = "inet";
              table = "t";
              name = "5";
            }
            // body;
          };
          referenceRule = kind: {
            add.rule = {
              family = "inet";
              table = "t";
              chain = "c";
              expr = [ { ${kind} = 5; } ];
            };
          };
          kinds = [
            "ct helper"
            "ct timeout"
            "ct expectation"
            "synproxy"
          ];
        in
        [
          { add.table = table; }
          {
            add.chain = {
              family = "inet";
              table = "t";
              name = "c";
            };
          }
          (object "ct helper" {
            type = "ftp";
            protocol = "tcp";
          })
          (object "ct timeout" {
            protocol = "tcp";
            l3proto = "ip";
            policy.established = 100;
          })
          (object "ct expectation" {
            protocol = "tcp";
            dport = 21;
            timeout = 100;
            size = 10;
            l3proto = "ip";
          })
          (object "synproxy" {
            mss = 1460;
            wscale = 7;
          })
        ]
        ++ map referenceRule kinds;
      inspect = ''
        nft -j list chain inet t c \
          | jq -c '.nftables[] | select(.rule) | .rule.expr[]'
      '';
      misbehaviour = ''
        {"ct helper":"5"}
        {"ct timeout":"5"}
        {"ct expectation":"5"}
        {"synproxy":"5"}
      '';
    }
    # nft's JSON parser rejects a listed meter, which the schema accepts
    # as Read-back, and nft's text has no meter object, so text refuses
    # one. A JSON parser that loads one fails this case.
    {
      name = "listed-meter-rejected-on-json";
      knownDifference = "docs/text-coverage.md";
      ruleset.nftables = [ { add.table = table; } ];
      subject.nftables = [
        {
          meter = {
            family = "inet";
            table = "t";
            name = "m";
            handle = 2;
          };
        }
      ];
      inspect = loadSubject;
      misbehaviour = "exit status 1\nError: Unknown object passed to add command.\nError: Parsing command array at index 0 failed.\n";
    }

    # Deleting or destroying a ct expectation deletes its whole table, and
    # exits 0.
    (
      objectNumberCase "delete" "ct expectation" "ce" "ct-expectation-deletes-table"
      // {
        inspect = "${loadSubject}nft list tables";
        misbehaviour = "exit status 0\n";
      }
    )
    (
      objectNumberCase "destroy" "ct expectation" "ce" "ct-expectation-deletes-table"
      // {
        inspect = "${loadSubject}nft list tables";
        misbehaviour = "exit status 0\n";
      }
    )
    # Listing a ct expectation lists the whole table.
    (
      objectNumberCase "list" "ct expectation" "ce" "ct-expectation-lists-table"
      // {
        inspect = "nft -j -f \"$subject\" | jq -c '[.nftables[] | keys[0]]'";
        misbehaviour = ''
          ["metainfo","table","chain","ct expectation","ct timeout"]
        '';
      }
    )
    # Deleting a ct timeout fails, destroying one is reported unsupported,
    # and listing one aborts.
    (
      objectNumberCase "delete" "ct timeout" "cto" "ct-timeout-fails"
      // {
        inspect = loadSubject;
        misbehaviour = "exit status 1\nError: Could not process rule: Invalid argument\n";
      }
    )
    (
      objectNumberCase "destroy" "ct timeout" "cto" "ct-timeout-unsupported"
      // {
        inspect = loadSubject;
        misbehaviour = "exit status 1\nError: \"destroy\" command is not supported, perhaps kernel support is missing?\n";
      }
    )
    (
      objectNumberCase "list" "ct timeout" "cto" "ct-timeout-aborts"
      // {
        inspect = loadSubject;
        misbehaviour = "exit status 134\nchain_cache_find: Assertion `name' failed\n";
      }
    )
    (ctCountCase "delete")
    (ctCountCase "destroy")

    # The tunnel parser assigns `dport` to the tunnel's sport and leaves its
    # dport unset, so a tunnel loads with its destination port as source
    # port and no destination port.
    {
      name = "tunnel-dport-loads-as-sport";
      knownDifference = "docs/spec-coverage.md";
      ruleset = tunnelObjects;
      inspect = "nft -j list ruleset | jq -c '.nftables[] | select(.tunnel) | .tunnel | { sport, dport }'";
      misbehaviour = ''
        {"sport":2222,"dport":0}
      '';
    }
    (ruleHandleZeroCase "delete")
    (ruleHandleZeroCase "destroy")
    # The set parser returns before it reads `elem` on delete, so `delete
    # set` with elements deletes the whole set. A set's Selector takes no
    # elements; `delete element` deletes some.
    {
      name = "delete-set-elem-deletes-whole-set";
      knownDifference = "docs/adr/0010-accept-what-nft-loads-as-written.md";
      ruleset.nftables = [
        { add.table = table; }
        {
          add.set = {
            family = "inet";
            table = "t";
            name = "s";
            type = "ipv4_addr";
            elem = [
              "10.0.0.1"
              "10.0.0.2"
            ];
          };
        }
      ];
      subject.nftables = [
        {
          delete.set = {
            family = "inet";
            table = "t";
            name = "s";
            elem = [ "10.0.0.1" ];
          };
        }
      ];
      inspect = ''
        nft -j -f "$subject"
        nft list table inet t
      '';
      misbehaviour = "table inet t {\n}\n";
    }
    (tunnelCommandCase "delete" "cmd_evaluate_delete")
    (tunnelCommandCase "destroy" "cmd_evaluate_delete")
    (tunnelCommandCase "list" "cmd_evaluate_list")

    /*
      In one batch, nft runs a reset of a counter, quota, set, map, or rule
      only as the last command: here the first reset prints nothing,
      resets nothing, and nft exits 0. `types.ruleset` rejects a reset
      anywhere else.
    */
    (resetCase {
      name = "reset-runs-only-the-last";
      subject = [
        (resetCounter "first")
        (resetCounter "second")
      ];
      misbehaviour = ''
        {"name":"first","packets":1,"bytes":2}
        {"name":"second","packets":0,"bytes":0}
      '';
    })
    # Any command after the reset drops it, not only another reset.
    (resetCase {
      name = "reset-before-another-command-resets-nothing";
      subject = [
        (resetCounter "first")
        {
          add.table = {
            family = "ip";
            name = "x";
          };
        }
      ];
      misbehaviour = ''
        {"name":"first","packets":1,"bytes":2}
        {"name":"second","packets":3,"bytes":4}
      '';
    })
    /*
      The payload parser looks a field up among all of a protocol's
      templates, the `meta l4proto` dependency's included, so `ip l4proto`
      loads as the header bits at offset 0: `ip version` and `ip
      hdrlength`. `expr.payload` takes only the fields nft loads as
      written (lib/schema/payload-fields.nix).
    */
    {
      name = "payload-l4proto-loads-header-field";
      knownDifference = "docs/spec-coverage.md";
      ruleset.nftables = [
        { add.table = table; }
        {
          add.chain = {
            family = "inet";
            table = "t";
            name = "c";
          };
        }
        {
          add.rule = {
            family = "inet";
            table = "t";
            chain = "c";
            expr = [
              {
                match = {
                  op = "==";
                  left.payload = {
                    protocol = "ip";
                    field = "l4proto";
                  };
                  right = 6;
                };
              }
            ];
          };
        }
      ];
      inspect = "nft list chain inet t c";
      misbehaviour = "table inet t {\n\tchain c {\n\t\tip version 0 ip hdrlength 6\n\t}\n}\n";
    }
  ];
}
