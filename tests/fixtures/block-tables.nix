# Table nodes shared by the block-form parity suite and the
# text-block-integration check.
{ dsl }:
let
  baseChain = {
    type = "filter";
    hook = "input";
    prio = 0;
  };
in
rec {
  inherit baseChain;

  limitTable = dsl.table "inet" "fw" {
    chains.input.rules = [
      [
        (dsl.limit {
          rate = 10;
          per = "minute";
          inv = true;
          rate_unit = "kbytes";
          burst = 5;
          burst_unit = "bytes";
        })
      ]
      [
        (dsl.limit.ref "slow")
        dsl.accept
      ]
    ];
    limits.slow = {
      rate = 5;
      per = "second";
      burst = 10;
      comment = "packet budget";
    };
  };

  # Exercise references in both directions: chains use named objects,
  # and verdict-map elements refer back to a chain. Intentionally declare
  # fields out of output order; rules within service must keep source order.
  referencedTable = dsl.table "inet" "fw" {
    chains.service.rules = [
      [
        (dsl.inSet dsl.fields.ip.saddr "@trusted")
        (dsl.counter.ref "hits")
        dsl.accept
      ]
      [ dsl.drop ]
    ];
    chains.input = baseChain // {
      rules = [ [ (dsl.vmap dsl.fields.tcp.dport "@dispatch") ] ];
    };
    sets.trusted = {
      type = "ipv4_addr";
      elements = [ "192.0.2.1" ];
    };
    maps.dispatch = {
      type = "inet_service";
      map = "verdict";
      elements = [
        [
          22
          (dsl.jump "service")
        ]
      ];
    };
    counters.hits = { };
  };

  # Tables the text-block-integration probe sends to the live parser.
  integrationTables = {
    inline-and-named-limits = limitTable;
    chain-object-references = referencedTable;
    minimal-base-chain = dsl.table "inet" "fw" { chains.input = baseChain; };
    chain-with-rules = dsl.table "inet" "fw" {
      chains.input = baseChain // {
        policy = "drop";
        rules = [
          [ dsl.accept ]
          [ dsl.drop ]
        ];
      };
    };
    mixed-chain-set-counter = dsl.table "inet" "fw" {
      chains.input = baseChain // {
        rules = [ [ dsl.accept ] ];
      };
      sets.lan_v4 = {
        type = "ipv4_addr";
        flags = [ "interval" ];
      };
      counters.hits = { };
    };
    set-with-inline-elements = dsl.table "inet" "fw" {
      sets.blocked = {
        type = "ipv4_addr";
        elements = [ "192.0.2.1" ];
      };
    };
  };
}
