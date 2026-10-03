# One ruleset builder per surface where an interface name reaches the
# renderers. The `*List` builders take a list of names; the others take
# one name.
{ dsl }:
rec {
  setElem = elem: setElemList [ elem ];

  setElemList =
    elems:
    dsl.ruleset [
      (dsl.table "inet" "fw" {
        sets.iifs = {
          type = "ifname";
          elements = elems;
        };
      })
    ];

  # Same set but the element carries options (`{ elem = { val; … }; }`):
  # the cross-field walker has to dig through the wrapper.
  setElemWithOptions =
    elem:
    dsl.ruleset [
      (dsl.table "inet" "fw" {
        sets.iifs = {
          type = "ifname";
          elements = [
            {
              elem = {
                val = elem;
                comment = "ok";
              };
            }
          ];
        };
      })
    ];

  # Map keyed on ifname. The key is the typed slot (the map's `type`
  # describes its key datatype), so `[k, v]` element pairs need their
  # KEY validated.
  mapKey =
    key:
    dsl.ruleset [
      (dsl.table "inet" "fw" {
        maps.iif_marks = {
          type = "ifname";
          map = "mark";
          elements = [
            [
              key
              1
            ]
          ];
        };
      })
    ];

  # netdev-family base chain bound to an ifname. Single-dev string
  # form — the schema types `chain.dev` as `listOrSingleton ifname`.
  chainDevString =
    dev:
    dsl.ruleset [
      (dsl.table "netdev" "t" {
        chains.ingress = {
          type = "filter";
          hook = "ingress";
          prio = 0;
          inherit dev;
          rules = [ [ dsl.accept ] ];
        };
      })
    ];

  # netdev-family base chain bound to a list of ifnames — the path
  # the audit's widening PoC exercises.
  chainDevList =
    devs:
    dsl.ruleset [
      (dsl.table "netdev" "t" {
        chains.ingress = {
          type = "filter";
          hook = "ingress";
          prio = 0;
          dev = devs;
          rules = [ [ dsl.accept ] ];
        };
      })
    ];

  # Flowtable dev field — same `listOrSingleton ifname` shape as
  # chain.dev; rendered as `devices = { … }` inside the flowtable
  # body.
  flowtableDevString =
    dev:
    dsl.ruleset [
      (dsl.table "inet" "t" {
        flowtables.ft = {
          hook = "ingress";
          prio = 0;
          inherit dev;
        };
      })
    ];

  flowtableDevList =
    devs:
    dsl.ruleset [
      (dsl.table "inet" "t" {
        flowtables.ft = {
          hook = "ingress";
          prio = 0;
          dev = devs;
        };
      })
    ];
}
