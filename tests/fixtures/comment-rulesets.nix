# One ruleset builder per comment-like surface. Each takes the string
# under test and places it in the only interesting field.
{ dsl }:
{
  # Build a minimal ruleset whose only interesting field is `comment` on a
  # table — the directly-exploitable surface.
  tableComment =
    comment:
    dsl.ruleset [
      (dsl.table "inet" "t" {
        inherit comment;
        chains.c = {
          type = "filter";
          hook = "input";
          prio = 0;
          policy = "accept";
          rules = [ [ dsl.accept ] ];
        };
      })
    ];

  chainComment =
    comment:
    dsl.ruleset [
      (dsl.table "inet" "t" {
        chains.c = {
          inherit comment;
          type = "filter";
          hook = "input";
          prio = 0;
          policy = "accept";
          rules = [ [ dsl.accept ] ];
        };
      })
    ];

  ruleComment =
    comment:
    dsl.ruleset [
      (dsl.table "inet" "t" {
        chains.c = {
          type = "filter";
          hook = "input";
          prio = 0;
          policy = "accept";
          rules = [
            {
              expr = [ dsl.accept ];
              inherit comment;
            }
          ];
        };
      })
    ];

  elementComment =
    comment:
    dsl.ruleset [
      (dsl.table "inet" "t" {
        sets.s = {
          type = "ipv4_addr";
          elem = [
            {
              elem = {
                val = "1.2.3.4";
                inherit comment;
              };
            }
          ];
        };
        chains.c = {
          type = "filter";
          hook = "input";
          prio = 0;
          policy = "accept";
          rules = [ [ dsl.accept ] ];
        };
      })
    ];

  logPrefix =
    prefix:
    dsl.ruleset [
      (dsl.table "inet" "t" {
        chains.c = {
          type = "filter";
          hook = "input";
          prio = 0;
          policy = "accept";
          rules = [ [ (dsl.log { inherit prefix; }) ] ];
        };
      })
    ];
}
