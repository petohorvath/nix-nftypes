{ lib }:

# Context-threading tree builders. `family`/`table`/`chain` flow from
# outer builders into inner leaves via an explicit context argument.
#
# Shape:
#   mkRuleset children          :: AttrSet           (top-level envelope)
#   mkTable args children       :: [Command]         (provides ctx to children)
#   mkChain args children       :: ctx -> [Command]  (threads ctx down)
#   declareChain args           :: ctx -> [Command]  (mkChain with no rules)
#   mkRule stmts|args           :: ctx -> [Command]  (leaf)
#   mk<NamedObject> args        :: ctx -> [Command]  (leaf, family/table only)
#
# Children of mkTable / mkChain may be:
#   - a function of ctx (threaded builder)
#   - a list of commands (flat passthrough, e.g. from a nested builder)
#   - a single command attrset (raw or DSL-produced, context-free)
#
# Named-object builders pass `args` through to the schema unchanged, so any
# hyphenated keys (`gc-interval`, `src-ipv4`, …) can be written as quoted
# attributes. Required-field validation happens at `evalModules` time
# rather than at DSL call time.

let
  compact = lib.filterAttrs (_: v: v != null);

  # Normalize one child into a command list. `ctx == null` means "top level";
  # children that need ctx must not appear there.
  resolveChild =
    ctx: c:
    if builtins.isFunction c then
      if ctx == null then
        throw "nftlib.dsl: child requires a context (family/table) — wrap it in mkTable"
      else
        c ctx
    else if builtins.isList c then
      c
    else if builtins.isAttrs c then
      [ c ]
    else
      throw "nftlib.dsl: invalid child — expected attrset, list, or ctx-function";

  resolveChildren = ctx: children: lib.concatMap (resolveChild ctx) children;

  # Factory: create a context-threaded builder for a named object kind.
  # The resulting builder takes the object's fields as an attrset, threads
  # `family`/`table` from ctx, and emits a single `add` command.
  mkObjectBuilder =
    kind: args: ctx:
    [
      {
        add = {
          ${kind} = compact (
            { inherit (ctx) family table; } // args
          );
        };
      }
    ];
in
rec {
  # -- Top-level envelope ---------------------------------------------------

  mkRuleset = children: {
    nftables = resolveChildren null children;
  };

  # -- Chain-context injection (without emitting a chain declaration) -------
  # Useful when chains are declared up-front and rules are appended later.
  inChain =
    chainName: children: ctx:
    resolveChildren (ctx // { chain = chainName; }) children;

  # -- Flush ruleset --------------------------------------------------------

  flushRuleset = { flush = { ruleset = null; }; };

  # -- Table -----------------------------------------------------------------

  mkTable =
    {
      family,
      name,
      handle ? null,
      flags ? null,
      comment ? null,
    }:
    children:
    let
      tableBody = compact { inherit family name handle flags comment; };
      tableCmd = { add = { table = tableBody; }; };
      ctx = { inherit family; table = name; };
    in
    [ tableCmd ] ++ resolveChildren ctx children;

  # -- Chain -----------------------------------------------------------------

  mkChain =
    {
      name,
      type ? null,
      hook ? null,
      prio ? null,
      dev ? null,
      policy ? null,
      handle ? null,
      comment ? null,
    }:
    children:
    ctx:
    let
      chainBody = compact {
        inherit (ctx) family table;
        inherit
          name
          type
          hook
          prio
          dev
          policy
          handle
          comment
          ;
      };
      chainCmd = { add = { chain = chainBody; }; };
      chainCtx = ctx // { chain = name; };
    in
    [ chainCmd ] ++ resolveChildren chainCtx children;

  # Convenience: declare a chain with no inline rules. Use `inChain` to
  # append rules afterwards.
  declareChain = args: mkChain args [ ];

  # -- Rule ------------------------------------------------------------------

  # Accepts either a list of statements (sugar) or a full attrset with `expr`
  # plus optional handle/index/comment.
  mkRule =
    x: ctx:
    let
      args = if builtins.isList x then { expr = x; } else x;
      ruleBody = compact (
        { inherit (ctx) family table chain; } // args
      );
    in
    [ { add = { rule = ruleBody; }; } ];

  # -- Named object builders -------------------------------------------------
  # All share the same pattern: `args` is merged with ctx's family/table,
  # compacted, and wrapped in `add.<kind>`. Per-kind required/optional
  # fields are enforced by the schema at evalModules time.

  mkSet = mkObjectBuilder "set";
  mkMap = mkObjectBuilder "map";
  mkElement = mkObjectBuilder "element";
  mkFlowtable = mkObjectBuilder "flowtable";
  mkCounter = mkObjectBuilder "counter";
  mkQuota = mkObjectBuilder "quota";
  mkLimitObject = mkObjectBuilder "limit";
  mkCTHelper = mkObjectBuilder "ct helper";
  mkCTTimeout = mkObjectBuilder "ct timeout";
  mkCTExpectation = mkObjectBuilder "ct expectation";
  mkSecmark = mkObjectBuilder "secmark";
  mkSynproxy = mkObjectBuilder "synproxy";
  mkTunnel = mkObjectBuilder "tunnel";
}
