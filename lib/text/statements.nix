{
  lib,
  context,
  primitives,
  expressions,
  nftSafeIfname,
}:

# Renderer for the `statement` attrTag union (lib/schema/statements.nix).
#
# Statements appear inside a rule body, separated by `; ` in compact mode
# or newline+indent in pretty mode (the join is done by the rule renderer
# in lib/text/objects.nix).
#
# Most statements are thin wrappers around expressions; the trickier ones
# are NAT (snat/dnat/redirect/masquerade) with their flag combinations,
# and counter/quota/limit which accept either a named reference (string)
# or an inline body.

let
  inherit (context) resetPrec;
  inherit (expressions) renderExpression safeToken;
  inherit (lib) optionalString;

  # ---- helpers ---------------------------------------------------------

  rExpr = ctx: e: renderExpression (resetPrec ctx) e;

  # Render a list of natFlags as a comma-separated suffix. NAT statements
  # accept a single flag string or a list (listOrSingleton).
  renderNatFlags =
    flags:
    if flags == null then
      ""
    else
      let
        items = if builtins.isList flags then flags else [ flags ];
      in
      " " + lib.concatStringsSep "," items;

  # Render the `to <addr>[:<port>]` or `to :<port>` clause shared by NAT-
  # family statements. addr can be null (port-only translation).
  renderNatTo =
    ctx: addr: port:
    if addr == null && port == null then
      ""
    else
      " to "
      + (if addr == null then "" else rExpr ctx addr)
      + (if port == null then "" else ":${rExpr ctx port}");

  # ---- per-tag renderers ----------------------------------------------

  # Verdicts/jump/goto live in expressions.nix (they're valid in both
  # statement and expression position). We reuse those renderers verbatim
  # rather than maintaining a parallel pair here.
  inherit (expressions) renderVerdict renderJump renderGoto;

  # Meta keys whose value is an interface-name string (kernel's
  # `dev_valid_name` rules). Matches against these keys take an ifname
  # RHS, which nft's grammar wants quoted when the string contains
  # special characters — bare `meta iifname eth0,eth1` lexes the `,`
  # as a bitmask operator and rejects ifname as a non-bitmask type
  # (audit-noted UX issue; not silent widening, but unhelpful).
  ifnameMetaKeys = [
    "iifname"
    "oifname"
    "sdifname"
    "ibrname"
    "obrname"
  ];

  # True iff the match LHS is a key whose RHS string should be treated
  # as an ifname (quoted, validated). Currently handles `meta <key>` for
  # the keys above and `fib … oifname` (whose result token returns the
  # interface name as a string).
  isIfnameLhs =
    lhs:
    if !(builtins.isAttrs lhs) then
      false
    else
      let
        names = builtins.attrNames lhs;
      in
      if builtins.length names != 1 then
        false
      else
        let
          tag = builtins.head names;
          body = lhs.${tag};
        in
        if tag == "meta" then
          builtins.elem (body.key or null) ifnameMetaKeys
        else if tag == "fib" then
          (body.result or null) == "oifname"
        else
          false;

  # match: `<left> <op> <right>`. `==` and `in` are elided in nft text:
  # equality is implicit, and set/range membership (op = "in") is
  # expressed by adjacency with no operator. Other operators always emit.
  #
  # When LHS is an ifname-typed key and RHS is a plain string (not an
  # `@`-prefixed set reference), the string is asserted ifname-safe and
  # emitted quoted: `meta iifname "eth0"`. This makes character-set
  # mistakes a render-time error rather than a confusing nft parse
  # error or kernel activation error. Set / range / setRef / other
  # tagged RHS shapes are left to renderExpression, which keeps the
  # existing set-literal-element handling intact.
  renderMatch =
    ctx:
    {
      left,
      op,
      right,
    }:
    let
      lhs = rExpr ctx left;
      ifnameRhs = isIfnameLhs left && builtins.isString right && !(lib.hasPrefix "@" right);
      rhs =
        if ifnameRhs then
          let
            bad = if nftSafeIfname.isSafe right then null else right;
          in
          if bad == null then
            primitives.string right
          else
            throw ''
              nftypes: refusing to render an ifname-typed match RHS ${builtins.toJSON bad} that is not a safe interface name (see lib/nft-safe-ifname.nix). The kernel's `dev_valid_name` already rejects '/' ':' whitespace and '.' / '..' / >15-byte names; this assert additionally rejects ',' ';' '{' '}' '"' '\' '#' and control characters, because such a value can never resolve to a real interface and nft's text parser may also misread unquoted special characters as operators. Offending value: ${builtins.toJSON bad}.
            ''
        else
          rExpr ctx right;
    in
    if op == "==" || op == "in" then "${lhs} ${rhs}" else "${lhs} ${op} ${rhs}";

  # counter: null → bare "counter"; str → named reference;
  # attrset → inline `counter packets P bytes B` (each optional).
  renderCounter =
    _ctx: body:
    if body == null then
      "counter"
    else if builtins.isString body then
      "counter name ${primitives.string body}"
    else
      let
        parts = [
          "counter"
        ]
        ++ lib.optional ((body.packets or null) != null) "packets ${toString body.packets}"
        ++ lib.optional ((body.bytes or null) != null) "bytes ${toString body.bytes}";
      in
      lib.concatStringsSep " " parts;

  # mangle: `<key> set <value>`. The schema allows any expression for both
  # sides; payload/meta/ct mangling all flow through this shape.
  renderMangle = ctx: { key, value }: "${rExpr ctx key} set ${rExpr ctx value}";

  # quota: str → named ref; attrset → `quota [over] <val> <unit> [used <u> <unit>]`.
  # `inv = true` flips the implicit "until" to "over". `val_unit` and
  # `used_unit` are `types.str` in the schema and render bare into the
  # output, so each flows through `safeToken` to reject parser-meta
  # bytes that would otherwise terminate the statement.
  renderQuota =
    _ctx: body:
    if builtins.isString body then
      "quota name ${primitives.string body}"
    else
      let
        head = "quota" + optionalString ((body.inv or null) == true) " over";
        valPart =
          " ${toString body.val}"
          + optionalString ((body.val_unit or null) != null) " ${safeToken body.val_unit}";
        usedPart =
          if (body.used or null) == null then
            ""
          else
            " used ${toString body.used}"
            + optionalString ((body.used_unit or null) != null) " ${safeToken body.used_unit}";
      in
      head + valPart + usedPart;

  # limit: str → named ref; attrset → `limit rate [over] <r> [<unit>]/<per> [burst N <unit>]`.
  # `rate_unit` / `burst_unit` are `types.str` rendered bare; same
  # `safeToken` treatment as quota above.
  renderLimit =
    _ctx: body:
    if builtins.isString body then
      "limit name ${primitives.string body}"
    else
      let
        head = "limit rate" + optionalString ((body.inv or null) == true) " over";
        rateUnit = optionalString ((body.rate_unit or null) != null) " ${safeToken body.rate_unit}";
        ratePart = " ${toString body.rate}${rateUnit}/${body.per}";
        burstPart =
          if (body.burst or null) == null then
            ""
          else
            # nft -f requires an explicit unit after `burst <N>`. The
            # libnftables JSON path treats burst_unit as optional and
            # defaults to "packets" when rate is in packets; the text
            # parser doesn't infer this, so we emit it explicitly.
            let
              burstUnit = if (body.burst_unit or null) != null then safeToken body.burst_unit else "packets";
            in
            " burst ${toString body.burst} ${burstUnit}";
      in
      head + ratePart + burstPart;

  # fwd: `fwd to <dev>` or `fwd to <addr> family <fam> via <dev>`.
  renderFwd =
    ctx:
    {
      dev,
      family ? null,
      addr ? null,
    }:
    if addr == null then
      "fwd to ${rExpr ctx dev}"
    else
      "fwd to ${rExpr ctx addr}"
      + optionalString (family != null) " family ${family}"
      + " via ${rExpr ctx dev}";

  # dup: `dup to <addr> [device <dev>]`.
  renderDup =
    ctx:
    {
      addr,
      dev ? null,
    }:
    "dup to ${rExpr ctx addr}" + optionalString (dev != null) " device ${rExpr ctx dev}";

  # NAT — snat/dnat share the same body. `addr` is omitted for port-only
  # translation; `family` precedes `to`; `port` is appended `:port`. flags
  # and type_flags are comma-joined and appended after the addr/port.
  renderNat =
    name: ctx:
    {
      addr ? null,
      family ? null,
      port ? null,
      flags ? null,
      type_flags ? null,
    }:
    let
      head = name + optionalString (family != null) " ${family}";
      to = renderNatTo ctx addr port;
      flagsStr = renderNatFlags flags;
      typeStr = renderNatFlags type_flags;
    in
    head + to + flagsStr + typeStr;

  # masquerade/redirect — port-only NAT-family statements. Same body shape.
  renderMasq =
    name: ctx:
    {
      port ? null,
      flags ? null,
    }:
    name + (if port == null then "" else " to :${rExpr ctx port}") + renderNatFlags flags;

  # reject: `reject [with <type> [<expr>]]`.
  renderReject =
    ctx:
    {
      type ? null,
      expr ? null,
    }:
    if type == null && expr == null then
      "reject"
    else
      "reject with ${type}" + optionalString (expr != null) " ${rExpr ctx expr}";

  # set/map dynamic-update statement: `<op> @<set> { <elem>[ : <data>] [stmt]* }`.
  # The schema types `set`/`map` as `types.str`; the renderer prepends `@`
  # and would otherwise emit the rest bare. `safeToken` rejects any byte
  # outside the bare-token grammar, including a newline + trailing statement
  # payload that would have parsed as a fresh nft command at rule scope.
  renderSetStmt =
    ctx:
    {
      op,
      elem,
      set,
      stmt ? null,
    }:
    let
      stmts =
        if stmt == null then
          ""
        else
          " " + lib.concatMapStringsSep " " (renderStatement (resetPrec ctx)) stmt;
    in
    "${op} @${safeToken set} { ${rExpr ctx elem}${stmts} }";

  renderMapStmt =
    ctx:
    {
      op,
      elem,
      data,
      map,
      stmt ? null,
    }:
    let
      stmts =
        if stmt == null then
          ""
        else
          " " + lib.concatMapStringsSep " " (renderStatement (resetPrec ctx)) stmt;
    in
    "${op} @${safeToken map} { ${rExpr ctx elem} : ${rExpr ctx data}${stmts} }";

  # log: `log [prefix "..."] [group N] [snaplen N] [queue-threshold N] [level L] [flags ...]`.
  renderLog =
    _ctx: body:
    let
      parts = [
        "log"
      ]
      ++ lib.optional ((body.prefix or null) != null) "prefix ${primitives.string body.prefix}"
      ++ lib.optional ((body.group or null) != null) "group ${toString body.group}"
      ++ lib.optional ((body.snaplen or null) != null) "snaplen ${toString body.snaplen}"
      ++
        lib.optional ((body."queue-threshold" or null) != null)
          "queue-threshold ${toString body."queue-threshold"}"
      ++ lib.optional ((body.level or null) != null) "level ${body.level}"
      ++
        lib.optional ((body.flags or null) != null)
          "flags ${primitives.flags { sep = " "; } body.flags}";
    in
    lib.concatStringsSep " " parts;

  # meter: `meter <name> [size N] { <key> <stmt> }`. The single trailing
  # statement is rendered inline.
  renderMeter =
    ctx:
    {
      name,
      key,
      stmt,
      size ? null,
    }:
    "meter ${primitives.identQuote name}"
    + optionalString (size != null) " size ${toString size}"
    + " { ${rExpr ctx key} ${renderStatement (resetPrec ctx) stmt} }";

  # queue: `queue` / `queue num <expr>` / `queue flags ... num <expr>`.
  renderQueue =
    ctx:
    {
      num ? null,
      flags ? null,
    }:
    let
      flagsStr = optionalString (flags != null) " flags ${primitives.flags { sep = ","; } flags}";
      numStr = if num == null then "" else " num ${rExpr ctx num}";
    in
    "queue" + flagsStr + numStr;

  # vmap: `<key> vmap <data>` — verdict-map dispatch as a statement.
  renderVmap = ctx: { key, data }: "${rExpr ctx key} vmap ${rExpr ctx data}";

  # ct count: `ct count <val>` or `ct count over <val>`.
  renderCtCount =
    _ctx:
    {
      val,
      inv ? null,
    }:
    "ct count" + optionalString (inv == true) " over" + " ${toString val}";

  # xt: deprecated escape hatch. Render as `xt <type> "<name>"`.
  renderXt = _ctx: { type, name }: "xt ${type} ${primitives.string name}";

  # last: `last [used <ms>]`. Body can be null or { used }.
  renderLast = _ctx: body: if body == null then "last" else "last used ${toString body.used}";

  # flow <op> <flowtable-ref>. The schema-level convention is that
  # `flowtable` includes the leading `@`, so the renderer emits the
  # value as-is. `safeToken` covers both `@name` and bare `name`
  # (the predicate's safe-byte set includes `@`), so an unsafe byte
  # in either form throws before reaching the output stream.
  renderFlow = _ctx: { op, flowtable }: "flow ${op} ${safeToken flowtable}";

  # tproxy: like dnat, but `to` syntax.
  renderTproxy =
    ctx:
    {
      family ? null,
      addr ? null,
      port ? null,
    }:
    "tproxy" + optionalString (family != null) " ${family}" + renderNatTo ctx addr port;

  # synproxy: bare / inline / named-reference (expr).
  renderSynproxy =
    ctx: body:
    if body == null then
      "synproxy"
    else if builtins.isAttrs body && body ? mss && body ? wscale then
      let
        head = "synproxy mss ${toString body.mss} wscale ${toString body.wscale}";
        flagsStr =
          if (body.flags or null) == null then "" else " " + primitives.flags { sep = " "; } body.flags;
      in
      head + flagsStr
    else
      # Named-reference expression. nft accepts either a bare name or a
      # quoted string.
      "synproxy name ${rExpr ctx body}";

  # reset: `reset <expr>` — typically `reset tcp option <name>`.
  renderReset = ctx: body: "reset ${rExpr ctx body}";

  # secmark / tunnel / ct helper / ct timeout / ct expectation — all are
  # `set` assignment shortcuts. Body is an expression that is, in practice,
  # always a string naming the referenced object. nft text requires the
  # name to be quoted.
  renderAssign =
    name: ctx: body:
    let
      rendered = if builtins.isString body then primitives.string body else rExpr ctx body;
    in
    "${name} set ${rendered}";

  # ---- dispatch table -------------------------------------------------

  taggedRenderers = {
    accept = renderVerdict "accept";
    drop = renderVerdict "drop";
    continue = renderVerdict "continue";
    return = renderVerdict "return";
    notrack = renderVerdict "notrack";
    jump = renderJump;
    goto = renderGoto;
    match = renderMatch;
    counter = renderCounter;
    mangle = renderMangle;
    quota = renderQuota;
    limit = renderLimit;
    fwd = renderFwd;
    dup = renderDup;
    snat = renderNat "snat";
    dnat = renderNat "dnat";
    masquerade = renderMasq "masquerade";
    redirect = renderMasq "redirect";
    reject = renderReject;
    set = renderSetStmt;
    map = renderMapStmt;
    log = renderLog;
    meter = renderMeter;
    queue = renderQueue;
    vmap = renderVmap;
    "ct count" = renderCtCount;
    xt = renderXt;
    last = renderLast;
    flow = renderFlow;
    tproxy = renderTproxy;
    synproxy = renderSynproxy;
    reset = renderReset;
    secmark = renderAssign "meta secmark";
    tunnel = renderAssign "meta tunnel";
    "ct helper" = renderAssign "ct helper";
    "ct timeout" = renderAssign "ct timeout";
    "ct expectation" = renderAssign "ct expectation";
  };

  renderStatement =
    ctx: v:
    if !(builtins.isAttrs v) then
      throw "text.statements: statement must be an attrset, got ${builtins.typeOf v}"
    else
      let
        names = builtins.attrNames v;
      in
      if builtins.length names != 1 then
        throw "text.statements: statement must have exactly one tag, got [${lib.concatStringsSep ", " names}]"
      else
        let
          tag = builtins.head names;
        in
        if !(taggedRenderers ? ${tag}) then
          throw "text.statements: no renderer for tag '${tag}'"
        else
          taggedRenderers.${tag} ctx v.${tag};

  # Render a rule body — the list of statements joined by space. Each
  # statement is rendered into its compact form. The resulting string does
  # not have a trailing newline; the rule renderer in objects.nix decides
  # how it sits inside the chain block.
  renderRuleExpr = ctx: stmts: lib.concatMapStringsSep " " (renderStatement ctx) stmts;
in
{
  inherit
    renderStatement
    renderRuleExpr
    ;
  # The tag set this renderer's dispatch table accepts. Read by the
  # schema↔text drift test (tests/default.nix) to assert every tag in
  # the `statement` union has a renderer entry — otherwise an unrendered
  # tag throws at render time instead of failing eval-time.
  tags = builtins.attrNames taggedRenderers;
}
