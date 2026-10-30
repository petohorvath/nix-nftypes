/*
  Renderer for the `statement` attrTag union (lib/schema/statements.nix).

  Statements appear inside a rule body, separated by `; ` in compact mode
  or newline+indent in pretty mode (the join is done by the rule renderer
  in lib/text/objects.nix).

  Most statements are thin wrappers around expressions; the trickier ones
  are NAT (snat/dnat/redirect/masquerade) with their flag combinations,
  and counter/quota/limit/ct count which accept either a named-object
  reference (a name or a map selecting one) or an inline body.
*/
{
  fail,
  lib,
  context,
  primitives,
  expressions,
  limit,
}:

let
  inherit (context) resetPrec;
  # Verdicts/jump/goto live in expressions.nix (they're valid in both
  # statement and expression position), so statements reuse them.
  inherit (expressions)
    renderExpression
    renderGoto
    renderJump
    renderRightOf
    renderVerdict
    ;
  inherit (lib) optionalString;
  inherit (primitives) safeToken;

  # ---- helpers ---------------------------------------------------------

  renderInnerExpression = ctx: e: renderExpression (resetPrec ctx) e;

  # A named-object reference: a name string, or a `{ map = …; }`
  # expression selecting the name.
  isObjectRef = body: builtins.isString body || (builtins.isAttrs body && body ? map);

  # `<keyword> name "<name>"` or `<keyword> name <key> map { … }`.
  renderObjectRef =
    ctx: keyword: body:
    "${keyword} name "
    + (
      if builtins.isString body then
        primitives.quoteString "${keyword} reference" body
      else
        renderInnerExpression ctx body
    );

  # A listOrSingleton flag value as a list.
  flagList =
    flags:
    if flags == null then
      [ ]
    else if builtins.isList flags then
      flags
    else
      [ flags ];

  # NAT flags as a comma-separated suffix. nft's text has no `netmap` flag:
  # `snat`/`dnat` spell it `prefix to`, so their renderer takes it out
  # first, and any left here is refused.
  renderNatFlags =
    flags:
    let
      items = flagList flags;
    in
    if builtins.elem "netmap" items then
      primitives.refuseNoTextSpelling "nat flags" "nft's text spells the netmap flag only as `snat`/`dnat` `prefix to`, which takes no port and no other flag."
    else
      lib.optionalString (items != [ ]) " ${lib.concatMapStringsSep "," (safeToken "nat flags") items}";

  /*
    A NAT address followed by `:<port>`. nft's lexer would read the port
    into an IPv6 address (`2001:db8::1:80` is one address), so an IPv6
    address, alone or as a range endpoint, goes in brackets. It would read
    `/24:80` as one string, so a space ends a prefix.
  */
  renderNatAddrBeforePort =
    ctx: addr:
    let
      bracketIp6 =
        a:
        if builtins.isString a && lib.hasInfix ":" a then
          "[${renderInnerExpression ctx a}]"
        else
          renderInnerExpression ctx a;
    in
    if builtins.isString addr then
      bracketIp6 addr
    else if builtins.isAttrs addr && addr ? range then
      lib.concatMapStringsSep "-" bracketIp6 addr.range
    else if builtins.isAttrs addr && addr ? prefix then
      "${renderInnerExpression ctx addr} "
    else
      renderInnerExpression ctx addr;

  # Render the `to <addr>[:<port>]` or `to :<port>` clause shared by NAT-
  # family statements. addr can be null (port-only translation).
  renderNatTo =
    ctx: addr: port:
    if addr == null && port == null then
      ""
    else if port == null then
      " to ${renderInnerExpression ctx addr}"
    else
      " to "
      + (if addr == null then "" else renderNatAddrBeforePort ctx addr)
      + ":${renderInnerExpression ctx port}";

  # ---- per-tag renderers ----------------------------------------------

  # match: `<left> <op> <right>`. Only `in` is elided: nft's implicit
  # form is JSON `in` (an any-bit test on a bitmask), so JSON `==` must
  # write its operator to stay an exact match. Every other op emits too.
  # Interface names on the right are quoted (`renderRightOf`).
  renderMatch =
    ctx:
    {
      left,
      op,
      right,
    }:
    let
      lhs = renderInnerExpression ctx left;
      rhs = renderRightOf "match right" left (resetPrec ctx) right;
    in
    if op == "in" then "${lhs} ${rhs}" else "${lhs} ${safeToken "match op" op} ${rhs}";

  # counter: null → bare "counter"; str → named reference;
  # attrset → inline `counter packets P bytes B` (each optional).
  renderCounter =
    ctx: body:
    if body == null then
      "counter"
    else if isObjectRef body then
      renderObjectRef ctx "counter" body
    else
      let
        parts = [
          "counter"
        ]
        ++ lib.optional (
          (body.packets or null) != null
        ) "packets ${safeToken "counter packets" body.packets}"
        ++ lib.optional ((body.bytes or null) != null) "bytes ${safeToken "counter bytes" body.bytes}";
      in
      lib.concatStringsSep " " parts;

  # mangle: `<key> set <value>`. The schema allows any expression for both
  # sides; payload/meta/ct mangling all flow through this shape.
  renderMangle =
    ctx: { key, value }: "${renderInnerExpression ctx key} set ${renderInnerExpression ctx value}";

  # quota: str → named ref;
  # attrset → `quota [over] <val> <unit> [used <u> <unit>]`.
  # `inv = true` flips the implicit "until" to "over". Text needs each
  # unit, and JSON's default to bytes. `val_unit` and `used_unit` render
  # bare into the output, and a Raw attrset can hold any string there, so
  # each flows through `safeToken` to reject parser-meta bytes that would
  # otherwise terminate the statement.
  renderQuota =
    ctx: body:
    if isObjectRef body then
      renderObjectRef ctx "quota" body
    else
      let
        unit = field: value: if value == null then "bytes" else safeToken "quota ${field}" value;
        head = "quota" + optionalString ((body.inv or null) == true) " over";
        valPart = " ${safeToken "quota val" body.val} ${unit "val_unit" (body.val_unit or null)}";
        usedPart =
          if (body.used or null) == null then
            ""
          else
            " used ${safeToken "quota used" body.used} ${unit "used_unit" (body.used_unit or null)}";
      in
      head + valPart + usedPart;

  # A device name, quoted (ADR 0004): bare, `010` loads ifindex 8 and
  # `$lan` takes a host `define`. Any other expression renders as such.
  renderDevice =
    field: ctx: dev:
    if builtins.isString dev then primitives.quoteIfname field dev else renderInnerExpression ctx dev;

  # fwd: `fwd to <dev>` or `fwd <family> to <addr> device <dev>`. JSON
  # takes a next hop only with both a family and an address, and ignores
  # either alone (parser_json.c json_parse_fwd_stmt).
  renderFwd =
    ctx:
    {
      dev,
      family ? null,
      addr ? null,
    }:
    if family == null || addr == null then
      "fwd to ${renderDevice "fwd device" ctx dev}"
    else
      "fwd ${safeToken "fwd family" family} to ${renderInnerExpression ctx addr}"
      + " device ${renderDevice "fwd device" ctx dev}";

  # dup: `dup to <addr> [device <dev>]`.
  renderDup =
    ctx:
    {
      addr,
      dev ? null,
    }:
    "dup to ${renderInnerExpression ctx addr}"
    + optionalString (dev != null) " device ${renderDevice "dup device" ctx dev}";

  /*
    NAT: snat/dnat share the same body. `addr` is omitted for port-only
    translation; `family` precedes `to`; `port` is appended `:port`; flags
    are comma-joined after the address and port. The address type is a
    keyword before `to`, as nft's grammar and evaluation read it:
    - the `netmap` flag is `prefix to`. nft's text sets the flags written
      after it in place of `netmap`, and takes no port, so it goes alone;
    - the `concat` type flag is `<family> addr . port to`;
    - the `prefix` type flag only changes how nft lists the statement, and
      nft derives `interval` from the map in text as in JSON, so neither
      is written.
    Without an address, nft's text takes no family (`snat ip to :80` is a
    syntax error), and nft's JSON parser loads the table's: it ignores the
    family in an inet table, and fails on another one in an ip or ip6
    table. So the family is left out there, and refused where the rule's
    table can't take it.
  */
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
      flagItems = flagList flags;
      hasNetmapFlag = builtins.elem "netmap" flagItems;
      hasConcatTypeFlag = builtins.elem "concat" (flagList type_flags);
      refuse = primitives.refuseNoTextSpelling;
      addressType =
        if hasConcatTypeFlag && hasNetmapFlag then
          refuse "nat flags" "nft's text has no spelling for a netmap concatenation."
        else if hasConcatTypeFlag && family == null then
          refuse "nat type_flags" "nft's text spells the concat type flag only after a family (`snat ip addr . port to`)."
        else if hasConcatTypeFlag && port != null then
          refuse "nat type_flags" "nft's text takes no port after `addr . port to`, and JSON rejects one."
        else if hasConcatTypeFlag then
          " addr . port"
        else if hasNetmapFlag && (port != null || builtins.length flagItems > 1) then
          refuse "nat flags" "nft's text spells the netmap flag `prefix to`, which takes no port and no other flag."
        else if hasNetmapFlag then
          " prefix"
        else
          "";
      tableFamilyOnly = builtins.elem ctx.family [
        "ip"
        "ip6"
      ];
      head =
        if addr != null && family != null then
          "${name} ${safeToken "nat family" family}"
        else if family != null && tableFamilyOnly && family != ctx.family then
          refuse "nat family" "Without an address, nft's text has no family, so it loads the ${ctx.family} table's, while nft's JSON parser fails on the family ${builtins.toJSON family} there."
        else
          name;
    in
    head + addressType + renderNatTo ctx addr port + renderNatFlags (lib.remove "netmap" flagItems);

  # masquerade/redirect — port-only NAT-family statements. Same body shape.
  renderMasquerade =
    name: ctx:
    {
      port ? null,
      flags ? null,
    }:
    name
    + (if port == null then "" else " to :${renderInnerExpression ctx port}")
    + renderNatFlags flags;

  # reject: `reject [with <type> [<expr>]]`. `tcp reset` is the one
  # type of two words.
  renderReject =
    ctx:
    {
      type ? null,
      expr ? null,
    }:
    if type == null && expr == null then
      "reject"
    else
      "reject with ${if type == "tcp reset" then type else safeToken "reject type" type}"
      + optionalString (expr != null) " ${renderInnerExpression ctx expr}";

  # set/map dynamic-update statement:
  # `<op> @<set> { <elem>[ : <data>] [stmt]* }`. The reference is stored
  # with its `@` and printed as is; `namedReference` refuses one without
  # it, or with a byte outside the bare-token grammar (a newline and a
  # trailing command would parse as a fresh nft command at rule scope).
  renderSetStatement =
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
    "${safeToken "set op" op} ${
      primitives.namedReference "reference" "set reference" set
    } { ${renderInnerExpression ctx elem}${stmts} }";

  renderMapStatement =
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
    "${safeToken "map op" op} ${
      primitives.namedReference "reference" "map reference" map
    } { ${renderInnerExpression ctx elem} : ${renderInnerExpression ctx data}${stmts} }";

  # nft's text takes one log flag group per `flags` clause, its tcp flags
  # comma-joined (`flags tcp sequence,options flags skuid`), and ORs the
  # clauses together as JSON ORs its list.
  renderLogFlags =
    flags:
    let
      items = flagList flags;
      tcpFlags = {
        "tcp sequence" = "sequence";
        "tcp options" = "options";
      };
      otherFlags = [
        "ip options"
        "skuid"
        "ether"
        "all"
      ];
      unknown = builtins.filter (flag: !(tcpFlags ? ${flag} || builtins.elem flag otherFlags)) items;
      tcpItems = builtins.filter (flag: tcpFlags ? ${flag}) items;
    in
    if unknown != [ ] then
      primitives.refuseNoTextSpelling "log flags" "${builtins.toJSON (builtins.head unknown)} is no log flag."
    else
      lib.optional (tcpItems != [ ])
        "flags tcp ${lib.concatMapStringsSep "," (flag: tcpFlags.${flag}) tcpItems}"
      ++ map (flag: "flags ${flag}") (builtins.filter (flag: builtins.elem flag otherFlags) items);

  # log: `log [prefix "..."] [group N] [snaplen N] [queue-threshold N]
  # [level L] [flags ...]`.
  renderLog =
    _ctx: body:
    let
      parts = [
        "log"
      ]
      ++ lib.optional (
        (body.prefix or null) != null
      ) "prefix ${primitives.quoteLogPrefix "log prefix" body.prefix}"
      ++ lib.optional ((body.group or null) != null) "group ${safeToken "log group" body.group}"
      ++ lib.optional ((body.snaplen or null) != null) "snaplen ${safeToken "log snaplen" body.snaplen}"
      ++
        lib.optional ((body."queue-threshold" or null) != null)
          "queue-threshold ${safeToken "log queue-threshold" body."queue-threshold"}"
      ++ lib.optional ((body.level or null) != null) "level ${safeToken "log level" body.level}"
      ++ renderLogFlags (body.flags or null);
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
    "meter ${primitives.safeName "identifier" "meter name" name}"
    + optionalString (size != null) " size ${safeToken "meter size" size}"
    + " { ${renderInnerExpression ctx key} ${renderStatement (resetPrec ctx) stmt} }";

  # queue: `queue [flags <f>] num <n>` for a number or range, and
  # `queue [flags <f>] to <expr>` for any other expression (symhash,
  # numgen, a map), which `num` doesn't take. Without a number, flags come
  # bare (`queue bypass`): `queue flags` needs a number.
  renderQueue =
    ctx:
    {
      num ? null,
      flags ? null,
    }:
    let
      flagsText = primitives.flags {
        field = "queue flags";
        sep = ",";
      } flags;
      flagsClause = optionalString (flags != null) " flags ${flagsText}";
      isNumber = builtins.isInt num || builtins.isAttrs num && num ? range;
    in
    if num == null then
      "queue" + optionalString (flags != null) " ${flagsText}"
    else
      "queue" + flagsClause + (if isNumber then " num " else " to ") + renderInnerExpression ctx num;

  # vmap: `<key> vmap <data>` — verdict-map dispatch as a statement.
  renderVmap =
    ctx:
    { key, data }:
    "${renderInnerExpression ctx key} vmap ${renderRightOf "vmap key" key (resetPrec ctx) data}";

  # ct count: a named-object reference, `ct count <val>`, or
  # `ct count over <val>`.
  renderCtCount =
    ctx: body:
    if isObjectRef body then
      renderObjectRef ctx "ct count" body
    else
      "ct count"
      + optionalString ((body.inv or null) == true) " over"
      + " ${safeToken "ct count val" body.val}";

  # xt: deprecated escape hatch. Render as `xt <type> "<name>"`.
  renderXt =
    _ctx:
    { type, name }:
    "xt ${safeToken "xt type" type} ${primitives.quoteString "xt name" name}";

  # last: `last`, `last used never` (JSON -1), or `last used <ms>ms`.
  renderLast =
    _ctx: body:
    if body == null then
      "last"
    else if body.used == -1 then
      "last used never"
    else if builtins.isInt body.used && body.used < -1 then
      primitives.refuseNoTextSpelling "last used" "JSON loads a negative time other than -1 (never) as a huge one."
    else
      "last used ${safeToken "last used" body.used}ms";

  # flow <op> @<flowtable>, the reference printed as stored.
  renderFlow =
    _ctx:
    { op, flowtable }:
    "flow ${safeToken "flow op" op} ${
      primitives.namedReference "flowtableReference" "flowtable reference" flowtable
    }";

  # tproxy: like dnat, but `to` syntax.
  renderTproxy =
    ctx:
    {
      family ? null,
      addr ? null,
      port ? null,
    }:
    "tproxy"
    + optionalString (family != null) " ${safeToken "tproxy family" family}"
    + renderNatTo ctx addr port;

  # synproxy: bare / inline / named-reference (expr).
  renderSynproxy =
    ctx: body:
    if body == null then
      "synproxy"
    else if builtins.isAttrs body && body ? mss && body ? wscale then
      let
        head = "synproxy mss ${safeToken "synproxy mss" body.mss} wscale ${safeToken "synproxy wscale" body.wscale}";
        flagsClause =
          if (body.flags or null) == null then
            ""
          else
            " "
            + primitives.flags {
              field = "synproxy flags";
              sep = " ";
            } body.flags;
      in
      head + flagsClause
    else
      # Named-reference expression. nft accepts either a bare name or a
      # quoted string.
      "synproxy name ${renderInnerExpression ctx body}";

  # reset: `reset <expr>` — typically `reset tcp option <name>`.
  renderReset = ctx: body: "reset ${renderInnerExpression ctx body}";

  /*
    secmark / tunnel / ct helper / ct timeout / ct expectation: assign a
    named object, `<keyword> <object>`, such as `ct helper set "ftp"` or
    `tunnel name "vxlan0"`. The body is an expression that is, in
    practice, a string naming the object, which nft's text needs quoted.
  */
  renderAssign =
    { field, keyword }:
    ctx: body:
    let
      rendered =
        if builtins.isString body then
          primitives.quoteString "${field} reference" body
        else
          renderInnerExpression ctx body;
    in
    "${keyword} ${rendered}";

  # ---- dispatch table -------------------------------------------------

  # Renders a null body, which nft lists for a statement with no options,
  # as the empty body.
  nullAsEmpty =
    render: ctx: body:
    render ctx (if body == null then { } else body);

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
    limit =
      ctx: body:
      if isObjectRef body then renderObjectRef ctx "limit" body else limit.renderStatement body;
    fwd = renderFwd;
    dup = renderDup;
    snat = renderNat "snat";
    dnat = renderNat "dnat";
    masquerade = nullAsEmpty (renderMasquerade "masquerade");
    redirect = nullAsEmpty (renderMasquerade "redirect");
    reject = nullAsEmpty renderReject;
    set = renderSetStatement;
    map = renderMapStatement;
    log = nullAsEmpty renderLog;
    meter = renderMeter;
    queue = nullAsEmpty renderQueue;
    vmap = renderVmap;
    "ct count" = renderCtCount;
    xt = renderXt;
    last = renderLast;
    flow = renderFlow;
    tproxy = renderTproxy;
    synproxy = renderSynproxy;
    reset = renderReset;
    secmark = renderAssign {
      field = "meta secmark";
      keyword = "meta secmark set";
    };
    tunnel = renderAssign {
      field = "tunnel";
      keyword = "tunnel name";
    };
    "ct helper" = renderAssign {
      field = "ct helper";
      keyword = "ct helper set";
    };
    "ct timeout" = renderAssign {
      field = "ct timeout";
      keyword = "ct timeout set";
    };
    "ct expectation" = renderAssign {
      field = "ct expectation";
      keyword = "ct expectation set";
    };
  };

  renderStatement =
    ctx: v:
    if !(builtins.isAttrs v) then
      fail "statement must be an attrset, got ${builtins.typeOf v}"
    else
      let
        names = builtins.attrNames v;
      in
      if builtins.length names != 1 then
        fail "statement must have exactly one tag, got [${lib.concatStringsSep ", " names}]"
      else
        let
          tag = builtins.head names;
        in
        if !(taggedRenderers ? ${tag}) then
          fail "no renderer for tag '${tag}'"
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
    renderRuleExpr
    renderStatement
    ;
  # The tag set this renderer's dispatch table accepts. Read by the
  # schema↔text drift test (tests/unit/schema.nix) to assert every tag in
  # the `statement` union has a renderer entry — otherwise an unrendered
  # tag throws at render time instead of failing eval-time.
  tags = builtins.attrNames taggedRenderers;
}
