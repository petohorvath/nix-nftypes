{
  lib,
  context,
  primitives,
  expressions,
  statements,
}:

# Renderer for the object kinds in lib/schema/objects.nix.
#
# Each object kind renders as the body of an `add <kind>` command (or
# `flush <kind>`, `delete <kind>`, etc — the command renderer in
# lib/text/commands.nix prepends the verb).
#
# Bodies generally take the form:
#
#   <family> <table> [<chain>|<set>|<...>] <name> [{ <opt>; <opt>; ... }]
#
# Required header (family/table/chain/name) goes on the same line as the
# verb; optional clauses go inside braces. For pretty mode, opts inside
# braces are one-per-line indented; for compact mode, separated by `; `.

let
  inherit (context)
    withDepth
    indent
    resetPrec
    ;
  inherit (expressions) renderExpression renderSetElement;
  inherit (statements) renderRuleExpr;

  rExpr = ctx: e: renderExpression (resetPrec ctx) e;
  rIdent = primitives.identQuote;

  # Wrap a list of body lines in `{ ... }`. The text grammar requires `;`
  # after every statement inside braces in both compact and pretty modes,
  # including the one immediately before `}` — newlines alone don't
  # separate them, and a missing trailing `;` makes the parser report
  # `unexpected '}'`.
  #
  # Compact: `{ a; b; c; }`.
  # Pretty:  one statement per line, indented, each terminated with `;`.
  #
  # Empty body: imperative form omits braces entirely (the `add <kind>`
  # verb provides enough context — `add counter inet fw hits` parses
  # fine), but block form must still emit `{ }` because a bare
  # `counter hits` inside a `table { ... }` block is ambiguous to the
  # parser.
  block =
    ctx: lines:
    if lines == [ ] && !(ctx.block or false) then
      ""
    else if lines == [ ] then
      " { }"
    else
      let
        inner = withDepth ctx;
        joined =
          if ctx.pretty then
            lib.concatMapStringsSep "" (l: "\n${indent inner}${l};") lines
          else
            lib.concatMapStrings (l: "${l}; ") lines;
        close = if ctx.pretty then "\n${indent ctx}}" else "}";
        open = if ctx.pretty then " {" else " { ";
      in
      "${open}${joined}${close}";

  # Render the family + scoping prefix shared by most objects:
  # "<family> <table>" or "<family> <table> <chain/set>".
  #
  # Names are emitted bare; the text parser expects an identifier (not a
  # quoted string) in the table/chain/set position after `add <kind>`.
  # If a name happens to collide with an nftables keyword (e.g. a
  # flowtable named "offload"), the user has to rename — there's no
  # quoting form that works in this position.
  #
  # In block-form rendering (`ctx.block`), the enclosing `table { ... }`
  # implies family/table, so `scope2` collapses to just the object's
  # name. `scope1` is unaffected — the only caller (the table header
  # itself) is never rendered in block form.
  scope1 = body: "${body.family} ${rIdent body.table}";
  scope2 = ctx: body: if ctx.block then rIdent body.name else "${scope1 body} ${rIdent body.name}";

  # Render a setDatatype: string → "ipv4_addr"; list → "ipv4_addr . port";
  # { typeof = expr } → "typeof <expr>".
  renderDatatype =
    ctx: dt:
    if builtins.isString dt then
      dt
    else if builtins.isList dt then
      lib.concatStringsSep " . " dt
    else if builtins.isAttrs dt && dt ? typeof then
      "typeof ${rExpr ctx dt.typeof}"
    else
      throw "text.objects: unrecognized datatype shape";

  # Render the elements clause shared by set/map/element. Empty list →
  # empty (caller skips the clause).
  renderElements =
    ctx: elems:
    let
      inner = lib.concatMapStringsSep ", " (renderSetElement (resetPrec ctx)) elems;
    in
    "elements = { ${inner} }";

  # Render a chain `dev` field — either a bare string ("eth0") or a list.
  # Single device: `device "eth0"`; multiple: `devices = { eth0, eth1 }`.
  renderChainDev =
    dev:
    if builtins.isString dev then
      "device ${primitives.string dev}"
    else
      "devices = { ${lib.concatStringsSep ", " dev} }";

  # ---- per-kind body renderers ---------------------------------------

  renderTableHeader =
    _ctx: body:
    scope1 {
      family = body.family;
      table = body.name;
    };

  renderTableBody =
    _ctx: body:
    lib.optionals ((body.flags or null) != null) [
      "flags ${primitives.flags { sep = ", "; } body.flags}"
    ]
    ++ lib.optionals ((body.comment or null) != null) [
      "comment ${primitives.string body.comment}"
    ];

  renderChainHeader = ctx: body: scope2 ctx body;

  # Shared between renderRuleHeader (imperative `add rule …`) and the
  # block-form rule lines folded into a chain's brace block: the
  # statements + optional `comment "…"` clause that make up everything
  # after the rule's family/table/chain prefix.
  renderRuleStmtsAndComment =
    ctx: body:
    let
      stmts = renderRuleExpr ctx body.expr;
      commentClause =
        if (body.comment or null) == null then "" else " comment ${primitives.string body.comment}";
    in
    "${stmts}${commentClause}";

  renderChainBody =
    ctx: body:
    let
      isBase = (body.type or null) != null && (body.hook or null) != null && (body.prio or null) != null;
      baseLine =
        if isBase then
          let
            devClause = if (body.dev or null) == null then "" else " ${renderChainDev body.dev}";
          in
          [ "type ${body.type} hook ${body.hook}${devClause} priority ${primitives.priority body.prio}" ]
        else
          [ ];
      policyLine = lib.optional ((body.policy or null) != null) "policy ${body.policy}";
      commentLine = lib.optional (
        (body.comment or null) != null
      ) "comment ${primitives.string body.comment}";
      # In block form, rules render inline inside the chain block; the
      # toTextBlock walker passes them via `ctx.rulesByChain.<name>`.
      # Imperative renderers leave the field unset and the list collapses.
      blockRuleLines = map (renderRuleStmtsAndComment ctx) (ctx.rulesByChain.${body.name} or [ ]);
    in
    baseLine ++ policyLine ++ commentLine ++ blockRuleLines;

  # rule: `<family> <table> <chain> <statements> [handle/index] [comment]`.
  # Rules do not use a brace block; statements are inline.
  renderRuleHeader =
    ctx: body:
    let
      pos =
        if (body.handle or null) != null then
          " handle ${toString body.handle}"
        else if (body.index or null) != null then
          " index ${toString body.index}"
        else
          "";
    in
    "${body.family} ${rIdent body.table} ${rIdent body.chain}${pos} ${renderRuleStmtsAndComment ctx body}";

  # Shared body renderer for set and map objects. They differ only in the
  # type clause: sets emit `type <K>`; maps emit `type <K> : <V>`. Every
  # other clause (flags/policy/size/timeout/gc-interval/auto-merge/stmt/
  # elements/comment) is identical.
  renderSetOrMapBody =
    typeLineFor: ctx: body:
    let
      elemList =
        if (body.elem or null) == null then
          [ ]
        else if builtins.isList body.elem then
          body.elem
        else
          [ body.elem ];
      # Stateful statements attached to elements are rendered as
      # `counter; quota` etc. inside the body.
      stmtLines =
        if (body.stmt or null) == null then
          [ ]
        else
          map (s: statements.renderStatement (resetPrec ctx) s) body.stmt;
    in
    [ (typeLineFor ctx body) ]
    ++
      lib.optional ((body.flags or null) != null)
        "flags ${primitives.flags { sep = ", "; } body.flags}"
    ++ lib.optional ((body.policy or null) != null) "policy ${body.policy}"
    ++ lib.optional ((body.size or null) != null) "size ${toString body.size}"
    ++ lib.optional ((body.timeout or null) != null) "timeout ${toString body.timeout}s"
    ++ lib.optional ((body."gc-interval" or null) != null) "gc-interval ${toString body."gc-interval"}s"
    ++ lib.optional ((body."auto-merge" or null) == true) "auto-merge"
    ++ stmtLines
    ++ lib.optional (elemList != [ ]) (renderElements ctx elemList)
    ++ lib.optional ((body.comment or null) != null) "comment ${primitives.string body.comment}";

  # set: header `<family> <table> <name>`; body covers type/flags/policy/
  # size/timeout/gc-interval/auto-merge/elements/comment/stmt.
  renderSetHeader = ctx: body: scope2 ctx body;
  renderSetBody = renderSetOrMapBody (ctx: body: "type ${renderDatatype ctx body.type}");

  # map: same as set but the type clause is `type K : V` and elements are
  # `k : v` pairs (handled by renderSetElement).
  renderMapHeader = ctx: body: scope2 ctx body;
  renderMapBody = renderSetOrMapBody (
    ctx: body: "type ${renderDatatype ctx body.type} : ${renderDatatype ctx body.map}"
  );

  # element: `<family> <table> <set-name> { <elem>, <elem>, ... }`. The
  # body is a bare comma-separated element list inside braces (no
  # `elements = ` prefix — that form is for set/map definitions).
  renderElement =
    ctx: body:
    let
      elemList = if builtins.isList body.elem then body.elem else [ body.elem ];
      inner = lib.concatMapStringsSep ", " (renderSetElement (resetPrec ctx)) elemList;
    in
    "element ${scope2 ctx body} { ${inner} }";

  # flowtable: `hook <hook> priority <prio>; devices = { ... };`.
  renderFlowtableHeader = ctx: body: scope2 ctx body;

  renderFlowtableBody =
    _ctx: body:
    let
      hookLine =
        if (body.hook or null) != null && (body.prio or null) != null then
          [ "hook ${body.hook} priority ${primitives.priority body.prio}" ]
        else
          [ ];
      devLine =
        if (body.dev or null) == null then
          [ ]
        else
          let
            devs = if builtins.isList body.dev then body.dev else [ body.dev ];
          in
          [ "devices = { ${lib.concatStringsSep ", " devs} }" ];
    in
    hookLine ++ devLine;

  # counter: bare body (`add counter ...`) or with packets/bytes/comment.
  renderCounterHeader = ctx: body: scope2 ctx body;

  renderCounterBody =
    _ctx: body:
    lib.optionals ((body.packets or null) != null || (body.bytes or null) != null) [
      (
        (lib.optionalString ((body.packets or null) != null) "packets ${toString body.packets}")
        + (lib.optionalString ((body.packets or null) != null && (body.bytes or null) != null) " ")
        + (lib.optionalString ((body.bytes or null) != null) "bytes ${toString body.bytes}")
      )
    ]
    ++ lib.optional ((body.comment or null) != null) "comment ${primitives.string body.comment}";

  # quota object: `[over] <bytes> bytes [used N bytes]`.
  renderQuotaHeader = ctx: body: scope2 ctx body;

  renderQuotaBody =
    _ctx: body:
    let
      headParts =
        lib.optional ((body.inv or null) == true) "over"
        ++ lib.optional ((body.bytes or null) != null) "${toString body.bytes} bytes"
        ++ lib.optional ((body.used or null) != null) "used ${toString body.used} bytes";
      head = if headParts == [ ] then [ ] else [ (lib.concatStringsSep " " headParts) ];
    in
    head ++ lib.optional ((body.comment or null) != null) "comment ${primitives.string body.comment}";

  # limit object: `rate [over] <r> [<unit>]/<per> [burst N <unit>]`.
  renderLimitHeader = ctx: body: scope2 ctx body;

  renderLimitBody =
    _ctx: body:
    let
      head =
        "rate"
        + lib.optionalString ((body.inv or null) == true) " over"
        + " ${toString body.rate}"
        + lib.optionalString ((body.rate_unit or null) != null) " ${body.rate_unit}"
        + "/${body.per}"
        + (
          if (body.burst or null) == null then
            ""
          else
            # nft -f requires an explicit unit after `burst <N>`. Default
            # to "packets" when none is set (same as the limit statement
            # renderer in lib/text/statements.nix).
            let
              burstUnit = if (body.burst_unit or null) != null then body.burst_unit else "packets";
            in
            " burst ${toString body.burst} ${burstUnit}"
        );
    in
    [ head ]
    ++ lib.optional ((body.comment or null) != null) "comment ${primitives.string body.comment}";

  # ct helper object. nft text wants `type "T" protocol P` joined as a
  # single statement (the parser only accepts a `type` clause when
  # `protocol` follows it inline, no separator). `l3proto` and `comment`
  # are then separate statements with their own `;`.
  renderCtHelperHeader = ctx: body: scope2 ctx body;

  renderCtHelperBody =
    _ctx: body:
    let
      hasType = (body.type or null) != null;
      hasProto = (body.protocol or null) != null;
      typeProtoLine =
        if hasType && hasProto then
          [ "type ${primitives.string body.type} protocol ${body.protocol}" ]
        else if hasType then
          [ "type ${primitives.string body.type}" ]
        else if hasProto then
          [ "protocol ${body.protocol}" ]
        else
          [ ];
    in
    typeProtoLine
    ++ lib.optional ((body.l3proto or null) != null) "l3proto ${body.l3proto}"
    ++ lib.optional ((body.comment or null) != null) "comment ${primitives.string body.comment}";

  # ct timeout object: `protocol tcp; l3proto ip; policy = { established: 300, ... };`.
  renderCtTimeoutHeader = ctx: body: scope2 ctx body;

  renderCtTimeoutBody =
    _ctx: body:
    let
      policyLine =
        if (body.policy or null) == null then
          [ ]
        else
          let
            entries = lib.mapAttrsToList (k: v: "${k}: ${toString v}") body.policy;
          in
          [ "policy = { ${lib.concatStringsSep ", " entries} }" ];
    in
    lib.optional ((body.protocol or null) != null) "protocol ${body.protocol}"
    ++ lib.optional ((body.l3proto or null) != null) "l3proto ${body.l3proto}"
    ++ policyLine
    ++ lib.optional ((body.comment or null) != null) "comment ${primitives.string body.comment}";

  # ct expectation object.
  renderCtExpectationHeader = ctx: body: scope2 ctx body;

  renderCtExpectationBody =
    _ctx: body:
    lib.optional ((body.protocol or null) != null) "protocol ${body.protocol}"
    ++ lib.optional ((body.dport or null) != null) "dport ${toString body.dport}"
    ++ lib.optional ((body.timeout or null) != null) "timeout ${toString body.timeout}s"
    ++ lib.optional ((body.size or null) != null) "size ${toString body.size}"
    ++ lib.optional ((body.l3proto or null) != null) "l3proto ${body.l3proto}"
    ++ lib.optional ((body.comment or null) != null) "comment ${primitives.string body.comment}";

  # secmark object.
  renderSecmarkHeader = ctx: body: scope2 ctx body;

  renderSecmarkBody =
    _ctx: body:
    lib.optional ((body.context or null) != null) (primitives.string body.context)
    ++ lib.optional ((body.comment or null) != null) "comment ${primitives.string body.comment}";

  # synproxy object.
  renderSynproxyHeader = ctx: body: scope2 ctx body;

  renderSynproxyBody =
    _ctx: body:
    let
      head = "mss ${toString body.mss} wscale ${toString body.wscale}";
      flagsLine = lib.optional ((body.flags or null) != null) (
        primitives.flags { sep = " "; } body.flags
      );
    in
    [ head ]
    ++ flagsLine
    ++ lib.optional ((body.comment or null) != null) "comment ${primitives.string body.comment}";

  # tunnel object: id/src-ipv4/dst-ipv4/sport/dport/ttl/tos/type and the
  # nested encapsulation-specific block.
  renderTunnelHeader = ctx: body: scope2 ctx body;

  renderTunnelBody =
    ctx: body:
    let
      mkAddr = key: lib.optional ((body.${key} or null) != null) "${key} ${rExpr ctx body.${key}}";
      mkInt = key: lib.optional ((body.${key} or null) != null) "${key} ${toString body.${key}}";
      typeLine = lib.optional ((body.type or null) != null) "type ${body.type}";
      nestedLine =
        if (body.tunnel or null) == null then
          [ ]
        else if builtins.isList body.tunnel then
          # GENEVE: list of { class, opt-type, data }.
          let
            entries = lib.concatMapStringsSep ", " (
              opt:
              "{ class ${toString opt.class}, opt-type ${toString opt."opt-type"}, data ${primitives.string opt.data} }"
            ) body.tunnel;
          in
          [ "geneve = { ${entries} }" ]
        else if body.tunnel ? gbp then
          [ "vxlan { gbp ${toString body.tunnel.gbp} }" ]
        else if (body.tunnel.version or null) == 1 then
          [ "erspan { version 1; index ${toString body.tunnel.index} }" ]
        else if (body.tunnel.version or null) == 2 then
          [
            "erspan { version 2; dir ${body.tunnel.dir}; hwid ${toString body.tunnel.hwid} }"
          ]
        else
          throw "text.objects: unrecognized tunnel encapsulation";
    in
    mkInt "id"
    ++ mkAddr "src-ipv4"
    ++ mkAddr "src-ipv6"
    ++ mkAddr "dst-ipv4"
    ++ mkAddr "dst-ipv6"
    ++ mkInt "sport"
    ++ mkInt "dport"
    ++ mkInt "ttl"
    ++ mkInt "tos"
    ++ typeLine
    ++ nestedLine
    ++ lib.optional ((body.comment or null) != null) "comment ${primitives.string body.comment}";

  # metainfo (for list output): version/release_name/json_schema_version.
  # Only meaningful in `nft -j list` output; the `list metainfo` verb
  # doesn't exist in text syntax and the only verb accepting metainfo
  # (`list`) is bodyless, so no body is emitted.
  renderMetainfoHeader = _ctx: _body: "";

  # meter (for list/flush output): family/table/name only. There's no
  # `add meter` — meters are anonymous, created via the `meter`
  # statement — so the header-only form is the entire surface.
  renderMeterHeader = ctx: body: scope2 ctx body;

  # ruleset envelope: null → bare; { family } → `<verb> ruleset <family>`.
  renderRulesetHeader =
    _ctx: body: if body == null then "" else (if body ? family then body.family else "");

  # ---- dispatch: kind → { header, body } -----------------------------
  #
  # Every kind provides either `render ctx body` (a full-string override,
  # used by `element` whose body is a comma-separated value list) or the
  # standard `header ctx body` + `body ctx body` pair. Both are `ctx:
  # body:` functions; headers that don't need ctx accept `_ctx:`.
  # Kinds with `noBraces = true` suppress the block wrapper entirely.
  emptyBody = _ctx: _body: [ ];

  kinds = {
    table = {
      header = renderTableHeader;
      body = renderTableBody;
    };
    chain = {
      header = renderChainHeader;
      body = renderChainBody;
    };
    rule = {
      header = renderRuleHeader;
      body = emptyBody;
      noBraces = true;
    };
    set = {
      header = renderSetHeader;
      body = renderSetBody;
    };
    map = {
      header = renderMapHeader;
      body = renderMapBody;
    };
    element = {
      render = renderElement;
    };
    flowtable = {
      header = renderFlowtableHeader;
      body = renderFlowtableBody;
    };
    counter = {
      header = renderCounterHeader;
      body = renderCounterBody;
    };
    quota = {
      header = renderQuotaHeader;
      body = renderQuotaBody;
    };
    limit = {
      header = renderLimitHeader;
      body = renderLimitBody;
    };
    "ct helper" = {
      header = renderCtHelperHeader;
      body = renderCtHelperBody;
    };
    "ct timeout" = {
      header = renderCtTimeoutHeader;
      body = renderCtTimeoutBody;
    };
    "ct expectation" = {
      header = renderCtExpectationHeader;
      body = renderCtExpectationBody;
    };
    secmark = {
      header = renderSecmarkHeader;
      body = renderSecmarkBody;
    };
    synproxy = {
      header = renderSynproxyHeader;
      body = renderSynproxyBody;
    };
    tunnel = {
      header = renderTunnelHeader;
      body = renderTunnelBody;
    };
    metainfo = {
      header = renderMetainfoHeader;
      body = emptyBody;
    };
    meter = {
      header = renderMeterHeader;
      body = emptyBody;
    };
    ruleset = {
      header = renderRulesetHeader;
      body = emptyBody;
      noBraces = true;
    };
  };

  # Internal worker shared by renderObject and renderObjectHeader. The
  # `withBody` flag selects whether the brace block is emitted. Trailing
  # whitespace is stripped so kinds with empty headers (`ruleset` with no
  # family filter) don't leave a dangling space.
  renderObjectGeneric =
    withBody: ctx: kind: body:
    if !(kinds ? ${kind}) then
      throw "text.objects: no renderer for kind '${kind}'"
    else
      let
        cfg = kinds.${kind};
        rendered =
          if cfg ? render then
            cfg.render ctx body
          else
            let
              header = cfg.header ctx body;
              bodyLines = if withBody then cfg.body ctx body else [ ];
              noBraces = cfg.noBraces or false;
              blockStr = if noBraces then "" else block ctx bodyLines;
              headerSep = lib.optionalString (header != "") " ";
            in
            "${kind}${headerSep}${header}${blockStr}";
      in
      lib.removeSuffix " " rendered;

  # Render an object for an `add`/`replace`/`insert` command — emits both
  # header and body (brace block if applicable). The `element` kind uses
  # its own `render` because its body is a bare comma-separated value
  # list rather than the `;`-separated statement body the block helper
  # produces.
  renderObject = renderObjectGeneric true;

  # Render only the header — used for `delete`/`destroy`/`flush`/`reset`/
  # `list`/`create` verbs, which the text grammar does not accept with a
  # brace body. Callers that need `create`'s positional value form append
  # it themselves (see lib/text/commands.nix).
  renderObjectHeader = renderObjectGeneric false;
in
{
  inherit
    renderObject
    renderObjectHeader
    ;
}
