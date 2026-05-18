{
  lib,
  context,
  primitives,
  # Lazy reference to the sibling `statements` renderer. Only `.renderStatement`
  # is consumed (by `renderElem` for element-attached `stmt` lists). Statements
  # already depend on expressions, so the back-reference is wired through
  # mutually-recursive `let` bindings in lib/text/default.nix and forced only
  # at render time.
  statements,
}:

# Renderer for the recursive `expression` type. Mirrors the schema layout
# in lib/schema/expressions.nix:
#   - scalar fallbacks: string, int, bool;
#   - bare list (used inside set/concat/range bodies);
#   - tagged union (taggedExpression) dispatched by single key.
#
# Two contexts in which expressions appear:
#   - default — top-level, statement RHS, etc.
#   - inside another binop — caller sets ctx.parentPrec; this renderer
#     wraps the result in parens iff our precedence is lower than parent.
#
# `set` / `map` / `elem` carry context-sensitive surface forms; the cases
# here cover the in-expression form (anonymous set literal, map lookup,
# element-with-options). The object renderer in lib/text/objects.nix calls
# its own variants for the named-object forms.

let
  inherit (context)
    withPrec
    resetPrec
    ;

  # C-style precedence of the binary operators. Higher = tighter binding.
  # `nft -f` accepts redundant parens, so adding more is always safe; we
  # only add them where required (child prec < parent prec).
  binopPrec = {
    "|" = 1;
    "^" = 2;
    "&" = 3;
    "<<" = 4;
    ">>" = 4;
  };

  # Render a numeric/string/bool atom.
  renderScalar =
    v:
    if builtins.isInt v then
      toString v
    else if builtins.isBool v then
      (if v then "1" else "0")
    else if builtins.isString v then
      # Strings in expression position are atoms: ip addresses, identifiers,
      # set references like "@trusted_v4". They render bare; the schema has
      # already validated them.
      v
    else
      throw "text.expressions: cannot render scalar of unknown type";

  # ---- per-tag renderers ------------------------------------------------

  # Anonymous set literal: { a, b, c }. Delegates element rendering to
  # renderSetElement so map 2-tuples and elem-wrappers are handled.
  # An empty list renders as `{ }`; the JSON parser accepts
  # `{ set = []; }`, and whether the result is valid in context is the
  # text parser's call, not the renderer's.
  #
  # An `@`-prefixed string body is the canonical named-set-reference form
  # (`{"set":"@name"}` in libnftables-JSON); render it as the bare reference
  # since text grammar wants `@name`, not `{ @name }`. A non-`@` string body
  # is the footgun — `{"set":"name"}` reads as a 1-element anonymous set
  # whose sole element is the literal string `name`, never the caller's
  # intent. The DSL's `expr.set` already throws on that shape, but raw
  # attrsets bypassing the DSL still reach this renderer.
  renderSet =
    ctx: body:
    if builtins.isString body && lib.hasPrefix "@" body then
      body
    else if !(builtins.isList body) then
      throw ''
        text: { set = …; } body must be a list (anonymous set) or an
        `@`-prefixed string (named-set reference). Got: ${builtins.toJSON body}.
        For a named-set reference, use `expr.setRef "<name>"` or pass
        `"@<name>"` directly as the right operand.
      ''
    else if body == [ ] then
      "{ }"
    else
      "{ " + lib.concatMapStringsSep ", " (renderSetElement (resetPrec ctx)) body + " }";

  # In-expression map lookup: <key> map <data>. Used as an RHS expression
  # like `tcp dport map @port_forward`. The named-map definition lives in
  # objects.nix; this is the lookup form.
  renderMapLookup =
    ctx:
    { key, data }:
    "${renderExpression (resetPrec ctx) key} map ${renderExpression (resetPrec ctx) data}";

  # CIDR prefix: <addr>/<len>.
  renderPrefix = ctx: { addr, len }: "${renderExpression (resetPrec ctx) addr}/${toString len}";

  # Range: <lo>-<hi>. Schema enforces exactly two elements.
  renderRange =
    ctx: xs:
    let
      lo = builtins.elemAt xs 0;
      hi = builtins.elemAt xs 1;
    in
    "${renderExpression (resetPrec ctx) lo}-${renderExpression (resetPrec ctx) hi}";

  # Concat: <a> . <b> . <c> — used to compose multi-key set/map expressions.
  renderConcat = ctx: xs: lib.concatMapStringsSep " . " (renderExpression (resetPrec ctx)) xs;

  # Payload — three disjoint shapes (parser_json.c:660-733). Discriminate by
  # key presence, mirroring the schema's addCheck predicates.
  renderPayload =
    _ctx: body:
    if body ? base && body ? offset && body ? len then
      "@${body.base},${toString body.offset},${toString body.len}"
    else if body ? tunnel then
      "${body.tunnel} ${body.protocol} ${body.field}"
    else
      "${body.protocol} ${body.field}";

  # Extension header (IPv6): <name> <field> for field access; bare <name>
  # for existence checks. The text grammar accepts both.
  renderExthdr =
    _ctx: body: if (body.field or null) == null then body.name else "${body.name} ${body.field}";

  renderTcpOption =
    _ctx: body:
    if body ? base then
      "tcp option @${toString body.base},${toString body.offset},${toString body.len}"
    else if (body.field or null) == null then
      "tcp option ${body.name}"
    else
      "tcp option ${body.name} ${body.field}";

  renderIpOption =
    _ctx: body:
    if (body.field or null) == null then
      "ip option ${body.name}"
    else
      "ip option ${body.name} ${body.field}";

  renderSctpChunk =
    _ctx: body:
    if (body.field or null) == null then
      "sctp chunk ${body.name}"
    else
      "sctp chunk ${body.name} ${body.field}";

  renderDccpOption = _ctx: body: "dccp option ${toString body.type}";

  renderMeta = _ctx: body: "meta ${body.key}";

  # Routing data: `rt <key>` or `rt <family> <key>` (for nexthop-style keys).
  renderRt =
    _ctx: body:
    if (body.family or null) == null then "rt ${body.key}" else "rt ${body.family} ${body.key}";

  # Conntrack: `ct [<dir>] [<family>] <key>`. The dir/family clauses are
  # optional and non-exclusive.
  renderCt =
    _ctx: body:
    let
      parts = [
        "ct"
      ]
      ++ lib.optional ((body.dir or null) != null) body.dir
      ++ lib.optional ((body.family or null) != null) body.family
      ++ [ body.key ];
    in
    lib.concatStringsSep " " parts;

  renderNumgen =
    _ctx: body:
    let
      base = "numgen ${body.mode} mod ${toString body.mod}";
    in
    base + lib.optionalString ((body.offset or null) != null) " offset ${toString body.offset}";

  renderJhash =
    ctx: body:
    let
      base = "jhash ${renderExpression (resetPrec ctx) body.expr} mod ${toString body.mod}";
    in
    base
    + lib.optionalString ((body.seed or null) != null) " seed ${toString body.seed}"
    + lib.optionalString ((body.offset or null) != null) " offset ${toString body.offset}";

  renderSymhash =
    _ctx: body:
    "symhash mod ${toString body.mod}"
    + lib.optionalString ((body.offset or null) != null) " offset ${toString body.offset}";

  # FIB: `fib <flags> <result>`, where flags is dot-separated when multiple.
  renderFib =
    _ctx: body:
    let
      flagsStr =
        if (body.flags or null) == null then
          ""
        else if builtins.isList body.flags then
          lib.concatStringsSep " . " body.flags + " "
        else
          body.flags + " ";
    in
    "fib ${flagsStr}${body.result}";

  renderSocket = _ctx: body: "socket ${body.key}";

  renderOsf =
    _ctx: body:
    if (body.ttl or null) == null then "osf ${body.key}" else "osf ttl ${body.ttl} ${body.key}";

  # ipsec: `ipsec <dir> [spnum N] <family> <key>`. The dir is required for
  # the text form; if absent we leave it off and rely on the parser to
  # accept the bare form (rare).
  renderIpsec =
    _ctx: body:
    let
      parts = [
        "ipsec"
      ]
      ++ lib.optional ((body.dir or null) != null) body.dir
      ++ lib.optional ((body.spnum or null) != null) "spnum ${toString body.spnum}"
      ++ lib.optional ((body.family or null) != null) body.family
      ++ [ body.key ];
    in
    lib.concatStringsSep " " parts;

  renderTunnelExpr = _ctx: body: "tunnel ${body.key}";

  # Element with options (used inside set element lists). The renderer for
  # bare elements is renderSetElement, which dispatches to this when the
  # value is `{ elem = { ... } }`.
  renderElem =
    ctx:
    {
      val,
      timeout ? null,
      expires ? null,
      comment ? null,
      stmt ? null,
    }:
    renderExpression (resetPrec ctx) val
    + lib.optionalString (timeout != null) " timeout ${toString timeout}s"
    + lib.optionalString (expires != null) " expires ${toString expires}s"
    + lib.optionalString (comment != null) " comment ${primitives.string comment}"
    + lib.optionalString (stmt != null) (
      " " + lib.concatMapStringsSep " " (statements.renderStatement (resetPrec ctx)) stmt
    );

  renderJump = _ctx: { target }: "jump ${target}";
  renderGoto = _ctx: { target }: "goto ${target}";

  # Bare verdicts as expressions (vmap data position).
  renderVerdict =
    name: _ctx: _body:
    name;

  renderBinop =
    op: ctx: xs:
    let
      myPrec = binopPrec.${op};
      childCtx = withPrec myPrec ctx;
      rendered = lib.concatMapStringsSep " ${op} " (renderExpression childCtx) xs;
    in
    if myPrec < ctx.parentPrec then "(${rendered})" else rendered;

  # ---- dispatch table --------------------------------------------------

  taggedRenderers = {
    concat = renderConcat;
    set = renderSet;
    map = renderMapLookup;
    prefix = renderPrefix;
    range = renderRange;
    payload = renderPayload;
    exthdr = renderExthdr;
    "tcp option" = renderTcpOption;
    "ip option" = renderIpOption;
    "sctp chunk" = renderSctpChunk;
    "dccp option" = renderDccpOption;
    meta = renderMeta;
    rt = renderRt;
    ct = renderCt;
    numgen = renderNumgen;
    jhash = renderJhash;
    symhash = renderSymhash;
    fib = renderFib;
    socket = renderSocket;
    osf = renderOsf;
    ipsec = renderIpsec;
    tunnel = renderTunnelExpr;
    elem = renderElem;
    accept = renderVerdict "accept";
    drop = renderVerdict "drop";
    continue = renderVerdict "continue";
    return = renderVerdict "return";
    jump = renderJump;
    goto = renderGoto;
    "|" = renderBinop "|";
    "^" = renderBinop "^";
    "&" = renderBinop "&";
    "<<" = renderBinop "<<";
    ">>" = renderBinop ">>";
  };

  # Single set element. Three shapes:
  #   - 2-tuple list [k, v] → map element `<k> : <v>`
  #   - { elem = { val; …; } } → forward to renderElem (timeout/expires/comment)
  #   - anything else → render as plain expression
  renderSetElement =
    ctx: v:
    if builtins.isList v && builtins.length v == 2 then
      let
        k = builtins.elemAt v 0;
        d = builtins.elemAt v 1;
      in
      "${renderExpression ctx k} : ${renderExpression ctx d}"
    else if builtins.isAttrs v && builtins.attrNames v == [ "elem" ] then
      renderElem ctx v.elem
    else
      renderExpression ctx v;

  # ---- main entry point ------------------------------------------------

  renderExpression =
    ctx: v:
    if builtins.isAttrs v then
      let
        names = builtins.attrNames v;
      in
      if builtins.length names != 1 then
        throw "text.expressions: tagged expression must have exactly one key, got [${lib.concatStringsSep ", " names}]"
      else
        let
          tag = builtins.head names;
          body = v.${tag};
        in
        if !(taggedRenderers ? ${tag}) then
          throw "text.expressions: no renderer for tag '${tag}'"
        else
          taggedRenderers.${tag} ctx body
    else if builtins.isList v then
      # A bare list at expression position — rare. Render comma-joined; the
      # specific cases that actually use this (set elements, range pairs,
      # concat children) are dispatched by their parent renderers above
      # before reaching this branch.
      lib.concatMapStringsSep ", " (renderExpression (resetPrec ctx)) v
    else
      renderScalar v;
in
{
  inherit
    renderExpression
    renderSetElement
    renderElem
    renderVerdict
    renderJump
    renderGoto
    binopPrec
    ;
}
