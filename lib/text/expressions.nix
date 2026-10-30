/*
  Renderer for the recursive `expression` type. Mirrors the schema layout
  in lib/schema/expressions.nix:
    - scalar fallbacks: string, int, bool;
    - bare list (used inside set/concat/range bodies);
    - tagged union (the schema's `taggedExpression`) dispatched by single key.

  Two contexts in which expressions appear:
    - default — top-level, statement RHS, etc.
    - inside another binop — caller sets ctx.parentPrec; this renderer
      wraps the result in parens iff our precedence is lower than parent.
      A binop raises the parent precedence by one for every operand after
      the first, so a right operand of equal precedence is wrapped too.

  `set` / `map` / `elem` carry context-sensitive surface forms; the cases
  here cover the in-expression form (anonymous set literal, map lookup,
  element-with-options). The object renderer in lib/text/objects.nix calls
  its own variants for the named-object forms.
*/
{
  fail,
  lib,
  context,
  primitives,
  nftSafeScalar,
}:

let
  inherit (context) resetPrec withPrec;
  inherit (primitives) safeToken;

  # C-style precedence of the binary operators. Higher = tighter binding.
  # `nft -f` accepts redundant parens, so adding more is always safe; we
  # only add them where required (see `renderBinop`).
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
      # nft's text lexes `-1` as a minus sign. Quoted, it is the symbol
      # JSON's integer becomes (parser_json.c json_parse_immediate).
      if v < 0 then ''"${toString v}"'' else toString v
    else if builtins.isBool v then
      (if v then "1" else "0")
    else if builtins.isString v then
      # Strings in expression position are atoms: ip addresses,
      # identifiers, set references like "@trusted_v4". They render
      # bare into the surrounding statement context, so any whitespace
      # or nft-grammar metacharacter would either split the token or
      # let a payload break out of expression position entirely. The
      # schema's `nftSafeScalarType` catches most violations at
      # evalModules time; this assert backstops callers that bypass
      # the schema (raw attrsets, third-party DSLs).
      if !(nftSafeScalar.isSafe v) then
        primitives.refuse
          {
            field = "expression";
            value = v;
          }
          "refusing to render a scalar string at expression position that contains a character unsafe for nft's bare-token grammar (any of: whitespace, ',', ';', '{', '}', '\"', '\\', '#', control character, byte above 0x7F). The renderer emits the value verbatim, so an unsafe byte either splits the token or breaks the parser context — at rule scope a newline + statement payload silently appends attacker-controlled commands."
      # A `@name` reference's name may hold a `/`, as nft's text and
      # JSON read it; any other string with one would load as a prefix.
      else if lib.hasPrefix "@" v then
        "@${primitives.checkName "reference" "expression" (lib.removePrefix "@" v)}"
      else if lib.hasInfix "/" v then
        primitives.refuseBarePrefix "expression" v
      else
        v
    else
      fail "cannot render scalar of unknown type";

  # ---- quoted values ----------------------------------------------------

  # Meta keys whose value is an interface name.
  ifnameMetaKeys = [
    "iifname"
    "oifname"
    "sdifname"
    "ibrname"
    "obrname"
  ];

  # True for an expression whose value is an interface name: an ifname
  # meta key, or a fib lookup of the output interface name.
  isIfnameExpression =
    e:
    builtins.isAttrs e
    && builtins.length (builtins.attrNames e) == 1
    && (builtins.elem (e.meta.key or null) ifnameMetaKeys || (e.fib.result or null) == "oifname");

  # True for an OS fingerprint (`osf name`, `osf version`), a string that
  # nft's text parses only quoted: it lists `"Linux:3.0"`.
  isOsfExpression = e: builtins.isAttrs e && builtins.attrNames e == [ "osf" ];

  # How the string values of expression `e` are quoted: a function of a
  # Refusal field and the string, or null for values written bare.
  quoterOfExpression =
    e:
    if isIfnameExpression e then
      primitives.quoteIfname
    else if isOsfExpression e then
      primitives.quoteString
    else
      null;

  isConcat =
    v: builtins.isAttrs v && builtins.attrNames v == [ "concat" ] && builtins.isList v.concat;

  /*
    A slot is a position that holds values of a known key: `field` names
    it in a Refusal, and `shape` has one entry per concatenation
    component: how that component's strings are quoted (see
    `quoterOfExpression`), or null. The renderer quotes those components
    and renders the others as expressions.
  */
  slotOf = field: shape: { inherit field shape; };

  # A slot the renderer knows nothing about: every value is an expression,
  # and a string must be one nft's lexer reads as written, since the
  # renderer can't quote it for a type it doesn't know.
  unidentifiedSlot = field: slotOf field [ null ] // { identified = false; };

  plainSlot = unidentifiedSlot "expression";

  # The slot of the values an expression is compared with or keyed by.
  slotOfExpression =
    field: e:
    slotOf field (if isConcat e then map quoterOfExpression e.concat else [ (quoterOfExpression e) ]);

  # The slot of the values of a set or map datatype: a type name, a list
  # of them for a concatenation, or `{ typeof = <expression>; }`.
  slotOfDatatype =
    field: dt:
    let
      quoterOfType = t: if t == "ifname" then primitives.quoteIfname else null;
    in
    if builtins.isString dt then
      slotOf field [ (quoterOfType dt) ]
    else if builtins.isList dt then
      slotOf field (map quoterOfType dt)
    else if builtins.isAttrs dt && dt ? typeof then
      slotOfExpression field dt.typeof
    else
      plainSlot;

  # JSON reads a leading `@` as a set reference and the string `*` as the
  # catch-all element; both keep their bare spelling, which means the same
  # in text.
  renderQuotedComponent =
    quote: field: ctx: v:
    if builtins.isString v && !(lib.hasPrefix "@" v) && v != "*" then
      quote field v
    else
      renderExpression ctx v;

  # The literal strings of a value: itself, or the parts of a
  # concatenation or range.
  literalStrings =
    v:
    if isConcat v then
      lib.concatMap literalStrings v.concat
    else if builtins.isAttrs v && builtins.attrNames v == [ "range" ] && builtins.isList v.range then
      lib.concatMap literalStrings v.range
    else
      lib.optional (builtins.isString v) v;

  # A value of `slot` that isn't quoted. A bare string with a `/`, but a
  # `@name` reference, would load as a prefix, so it is refused. In an
  # unidentified slot, so is a string nft's lexer reads as something else.
  renderUnquotedIn =
    slot: ctx: v:
    let
      rendered = renderExpression ctx v;
      misreadString = lib.findFirst (s: !(primitives.isWrittenSymbol s)) null (literalStrings v);
    in
    if builtins.isString v && !(lib.hasPrefix "@" v) && lib.hasInfix "/" v then
      primitives.refuseBarePrefix slot.field v
    else if (slot.identified or true) || misreadString == null then
      rendered
    else
      builtins.seq rendered (primitives.refuseUnidentified slot.field misreadString);

  # One value of `slot`.
  renderValueIn =
    slot: ctx: v:
    let
      inherit (slot) field shape;
    in
    if lib.all (quote: quote == null) shape then
      renderUnquotedIn slot ctx v
    else if builtins.length shape == 1 then
      renderQuotedComponent (builtins.head shape) field ctx v
    else if isConcat v && builtins.length v.concat == builtins.length shape then
      lib.concatStringsSep " . " (
        lib.zipListsWith (
          quote: x:
          if quote != null then
            renderQuotedComponent quote field (resetPrec ctx) x
          else
            renderUnquotedIn slot (resetPrec ctx) x
        ) shape v.concat
      )
    else
      renderUnquotedIn slot ctx v;

  # ---- per-tag renderers ------------------------------------------------

  # Anonymous set literal: { a, b, c }. Delegates element rendering to
  # renderSetElementIn so map 2-tuples and elem-wrappers are handled.
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
  #
  # Elements are values of `keySlot`; a map element's data is a value of
  # `dataSlot`.
  renderSetIn =
    keySlot: dataSlot: ctx: body:
    if builtins.isString body && lib.hasPrefix "@" body then
      body
    else if !(builtins.isList body) then
      primitives.refuse
        {
          field = "set expression";
          value = body;
        }
        "refusing to render a `{ set = …; }` body that is neither a list (anonymous set) nor an `@`-prefixed string (named-set reference). For a named-set reference, use `expr.setRef \"<name>\"` or pass `\"@<name>\"` directly as the right operand."
    else if body == [ ] then
      "{ }"
    else
      "{ "
      + lib.concatMapStringsSep ", " (renderSetElementIn keySlot dataSlot (resetPrec ctx)) body
      + " }";

  renderSet = renderSetIn plainSlot plainSlot;

  # The right side of a match, or the map of a lookup, whose left side or
  # key is `left`: a value, or an anonymous set or map of values, of the
  # slot `left` gives.
  renderRightOf =
    field: left: ctx: v:
    let
      slot = slotOfExpression field left;
    in
    if builtins.isAttrs v && builtins.attrNames v == [ "set" ] then
      renderSetIn slot plainSlot ctx v.set
    else
      renderValueIn slot ctx v;

  # In-expression map lookup: <key> map <data>. Used as an RHS expression
  # like `tcp dport map @port_forward`. The named-map definition lives in
  # objects.nix; this is the lookup form.
  renderMapLookup =
    ctx:
    { key, data }:
    "${renderExpression (resetPrec ctx) key} map ${
      renderRightOf "map lookup key" key (resetPrec ctx) data
    }";

  # CIDR prefix: <addr>/<len>.
  renderPrefix =
    ctx:
    { addr, len }:
    "${renderExpression (resetPrec ctx) addr}/${safeToken "prefix len" len}";

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
  # key presence, mirroring the schema's addCheck predicates. `base` (raw
  # form) is enum-typed; the named/tunnel forms thread protocol/field/tunnel
  # through `safeToken` since the schema accepts them as `types.str`.
  renderPayload =
    _ctx: body:
    if body ? base && body ? offset && body ? len then
      "@${safeToken "payload base" body.base},${safeToken "payload offset" body.offset},${safeToken "payload len" body.len}"
    else if body ? tunnel then
      "${safeToken "payload tunnel" body.tunnel} ${safeToken "payload protocol" body.protocol} ${renderPayloadField body.protocol body.field}"
    else
      "${safeToken "payload protocol" body.protocol} ${renderPayloadField body.protocol body.field}";

  /*
    Text spellings of payload fields that aren't one bare token: arp's
    two-word addresses, and icmpv6 `parameter-problem`, which nft lists but
    parses only as `param-problem`. Every other field must be one bare
    token, so a field with a space can't add words to the match.
  */
  payloadFieldSpellings = {
    arp = lib.genAttrs [
      "saddr ether"
      "saddr ip"
      "daddr ether"
      "daddr ip"
    ] lib.id;
    icmpv6."parameter-problem" = "param-problem";
  };

  renderPayloadField =
    protocol: field: payloadFieldSpellings.${protocol}.${field} or (safeToken "payload field" field);

  # Extension header (IPv6): <name> <field> for field access; bare <name>
  # for existence checks. The text grammar accepts both.
  # Without a field, an existence check: `exthdr <name>`, which nft's
  # text spells only for these headers.
  exthdrExistenceNames = [
    "hbh"
    "rt"
    "frag"
    "dst"
    "mh"
  ];

  renderExthdr =
    _ctx: body:
    if (body.field or null) == null then
      if builtins.elem body.name exthdrExistenceNames then
        "exthdr ${body.name}"
      else
        primitives.refuseNoTextSpelling "exthdr name" "nft's text checks only ${lib.concatStringsSep ", " exthdrExistenceNames} for existence."
    else
      "${safeToken "exthdr name" body.name} ${safeToken "exthdr field" body.field}";

  renderTcpOption =
    _ctx: body:
    if body ? base then
      "tcp option @${safeToken "tcp option base" body.base},${safeToken "tcp option offset" body.offset},${safeToken "tcp option len" body.len}"
    else if (body.field or null) == null then
      "tcp option ${safeToken "tcp option name" body.name}"
    else
      "tcp option ${safeToken "tcp option name" body.name} ${safeToken "tcp option field" body.field}";

  renderIpOption =
    _ctx: body:
    if (body.field or null) == null then
      "ip option ${safeToken "ip option name" body.name}"
    else
      "ip option ${safeToken "ip option name" body.name} ${safeToken "ip option field" body.field}";

  renderSctpChunk =
    _ctx: body:
    if (body.field or null) == null then
      "sctp chunk ${safeToken "sctp chunk name" body.name}"
    else
      "sctp chunk ${safeToken "sctp chunk name" body.name} ${safeToken "sctp chunk field" body.field}";

  renderDccpOption = _ctx: body: "dccp option ${safeToken "dccp option type" body.type}";

  renderMeta = _ctx: body: "meta ${safeToken "meta key" body.key}";

  # Routing data: `rt <key>` or `rt <family> <key>` (for nexthop-style keys).
  renderRt =
    _ctx: body:
    "rt "
    + lib.optionalString ((body.family or null) != null) "${safeToken "rt family" body.family} "
    + safeToken "rt key" body.key;

  # The ct keys whose token holds a space: nft's text reads the family and
  # the address key as one key (ct_templates).
  ctFamilyAddressKeys = [
    "ip saddr"
    "ip daddr"
    "ip6 saddr"
    "ip6 daddr"
  ];

  # Conntrack: `ct [<dir>] <key>`. A key such as `ip saddr` carries its
  # family. nft's JSON parser ignores a `family` field, while text would
  # load it as part of the key, so it is refused (ADR 0010).
  renderCt =
    _ctx: body:
    if (body.family or null) != null then
      primitives.refuseJsonIgnored "ct family"
    else
      lib.concatStringsSep " " (
        [ "ct" ]
        ++ lib.optional ((body.dir or null) != null) (safeToken "ct dir" body.dir)
        ++ [
          (if builtins.elem body.key ctFamilyAddressKeys then body.key else safeToken "ct key" body.key)
        ]
      );

  renderNumgen =
    _ctx: body:
    let
      base = "numgen ${safeToken "numgen mode" body.mode} mod ${safeToken "numgen mod" body.mod}";
    in
    base
    + lib.optionalString (
      (body.offset or null) != null
    ) " offset ${safeToken "numgen offset" body.offset}";

  renderJhash =
    ctx: body:
    let
      base = "jhash ${renderExpression (resetPrec ctx) body.expr} mod ${safeToken "jhash mod" body.mod}";
    in
    base
    + lib.optionalString ((body.seed or null) != null) " seed ${safeToken "jhash seed" body.seed}"
    + lib.optionalString (
      (body.offset or null) != null
    ) " offset ${safeToken "jhash offset" body.offset}";

  renderSymhash =
    _ctx: body:
    "symhash mod ${safeToken "symhash mod" body.mod}"
    + lib.optionalString (
      (body.offset or null) != null
    ) " offset ${safeToken "symhash offset" body.offset}";

  # FIB: `fib <flags> <result>`, where flags is dot-separated when multiple.
  renderFib =
    _ctx: body:
    let
      flagsPrefix =
        if (body.flags or null) == null then
          ""
        else
          primitives.flags {
            field = "fib flags";
            sep = " . ";
          } body.flags
          + " ";
    in
    "fib ${flagsPrefix}${safeToken "fib result" body.result}";

  renderSocket = _ctx: body: "socket ${safeToken "socket key" body.key}";

  renderOsf =
    _ctx: body:
    "osf "
    + lib.optionalString ((body.ttl or null) != null) "ttl ${safeToken "osf ttl" body.ttl} "
    + safeToken "osf key" body.key;

  # ipsec: `ipsec <dir> [spnum N] <family> <key>`. The dir is required for
  # the text form; if absent we leave it off and rely on the parser to
  # accept the bare form (rare).
  renderIpsec =
    _ctx: body:
    let
      parts = [
        "ipsec"
      ]
      ++ lib.optional ((body.dir or null) != null) (safeToken "ipsec dir" body.dir)
      ++ lib.optional ((body.spnum or null) != null) "spnum ${safeToken "ipsec spnum" body.spnum}"
      ++ lib.optional ((body.family or null) != null) (safeToken "ipsec family" body.family)
      ++ [ (safeToken "ipsec key" body.key) ];
    in
    lib.concatStringsSep " " parts;

  renderTunnelExpr = _ctx: body: "tunnel ${safeToken "tunnel key" body.key}";

  # Element with options (used inside set element lists). The renderer for
  # bare elements is renderSetElementIn, which dispatches to this when the
  # value is `{ elem = { ... } }`.
  #
  # nft's JSON parser ignores element statements, both the keys nft lists
  # (`counter`, `quota`, `limit`, `last`) and a `stmt` list, while text
  # would load them, so they are refused (ADR 0010).
  renderElemIn =
    slot: ctx:
    {
      val,
      timeout ? null,
      expires ? null,
      comment ? null,
      counter ? null,
      quota ? null,
      limit ? null,
      last ? null,
      stmt ? null,
    }:
    let
      statementKeys = lib.attrNames (
        lib.filterAttrs (_: value: value != null) {
          inherit
            counter
            last
            limit
            quota
            stmt
            ;
        }
      );
    in
    if statementKeys != [ ] then
      primitives.refuseJsonIgnored "element ${builtins.head statementKeys}"
    else
      renderValueIn slot (resetPrec ctx) val
      + lib.optionalString (timeout != null) " timeout ${safeToken "element timeout" timeout}s"
      + lib.optionalString (expires != null) " expires ${safeToken "element expires" expires}s"
      + lib.optionalString (
        comment != null
      ) " comment ${primitives.quoteString "element comment" comment}";

  renderElem = renderElemIn plainSlot;

  # Verdict target is a chain name; route through `primitives.name` so the
  # renderer's `assertSafeString` assert catches the parser-meta injection set
  # ('"', '\', control chars) and other invalid bytes land in the
  # quoted-form fallback that nft rejects in identifier position.
  renderJump = _ctx: { target }: "jump ${primitives.name "identifier" "jump target" target}";
  renderGoto = _ctx: { target }: "goto ${primitives.name "identifier" "goto target" target}";

  # Bare verdicts as expressions (vmap data position).
  renderVerdict =
    name: _ctx: _body:
    name;

  /*
    nft's grammar is left-associative, and its JSON parser folds an operand
    list left (`[a b c]` is `(a op b) op c`). The first operand needs
    parens only below this precedence; every later one also at it, or
    `mark << (1 << 2)` would load as `mark << 1 << 2`, which is `mark << 3`.
  */
  renderBinop =
    op: ctx: xs:
    let
      myPrec = binopPrec.${op};
      renderOperand =
        index: x: renderExpression (withPrec (if index == 0 then myPrec else myPrec + 1) ctx) x;
      rendered = lib.concatStringsSep " ${op} " (lib.imap0 renderOperand xs);
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

  # Single set element, a value of `keySlot`. Three shapes:
  #   - 2-tuple list [k, v] → map element `<k> : <v>`, v of `dataSlot`
  #   - { elem = { val; …; } } → renderElemIn (timeout/expires/comment)
  #   - anything else → render as a value
  renderSetElementIn =
    keySlot: dataSlot: ctx: v:
    if builtins.isList v && builtins.length v == 2 then
      let
        k = builtins.elemAt v 0;
        d = builtins.elemAt v 1;
      in
      "${renderValueIn keySlot ctx k} : ${renderValueIn dataSlot ctx d}"
    else if builtins.isAttrs v && builtins.attrNames v == [ "elem" ] then
      renderElemIn keySlot ctx v.elem
    else
      renderValueIn keySlot ctx v;

  # The value of an `add element` command, whose set type the renderer
  # can't see.
  renderElementCommandValue = renderSetElementIn (unidentifiedSlot "element") (
    unidentifiedSlot "element value"
  );

  # ---- main entry point ------------------------------------------------

  renderExpression =
    ctx: v:
    if builtins.isAttrs v then
      let
        names = builtins.attrNames v;
      in
      if builtins.length names != 1 then
        fail "tagged expression must have exactly one key, got [${lib.concatStringsSep ", " names}]"
      else
        let
          tag = builtins.head names;
          body = v.${tag};
        in
        if !(taggedRenderers ? ${tag}) then
          fail "no renderer for tag '${tag}'"
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
    binopPrec
    renderElem
    renderElementCommandValue
    renderExpression
    renderGoto
    renderJump
    renderRightOf
    renderSetElementIn
    renderVerdict
    slotOfDatatype
    ;
  # The tag set this renderer's dispatch table accepts. Read by the
  # schema↔text drift test (tests/unit/schema.nix) to assert every tagged
  # expression tag has a renderer entry.
  tags = builtins.attrNames taggedRenderers;
}
