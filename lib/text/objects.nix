/*
  Renderer for the object kinds in lib/schema/objects.nix.

  Each object kind renders as the body of an `add <kind>` command (or
  `flush <kind>`, `delete <kind>`, etc — the command renderer in
  lib/text/commands.nix prepends the verb).

  Bodies generally take the form:

    <family> <table> [<chain>|<set>|<...>] <name> [{ <opt>; <opt>; ... }]

  Required header (family/table/chain/name) goes on the same line as the
  verb; optional clauses go inside braces. For pretty mode, opts inside
  braces are one-per-line indented; for compact mode, separated by `; `.
*/
{
  fail,
  lib,
  context,
  primitives,
  expressions,
  statements,
  limit,
  nftSafeScalar,
}:

let
  inherit (context)
    indent
    resetPrec
    withDepth
    withFamily
    ;
  inherit (expressions)
    renderElementCommandValue
    renderExpression
    renderSetElementIn
    slotOfDatatype
    ;
  inherit (primitives) identQuote quoteIfname safeToken;
  inherit (statements) renderRuleExpr;

  renderInnerExpression = ctx: e: renderExpression (resetPrec ctx) e;

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
  # implies family/table, so `renderObjectScope` collapses to just the
  # object's name. `renderTableScope` is unaffected — the only caller (the
  # table header itself) is never rendered in block form.
  renderTableScope = body: "${safeToken "family" body.family} ${identQuote "table name" body.table}";
  renderObjectScope =
    ctx: body:
    if ctx.block then
      identQuote "object name" body.name
    else
      "${renderTableScope body} ${identQuote "object name" body.name}";

  # SECURITY-CRITICAL: a string datatype renders bare into the set/map
  # `type <X>` clause; a list renders bare joined with ` . `. An unsafe
  # byte in the name either ends the `type` clause early (`;`, `}`,
  # newline) and lets the trailing bytes parse as fresh nft commands,
  # or splits the token in ways that corrupt the parse. The legitimate
  # datatype set is identifier-shaped (`ipv4_addr`, `inet_service`,
  # `ifname`, …), so the shared `nft-safe-scalar` predicate captures
  # exactly the safe subset.
  assertSafeDatatype =
    field: name:
    if !(builtins.isString name) || nftSafeScalar.isSafe name then
      true
    else
      primitives.refuse
        {
          inherit field;
          value = name;
        }
        "refusing to render a set/map datatype that contains a character unsafe for nft's `type <X>` clause. The renderer emits the value bare (or joined with ` . ` for concatenated keys), so an unsafe byte either truncates the clause or splits the token — at table scope a newline + `add chain …` payload silently appends an attacker-controlled chain. The shared predicate (lib/nft-safe-scalar.nix) excludes whitespace, ',', ';', '{', '}', '\"', '\\', '#', and control characters; legitimate nft datatypes are identifier-shaped and pass cleanly.";

  # Render a datatype: string → "ipv4_addr"; list → "ipv4_addr . port".
  renderDatatype =
    field: dt:
    if builtins.isString dt then
      lib.seq (assertSafeDatatype field dt) dt
    else if builtins.isList dt then
      lib.seq (lib.all (assertSafeDatatype field) dt) (lib.concatStringsSep " . " dt)
    else
      fail "unrecognized datatype shape";

  isTypeof = dt: builtins.isAttrs dt && dt ? typeof;

  # The expression a `{ typeof = …; }` declaration derives its datatype
  # from.
  renderTypeof = ctx: dt: renderInnerExpression ctx dt.typeof;

  # `typeof <expr>` or `type <datatype>`.
  renderSetTypeLine =
    ctx: body:
    if isTypeof body.type then
      "typeof ${renderTypeof ctx body.type}"
    else
      "type ${renderDatatype "set type" body.type}";

  /*
    nft's text grammar declares both sides of a map with one keyword. A
    typeof key takes a typeof value, or a value type by name (`verdict`,
    or an object kind such as `counter`); a datatype key can't take a
    typeof value.
  */
  renderMapTypeLine =
    ctx: body:
    let
      # Two-word object kinds, which nft's text takes after a typeof key
      # only, though it lists them after a datatype key too.
      isCtObjectKind = builtins.elem body.map [
        "ct helper"
        "ct timeout"
        "ct expectation"
      ];
    in
    if isTypeof body.type then
      "typeof ${renderTypeof ctx body.type} : ${
        if isTypeof body.map then
          renderTypeof ctx body.map
        else if isCtObjectKind then
          body.map
        else
          renderDatatype "map value type" body.map
      }"
    else if isCtObjectKind then
      primitives.refuseNoTextSpelling "map type" "nft's text declares a map of ${body.map} objects only with a typeof key, as in `typeof tcp dport : ${body.map}`."
    else if isTypeof body.map then
      primitives.refuse
        {
          field = "map type";
        }
        "refusing to render a map with a datatype key and a typeof value: map ${
          builtins.toJSON (body.name or null)
        }. nft's text grammar declares both sides with `type` or both with `typeof`; give the key as `{ typeof = …; }` too, or the value as a datatype."
    else
      "type ${renderDatatype "map type" body.type} : ${renderDatatype "map value type" body.map}";

  # Render the elements clause of a set or map: keys are values of
  # `keySlot` and a map's data values of `dataSlot`. Empty list → empty
  # (caller skips the clause).
  renderElements =
    keySlot: dataSlot: ctx: elems:
    let
      inner = lib.concatMapStringsSep ", " (renderSetElementIn keySlot dataSlot (resetPrec ctx)) elems;
    in
    "elements = { ${inner} }";

  # A device list, `devices = { "eth0", "eth1" }`. Quoted, as every
  # interface name is, a device such as `010` keeps its name.
  renderDevices =
    field: devs: "devices = { ${lib.concatMapStringsSep ", " (quoteIfname field) devs} }";

  # Render a chain `dev` field — either a bare string ("eth0") or a list.
  # Single device: `device "eth0"`; multiple: `devices = { "eth0", "eth1" }`.
  renderChainDev =
    dev:
    if builtins.isString dev then
      "device ${quoteIfname "chain device" dev}"
    else
      renderDevices "chain device" dev;

  # ---- per-kind body renderers ---------------------------------------

  renderTableHeader =
    _ctx: body:
    renderTableScope {
      inherit (body) family;
      table = body.name;
    };

  renderTableBody =
    _ctx: body:
    lib.optionals ((body.flags or null) != null) [
      "flags ${primitives.flags { field = "table flags"; } body.flags}"
    ]
    ++ lib.optionals ((body.comment or null) != null) [
      "comment ${primitives.quoteString "table comment" body.comment}"
    ];

  renderChainHeader = ctx: body: renderObjectScope ctx body;

  # Shared between renderRuleHeader (imperative `add rule …`) and the
  # block-form rule lines folded into a chain's brace block: the
  # statements + optional `comment "…"` clause that make up everything
  # after the rule's family/table/chain prefix.
  renderRuleStmtsAndComment =
    ctx: body:
    let
      stmts = renderRuleExpr (withFamily (body.family or null) ctx) body.expr;
      commentClause =
        if (body.comment or null) == null then
          ""
        else
          " comment ${primitives.quoteString "rule comment" body.comment}";
    in
    "${stmts}${commentClause}";

  renderChainBody =
    _ctx: body:
    let
      isBase = (body.type or null) != null && (body.hook or null) != null && (body.prio or null) != null;
      baseLine =
        if isBase then
          let
            devClause = if (body.dev or null) == null then "" else " ${renderChainDev body.dev}";
          in
          [
            "type ${safeToken "chain type" body.type} hook ${safeToken "chain hook" body.hook}${devClause} priority ${primitives.priority "chain prio" body.prio}"
          ]
        else
          [ ];
      policyLine = lib.optional (
        (body.policy or null) != null
      ) "policy ${safeToken "chain policy" body.policy}";
      commentLine = lib.optional (
        (body.comment or null) != null
      ) "comment ${primitives.quoteString "chain comment" body.comment}";
    in
    baseLine ++ policyLine ++ commentLine;

  # The table module supplies this chain's rules explicitly. Formatting
  # context contains no table data, and imperative chain declarations keep
  # their usual body without inline rules.
  renderChainBlock =
    ctx: body: rules:
    "chain ${identQuote "chain name" body.name}${
      block ctx (renderChainBody ctx body ++ map (renderRuleStmtsAndComment ctx) rules)
    }";

  /*
    Render a table tree's contents in block form, for a host that supplies
    the `table <family> <name> { … }` wrapper. `table` is the table
    module's cleaned `{ body, chains, objects }`, with each chain's rules
    beside its body. Returns the table's options, then its chain blocks
    with their rules, then its objects, each ending with a newline. Every
    block form Refusal is raised here or in the renderers it calls.
  */
  renderTableBlock =
    ctx: table:
    lib.concatMapStrings (declaration: "${declaration}\n") (
      map (line: "${line};") (renderTableBody ctx table.body)
      ++ map (chain: renderChainBlock ctx chain.body chain.rules) table.chains
      ++ map (object: renderObject ctx object.kind object.body) table.objects
    );

  /*
    How `renderTableBlock` treats each field of the table, chain, and rule
    bodies a table tree prepares: rendered, refused, supplied by the
    tree's scope (the host's table wrapper or the enclosing chain block),
    or rejected by the tree before it renders, as a rule's `index` is,
    since a chain block lists its rules in order.
    Objects render as they do in `toText`.
    The block-form drift test (tests/unit/schema.nix) fails when a schema
    field is missing here.
  */
  blockFields = {
    table = {
      rendered = [
        "comment"
        "flags"
      ];
      scope = [
        "family"
        "name"
      ];
    };
    chain = {
      rendered = [
        "comment"
        "dev"
        "hook"
        "name"
        "policy"
        "prio"
        "type"
      ];
      scope = [
        "family"
        "table"
      ];
    };
    rule = {
      rendered = [
        "comment"
        "expr"
      ];
      rejected = [ "index" ];
      scope = [
        "chain"
        "family"
        "table"
      ];
    };
  };

  # rule: `<family> <table> <chain> <statements> [handle/index] [comment]`.
  # Rules do not use a brace block; statements are inline.
  renderRuleHeader =
    ctx: body:
    let
      pos =
        if (body.handle or null) != null then
          " handle ${safeToken "rule handle" body.handle}"
        else if (body.index or null) != null then
          " index ${safeToken "rule index" body.index}"
        else
          "";
    in
    "${renderTableScope body} ${identQuote "chain name" body.chain}${pos} ${renderRuleStmtsAndComment ctx body}";

  # Shared body renderer for set and map objects. They differ only in the
  # type clause: sets emit `type <K>`; maps emit `type <K> : <V>` (or
  # `typeof`, see the type-line renderers above). Every
  # other clause (flags/policy/size/timeout/gc-interval/auto-merge/stmt/
  # elements) is identical. A comment is refused: nft lists it, but its
  # JSON parser ignores it.
  #
  # Elements whose datatype makes them interface names are quoted (see
  # `slotOfDatatype`); bare, nft reads `010` as a number.
  renderSetOrMapBody =
    kind: typeLineFor: ctx: body:
    let
      keySlot = slotOfDatatype "${kind} element" (body.type or null);
      dataSlot = slotOfDatatype "${kind} element value" (body.map or null);
      elemList =
        if (body.elem or null) == null then
          [ ]
        else if builtins.isList body.elem then
          body.elem
        else
          [ body.elem ];
      # Set-level statements (`counter;` etc.), which give each element its
      # own instance.
      stmtLines =
        if (body.stmt or null) == null then
          [ ]
        else
          map (statements.renderStatement (resetPrec ctx)) body.stmt;
    in
    [ (typeLineFor ctx body) ]
    ++
      lib.optional ((body.flags or null) != null)
        "flags ${primitives.flags { field = "${kind} flags"; } body.flags}"
    ++ lib.optional ((body.policy or null) != null) "policy ${safeToken "${kind} policy" body.policy}"
    ++ lib.optional ((body.size or null) != null) "size ${safeToken "${kind} size" body.size}"
    ++ lib.optional (
      (body.timeout or null) != null
    ) "timeout ${safeToken "${kind} timeout" body.timeout}s"
    ++
      lib.optional ((body."gc-interval" or null) != null)
        "gc-interval ${safeToken "${kind} gc-interval" body."gc-interval"}s"
    ++ lib.optional ((body."auto-merge" or null) == true) "auto-merge"
    ++ stmtLines
    ++ lib.optional (elemList != [ ]) (renderElements keySlot dataSlot ctx elemList)
    ++ lib.optional ((body.comment or null) != null) (primitives.refuseJsonIgnored "${kind} comment");

  # set: header `<family> <table> <name>`; body covers type/flags/policy/
  # size/timeout/gc-interval/auto-merge/elements/stmt.
  renderSetHeader = ctx: body: renderObjectScope ctx body;
  renderSetBody = renderSetOrMapBody "set" renderSetTypeLine;

  # map: same as set but the type clause is `type K : V` and elements are
  # `k : v` pairs (handled by renderSetElementIn).
  renderMapHeader = ctx: body: renderObjectScope ctx body;
  renderMapBody = renderSetOrMapBody "map" renderMapTypeLine;

  # element: `<family> <table> <set-name> { <elem>, <elem>, ... }`. The
  # body is a bare comma-separated element list inside braces (no
  # `elements = ` prefix — that form is for set/map definitions).
  renderElement =
    ctx: body:
    let
      elemList = if builtins.isList body.elem then body.elem else [ body.elem ];
      inner = lib.concatMapStringsSep ", " (renderElementCommandValue (resetPrec ctx)) elemList;
    in
    "element ${renderObjectScope ctx body} { ${inner} }";

  # flowtable: `hook <hook> priority <prio>; devices = { ... };`.
  renderFlowtableHeader = ctx: body: renderObjectScope ctx body;

  renderFlowtableBody =
    _ctx: body:
    let
      hookLine =
        if (body.hook or null) != null && (body.prio or null) != null then
          [
            "hook ${safeToken "flowtable hook" body.hook} priority ${primitives.priority "flowtable prio" body.prio}"
          ]
        else
          [ ];
      devLine =
        if (body.dev or null) == null then
          [ ]
        else
          let
            devs = if builtins.isList body.dev then body.dev else [ body.dev ];
          in
          [ (renderDevices "flowtable device" devs) ];
    in
    hookLine ++ devLine;

  # counter: bare body (`add counter ...`) or with packets/bytes/comment.
  renderCounterHeader = ctx: body: renderObjectScope ctx body;

  # `packets N bytes N`, or "" without counts; shared with the positional
  # `create counter`. nft's text takes the counts only as a pair, and JSON
  # loads a missing one as 0.
  renderCounterClause =
    body:
    let
      count =
        name:
        if (body.${name} or null) == null then "0" else safeToken "counter object ${name}" body.${name};
    in
    lib.optionalString (
      (body.packets or null) != null || (body.bytes or null) != null
    ) "packets ${count "packets"} bytes ${count "bytes"}";

  renderCounterBody =
    _ctx: body:
    let
      clause = renderCounterClause body;
    in
    lib.optional (clause != "") clause
    ++ lib.optional (
      (body.comment or null) != null
    ) "comment ${primitives.quoteString "counter comment" body.comment}";

  # quota object: `[over] <bytes> bytes [used N bytes]`.
  renderQuotaHeader = ctx: body: renderObjectScope ctx body;

  # `[over] <bytes> bytes [used <used> bytes]`, shared with the positional
  # `create quota`. JSON's `bytes` defaults to 0, and text needs one.
  renderQuotaClause =
    body:
    lib.concatStringsSep " " (
      lib.optional ((body.inv or null) == true) "over"
      ++ [
        "${if (body.bytes or null) == null then "0" else safeToken "quota object bytes" body.bytes} bytes"
      ]
      ++ lib.optional (
        (body.used or null) != null
      ) "used ${safeToken "quota object used" body.used} bytes"
    );

  renderQuotaBody =
    _ctx: body:
    [ (renderQuotaClause body) ]
    ++ lib.optional (
      (body.comment or null) != null
    ) "comment ${primitives.quoteString "quota comment" body.comment}";

  # ct count object: `over <val>` (inv) or `until <val>`; the grammar
  # requires one of the two keywords.
  renderCtCountHeader = ctx: body: renderObjectScope ctx body;

  renderCtCountBody =
    _ctx: body:
    [
      "${
        if (body.inv or null) == true then "over" else "until"
      } ${safeToken "ct count object val" body.val}"
    ]
    ++ lib.optional (
      (body.comment or null) != null
    ) "comment ${primitives.quoteString "ct count comment" body.comment}";

  # Limit clauses and comments are spelled by limit.nix.
  renderLimitHeader = ctx: body: renderObjectScope ctx body;

  # ct helper object. nft text wants `type "T" protocol P` joined as a
  # single statement (the parser only accepts a `type` clause when
  # `protocol` follows it inline, no separator). `l3proto` and `comment`
  # are then separate statements with their own `;`.
  renderCtHelperHeader = ctx: body: renderObjectScope ctx body;

  renderCtHelperBody =
    _ctx: body:
    let
      hasType = (body.type or null) != null;
      hasProto = (body.protocol or null) != null;
      protocol = safeToken "ct helper protocol" body.protocol;
      typeProtoLine =
        if hasType && hasProto then
          [ "type ${primitives.quoteString "ct helper type" body.type} protocol ${protocol}" ]
        else if hasType then
          [ "type ${primitives.quoteString "ct helper type" body.type}" ]
        else if hasProto then
          [ "protocol ${protocol}" ]
        else
          [ ];
    in
    typeProtoLine
    ++ lib.optional (
      (body.l3proto or null) != null
    ) "l3proto ${safeToken "ct helper l3proto" body.l3proto}"
    ++ lib.optional (
      (body.comment or null) != null
    ) "comment ${primitives.quoteString "ct helper comment" body.comment}";

  # ct timeout object:
  # `protocol tcp; l3proto ip; policy = { established: 300, ... };`.
  renderCtTimeoutHeader = ctx: body: renderObjectScope ctx body;

  renderCtTimeoutBody =
    _ctx: body:
    let
      # `policy` is `attrsOf ints.unsigned` in the schema, so keys are
      # arbitrary strings. They render bare into `policy = { <k>: <v>, … }`
      # — a `;` / `}` / newline in a key would terminate the clause and
      # let trailing bytes parse as fresh nft commands. Connection-state
      # names (`established`, `close_wait`, `time_wait`, …) are
      # identifier-shaped and pass `safeToken` cleanly.
      policyLine =
        if (body.policy or null) == null then
          [ ]
        else
          let
            entries = lib.mapAttrsToList (
              k: v: "${safeToken "ct timeout policy key" k}: ${safeToken "ct timeout policy value" v}"
            ) body.policy;
          in
          [ "policy = { ${lib.concatStringsSep ", " entries} }" ];
    in
    lib.optional (
      (body.protocol or null) != null
    ) "protocol ${safeToken "ct timeout protocol" body.protocol}"
    ++ lib.optional (
      (body.l3proto or null) != null
    ) "l3proto ${safeToken "ct timeout l3proto" body.l3proto}"
    ++ policyLine
    ++ lib.optional (
      (body.comment or null) != null
    ) "comment ${primitives.quoteString "ct timeout comment" body.comment}";

  renderCtExpectationHeader = ctx: body: renderObjectScope ctx body;

  renderCtExpectationBody =
    _ctx: body:
    let
      line =
        name: suffix:
        lib.optional ((body.${name} or null) != null)
          "${name} ${safeToken "ct expectation ${name}" body.${name}}${suffix}";
    in
    line "protocol" ""
    ++ line "dport" ""
    ++ line "timeout" "ms"
    ++ line "size" ""
    ++ line "l3proto" ""
    ++ lib.optional (
      (body.comment or null) != null
    ) "comment ${primitives.quoteString "ct expectation comment" body.comment}";

  renderSecmarkHeader = ctx: body: renderObjectScope ctx body;

  renderSecmarkBody =
    _ctx: body:
    lib.optional ((body.context or null) != null) (
      primitives.quoteString "secmark context" body.context
    )
    ++ lib.optional (
      (body.comment or null) != null
    ) "comment ${primitives.quoteString "secmark comment" body.comment}";

  renderSynproxyHeader = ctx: body: renderObjectScope ctx body;

  /*
    `mss N; wscale N[; <flags>]`, one body statement, shared with the
    positional `create synproxy`. nft 1.1.7 misreads `mss N wscale N` on
    one line (`wscale` loads as 0, or as 8 after `timestamp`); separated by
    single `;`s, every tested nft reads it right. The flags must follow
    `wscale N;` directly, so they can't be a statement of their own.
  */
  renderSynproxyClause =
    body:
    lib.concatStringsSep "; " (
      [
        "mss ${safeToken "synproxy object mss" body.mss}"
        "wscale ${safeToken "synproxy object wscale" body.wscale}"
      ]
      ++ lib.optional ((body.flags or null) != null) (
        primitives.flags {
          field = "synproxy object flags";
          sep = " ";
        } body.flags
      )
    );

  renderSynproxyBody =
    _ctx: body:
    [ (renderSynproxyClause body) ]
    ++ lib.optional (
      (body.comment or null) != null
    ) "comment ${primitives.quoteString "synproxy comment" body.comment}";

  /*
    A tunnel object is a Refusal in every command and listed form. nft's
    JSON parser writes its `dport` into `sport`, so no text spelling loads
    what the JSON form loads (ADR 0001), and nft's JSON path crashes on
    delete, destroy, and list of one. The schema accepts tunnels only as
    Read-back.
  */
  refuseTunnel =
    _ctx: _body:
    primitives.refuse
      {
        field = "tunnel";
      }
      "refusing to render a tunnel object. nft's JSON parser loads a tunnel's ports wrongly, so text and JSON would load different tunnels. Load the tunnel with nft's own text syntax instead.";

  # A listed metainfo is listing metadata, which nft's JSON parser
  # ignores, so text drops it and loads what the JSON form loads.
  dropMetainfo = _ctx: _body: null;

  # meter (for list/flush): family/table/name only. Meters are created
  # by the `meter` statement, and nft lists one as a dynamic set.
  renderMeterHeader = ctx: body: renderObjectScope ctx body;

  # nft's text has no meter object, and its JSON parser rejects a listed
  # one ("Unknown object passed to add command").
  refuseListedMeter =
    _ctx: _body:
    primitives.refuseNoTextSpelling "meter" "nft's text has no meter object, and nft's JSON parser rejects a listed one. nft lists the dynamic set a `meter` statement creates as a `set`.";

  # ruleset envelope: null → bare; { family } → `<verb> ruleset <family>`.
  renderRulesetHeader =
    _ctx: body: if body == null || !(body ? family) then "" else safeToken "ruleset family" body.family;

  # ---- dispatch: kind → { header, body } -----------------------------
  #
  # Every kind provides either `render ctx body` (a full-string override,
  # used by `element` whose body is a comma-separated value list) or the
  # standard `header ctx body` + `body ctx body` pair. Both are `ctx:
  # body:` functions; headers that don't need ctx accept `_ctx:`.
  # Kinds with `noBraces = true` suppress the block wrapper entirely.
  # A kind that appears whole only in a listing, `metainfo` or `meter`,
  # gives `object ctx body` for that form instead of a body: it returns
  # null to drop the object, or raises a Refusal.
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
      body = _ctx: limit.renderObjectBody;
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
    "ct count" = {
      header = renderCtCountHeader;
      body = renderCtCountBody;
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
      render = refuseTunnel;
    };
    # No command takes a metainfo (lib/text/commands.nix refuses one), so
    # it has no header.
    metainfo = {
      object = dropMetainfo;
    };
    meter = {
      header = renderMeterHeader;
      object = refuseListedMeter;
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
      fail "no renderer for kind '${kind}'"
    else if withBody && kinds.${kind} ? object then
      kinds.${kind}.object ctx body
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
              blockClause = if noBraces then "" else block ctx bodyLines;
              headerSep = lib.optionalString (header != "") " ";
            in
            "${kind}${headerSep}${header}${blockClause}";
      in
      lib.removeSuffix " " rendered;

  # Render an object for an `add`/`replace`/`insert` command — emits both
  # header and body (brace block if applicable). The `element` kind uses
  # its own `render` because its body is a bare comma-separated value
  # list rather than the `;`-separated statement body the block helper
  # produces. A listed `metainfo` renders as null.
  renderObject = renderObjectGeneric true;

  # Render only the header — used for `delete`/`destroy`/`flush`/`reset`/
  # `list`/`create` verbs, which the text grammar does not accept with a
  # brace body. Callers that need `create`'s positional value form append
  # it themselves (see lib/text/commands.nix).
  renderObjectHeader = renderObjectGeneric false;
in
{
  inherit
    blockFields
    renderCounterClause
    renderObject
    renderObjectHeader
    renderQuotaClause
    renderSynproxyClause
    renderTableBlock
    ;
  # The kind set this renderer's dispatch table accepts. Read by the
  # schema↔text drift test (tests/unit/schema.nix) to assert every object
  # kind referenced by the object unions (addObject, readBackObject) has a
  # renderer entry.
  renderableKinds = builtins.attrNames kinds;
}
