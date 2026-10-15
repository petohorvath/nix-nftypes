/*
  Renderer for the top-level command attrTag (lib/schema/commands.nix).

  Each command is `{ <verb>: { <kind>: <body> } }`. The verbs:
    add / create / delete / destroy — body is any add-object kind
    list / reset / flush             — body is any kind of the verb's union
    replace / insert                 — body is a single-tag {rule: ...}
    rename                           — body is a single-tag {chain: ...}

  Most verbs are just `<verb> <object-rendering>`. Two exceptions:
    - `rename chain` uses a one-line form with both old and new names
      (no braces), handled by renderRename.
    - `create` on counter/quota/limit/synproxy/secmark uses *positional*
      values after the name (the text grammar rejects the brace form
      there), handled by renderCreate + positionalCreate. The positional forms
      have no comment clause, so a comment there is a Refusal.
*/
{
  lib,
  primitives,
  objects,
  limit,
}:

let
  inherit (objects) renderObject renderObjectHeader;

  # Unwrap `{ <kind>: <body> }` into a (kind, body) pair, then prefix
  # with the verb. `objectRenderer` is either `renderObject` (emits
  # header + body block) or `renderObjectHeader` (header only — for
  # by-name verbs like delete/destroy/flush/reset/list, whose text grammar
  # forbids brace bodies).
  renderVerbCommand =
    objectRenderer: verb: ctx: wrapped:
    let
      names = builtins.attrNames wrapped;
    in
    if builtins.length names != 1 then
      throw "nix-nftypes: text: ${verb} expects exactly one inner kind, got [${lib.concatStringsSep ", " names}]"
    else
      let
        kind = builtins.head names;
        body = wrapped.${kind};
      in
      "${verb} ${objectRenderer ctx kind body}";

  # rename chain: the text grammar requires both old and new chain names
  # on the same line, no braces. The schema's rename body carries the new
  # name in `newname`.
  renderRename =
    _ctx:
    { chain }:
    let
      prefix = "rename chain ${primitives.safeToken "rename family" chain.family} ${primitives.identQuote "table name" chain.table} ${primitives.identQuote "chain name" chain.name}";
      newname =
        if (chain.newname or null) == null then
          throw "nix-nftypes: text: rename.chain requires `newname`"
        else
          chain.newname;
    in
    "${prefix} ${primitives.identQuote "chain newname" newname}";

  # `create` for counter/quota/limit/synproxy/secmark: positional body, no
  # braces.
  # `<verb> <kind> <fam> <table> <name> <positional-args>`.
  positionalCreate = {
    counter = objects.renderCounterClause;

    quota = objects.renderQuotaClause;

    limit = limit.renderCreate;

    # The clause ends in `;`: without flags, nft wants a separator after
    # `wscale N`.
    synproxy = body: "${objects.renderSynproxyClause body};";

    # nft's text needs the context here, while JSON loads a secmark
    # without one.
    secmark =
      body:
      if (body.context or null) == null then
        primitives.refuseNoTextSpelling "create secmark context" "nft's text `create secmark` takes its SELinux context positionally and requires one, while JSON's loads a secmark without one. Give a context, or use `add secmark`."
      else
        primitives.quoteString "secmark context" body.context;
  };

  # `create` dispatcher: use positional body for counter/quota/limit/
  # synproxy/secmark, full brace body for other kinds.
  renderCreate =
    ctx: wrapped:
    let
      names = builtins.attrNames wrapped;
    in
    if builtins.length names != 1 then
      throw "nix-nftypes: text: create expects exactly one inner kind, got [${lib.concatStringsSep ", " names}]"
    else
      let
        kind = builtins.head names;
        body = wrapped.${kind};
      in
      if positionalCreate ? ${kind} then
        # Header only (family/table/name), then positional values.
        let
          headerRendering = renderObjectHeader ctx kind body;
          positional = positionalCreate.${kind} body;
        in
        if (body.comment or null) != null then
          primitives.refuseNoTextSpelling "create ${kind} comment" "nft's text `create ${kind}` takes no comment, while JSON's loads one. Use `add ${kind}`, or drop the comment."
        else
          "create ${headerRendering}${lib.optionalString (positional != "") " ${positional}"}"
      else
        # Brace-body kinds (set/map/flowtable/ct-*/...);
        # `add`-style rendering works.
        "create ${renderObject ctx kind body}";

  # Text reads a rule's handle as a position. nft's JSON parser ignores a
  # listed rule's handle, so text leaves it off. On `add rule`, nft 1.1.6's
  # JSON parser ignores it too, while 1.1.7's reads it as text does, so
  # text can't load what both versions load.
  renderListedObject =
    ctx: kind: body:
    renderObject ctx kind (if kind == "rule" then removeAttrs body [ "handle" ] else body);

  renderAddedObject =
    ctx: kind: body:
    if kind == "rule" && (body.handle or null) != null then
      primitives.refuseNoTextSpelling "add rule handle" "nftables 1.1.6's JSON parser ignores a handle on `add rule` and appends the rule, while 1.1.7's, like text, adds it after the rule with that handle. Place the rule with `index`, or with `insert`."
    else
      renderObject ctx kind body;

  verbRenderers = {
    add = renderVerbCommand renderAddedObject "add";
    replace = renderVerbCommand renderObject "replace";
    insert = renderVerbCommand renderObject "insert";
    create = renderCreate;
    delete = renderVerbCommand renderObjectHeader "delete";
    destroy = renderVerbCommand renderObjectHeader "destroy";
    list = renderVerbCommand renderObjectHeader "list";
    reset = renderVerbCommand renderObjectHeader "reset";
    flush = renderVerbCommand renderObjectHeader "flush";
    rename = renderRename;
  };

  # Render a top-level command. Accepts either a tagged command
  # `{ verb: { kind: body } }` or a bare list-object form
  # `{ kind: body }` (used in `nft -j list` output).
  renderCommand =
    ctx: cmd:
    if !(builtins.isAttrs cmd) then
      throw "nix-nftypes: text: command must be an attrset, got ${builtins.typeOf cmd}"
    else
      let
        names = builtins.attrNames cmd;
      in
      if builtins.length names != 1 then
        throw "nix-nftypes: text: command must have exactly one tag, got [${lib.concatStringsSep ", " names}]"
      else
        let
          tag = builtins.head names;
        in
        if verbRenderers ? ${tag} then
          # A metainfo appears only in a listing: nft's text and JSON
          # parsers reject every command that names one.
          if builtins.isAttrs cmd.${tag} && cmd.${tag} ? metainfo then
            primitives.refuseNoTextSpelling "${tag} metainfo" "A metainfo appears only in a listing, and nft rejects `${tag} metainfo` in text and JSON."
          else
            verbRenderers.${tag} ctx cmd.${tag}
        else
          # Bare list-object (no verb). Render as the object itself —
          # body is meaningful here (this is the form `nft -j list` emits).
          renderListedObject ctx tag cmd.${tag};
in
{
  inherit renderCommand;
}
