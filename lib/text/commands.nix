{
  lib,
  primitives,
  objects,
}:

# Renderer for the top-level command attrTag (lib/schema/commands.nix).
#
# Each command is `{ <verb>: { <kind>: <body> } }`. The verbs:
#   add / create / delete / destroy — body is an addObject (any kind)
#   list / reset / flush             — body is the relevant restricted union
#   replace / insert                 — body is a single-tag {rule: ...}
#   rename                           — body is a single-tag {chain: ...}
#
# Most verbs are just `<verb> <object-rendering>`. Two exceptions:
#   - `rename chain` uses a one-line form with both old and new names
#     (no braces), handled by renderRename.
#   - `create` on quota/limit/synproxy uses *positional* values after
#     the name (the text grammar rejects the brace form there), handled
#     by renderCreate + positionalCreate.

let
  inherit (objects) renderObject renderObjectHeader;

  # Unwrap `{ <kind>: <body> }` into a (kind, body) pair, then prefix
  # with the verb. `renderFn` is either `renderObject` (emits header +
  # body block) or `renderObjectHeader` (header only — for by-name verbs
  # like delete/destroy/flush/reset/list, whose text grammar forbids
  # brace bodies).
  prefixed =
    renderFn: verb: ctx: wrapped:
    let
      names = builtins.attrNames wrapped;
    in
    if builtins.length names != 1 then
      throw "text.commands: ${verb} expects exactly one inner kind, got [${lib.concatStringsSep ", " names}]"
    else
      let
        kind = builtins.head names;
        body = wrapped.${kind};
      in
      "${verb} ${renderFn ctx kind body}";

  # rename chain: the text grammar requires both old and new chain names
  # on the same line, no braces. The schema reuses the chain body and
  # passes the new name in `newname`.
  renderRename =
    _ctx:
    { chain }:
    let
      pre = "rename chain ${chain.family} ${primitives.identQuote chain.table} ${primitives.identQuote chain.name}";
      newname =
        if chain.newname == null then
          throw "text.commands: rename.chain requires `newname`"
        else
          chain.newname;
    in
    "${pre} ${primitives.identQuote newname}";

  # `create` for quota/limit/synproxy: positional body, no braces.
  # `<verb> <kind> <fam> <table> <name> <positional-args>`.
  positionalCreate = {
    quota =
      body:
      let
        head = lib.optionalString ((body.inv or null) == true) "over ";
      in
      "${head}${toString body.bytes} bytes"
      + lib.optionalString ((body.used or null) != null) " used ${toString body.used} bytes";

    limit =
      body:
      let
        head = lib.optionalString ((body.inv or null) == true) "over ";
        rateUnit = lib.optionalString ((body.rate_unit or null) != null) " ${body.rate_unit}";
        burst =
          if (body.burst or null) == null then
            ""
          else
            let
              u = if (body.burst_unit or null) != null then body.burst_unit else "packets";
            in
            " burst ${toString body.burst} ${u}";
      in
      "rate ${head}${toString body.rate}${rateUnit}/${body.per}${burst}";

    synproxy =
      body:
      let
        flags =
          if (body.flags or null) == null then "" else " " + primitives.flags { sep = " "; } body.flags;
      in
      "mss ${toString body.mss} wscale ${toString body.wscale}${flags}";
  };

  # `create` dispatcher: use positional body for quota/limit/synproxy,
  # full brace body for other kinds.
  renderCreate =
    ctx: wrapped:
    let
      names = builtins.attrNames wrapped;
    in
    if builtins.length names != 1 then
      throw "text.commands: create expects exactly one inner kind, got [${lib.concatStringsSep ", " names}]"
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
        "create ${headerRendering} ${positional}"
      else
        # Brace-body kinds (set/map/flowtable/ct-*/secmark/tunnel/...);
        # `add`-style rendering works.
        "create ${renderObject ctx kind body}";

  verbRenderers = {
    add = prefixed renderObject "add";
    replace = prefixed renderObject "replace";
    insert = prefixed renderObject "insert";
    create = renderCreate;
    delete = prefixed renderObjectHeader "delete";
    destroy = prefixed renderObjectHeader "destroy";
    list = prefixed renderObjectHeader "list";
    reset = prefixed renderObjectHeader "reset";
    flush = prefixed renderObjectHeader "flush";
    rename = renderRename;
  };

  # Render a top-level command. Accepts either a tagged command
  # `{ verb: { kind: body } }` or a bare list-object form
  # `{ kind: body }` (used in `nft -j list` output).
  renderCommand =
    ctx: cmd:
    if !(builtins.isAttrs cmd) then
      throw "text.commands: command must be an attrset, got ${builtins.typeOf cmd}"
    else
      let
        names = builtins.attrNames cmd;
      in
      if builtins.length names != 1 then
        throw "text.commands: command must have exactly one tag, got [${lib.concatStringsSep ", " names}]"
      else
        let
          tag = builtins.head names;
        in
        if verbRenderers ? ${tag} then
          verbRenderers.${tag} ctx cmd.${tag}
        else
          # Bare list-object (no verb). Render as the object itself —
          # body is meaningful here (this is the form `nft -j list` emits).
          renderObject ctx tag cmd.${tag};
in
{
  inherit renderCommand;
}
