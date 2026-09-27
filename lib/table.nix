{
  lib,
  objects,
  clean,
  text,
}:

# One table tree, two renderings. Preparation keeps validated rules with
# their chains; only command expansion flattens them. The prepared shape is
# private to this module, so block rendering never has to recover ownership
# from commands or pass rules through the text renderer's formatting context.
let
  validate = import ./dsl/internal/validate.nix { inherit lib; };
  compact = import ./dsl/internal/compact.nix { inherit lib; };
  markers = import ./dsl/internal/markers.nix { };
  nftSafeIfname = import ./nft-safe-ifname.nix { };
  context = import ./text/context.nix { inherit lib; };
  objectKindRegistry = import ./dsl/structure/object-kinds.nix { inherit lib objects; };
  objectKinds = lib.mapAttrs' (
    _: cfg: lib.nameValuePair cfg.plural (removeAttrs cfg [ "plural" ])
  ) objectKindRegistry;

  # Attribute names are sorted. Standalone elements are the one exception
  # to kind order: their set/map definitions must already exist.
  sortedNames = builtins.attrNames;
  orderedObjectKindNames =
    builtins.filter (name: name != "elements") (sortedNames objectKinds)
    ++ lib.optional (objectKinds ? elements) "elements";

  # The tree owns scope. Check after schema validation so ordinary type
  # errors keep their existing paths, and matching explicit scope fields
  # remain useful when composing bodies. Raw commands can choose any scope.
  prepareBody =
    type: prefix: scope: userBody:
    let
      validated = compact (validate {
        inherit type prefix;
        value = compact (scope // userBody);
      });
      conflicts = builtins.filter (key: validated.${key} != scope.${key}) (sortedNames scope);
      key = builtins.head conflicts;
      path = lib.concatStringsSep "." (prefix ++ [ key ]);
    in
    if conflicts == [ ] then
      validated
    else
      throw "nix-nft-types: ${path} must match its table-tree scope ${builtins.toJSON scope.${key}}, got ${
        builtins.toJSON validated.${key}
      }";

  prepareObject =
    scope: pluralKey: name: userBody:
    let
      cfg = objectKinds.${pluralKey};
      body = prepareBody cfg.body [ pluralKey name ] (scope // { inherit name; }) (
        cfg.renameBody userBody
      );
      # Cross-field validation supplements the schema: ifname set/map
      # elements render bare, so unsafe characters can widen a set or break
      # the parser. The text object renderer also checks raw callers.
      bad = if cfg.tag == "set" || cfg.tag == "map" then nftSafeIfname.badIfnameElement body else null;
    in
    {
      kind = cfg.tag;
      body =
        if bad == null then
          body
        else
          throw "${pluralKey}.${name}: set has type = \"ifname\" but element ${builtins.toJSON bad} is not a safe interface name (see lib/nft-safe-ifname.nix). nft renders ifname elements bare into `elements = { ... }`, so unsafe characters can silently widen the set or break the text parser.\n";
    };

  prepareRule =
    scope: idx: entry:
    prepareBody objects.ruleBody [ "chains" scope.chain "rules" (toString idx) ] scope (
      if builtins.isList entry then { expr = entry; } else entry
    );

  prepareChain = scope: name: userBody: {
    body = prepareBody objects.chainBody [ "chains" name ] (scope // { inherit name; }) (
      removeAttrs userBody [ "rules" ]
    );
    rules = lib.imap0 (prepareRule (scope // { chain = name; })) (userBody.rules or [ ]);
  };

  prepareTable =
    node:
    let
      inherit (node) family name;
      body = removeAttrs node [
        markers.table
        "family"
        "name"
      ];
      allowedBodyKeys = [
        "_type"
        "handle"
        "flags"
        "comment"
        "chains"
      ]
      ++ sortedNames objectKinds;
      unknownBodyKeys = lib.subtractLists allowedBodyKeys (sortedNames body);
      checkedBody =
        if unknownBodyKeys == [ ] then
          body
        else
          throw (
            "nix-nft-types: dsl.table ${family}.${name} has unsupported key(s): "
            + lib.concatStringsSep ", " unknownBodyKeys
          );
      tableOpts = builtins.intersectAttrs {
        handle = null;
        flags = null;
        comment = null;
      } checkedBody;
      scope = {
        inherit family;
        table = name;
      };
      chains = checkedBody.chains or { };
      presentKinds = builtins.filter (kind: checkedBody ? ${kind}) orderedObjectKindNames;
    in
    {
      body = prepareBody objects.tableBody [ ] { inherit family name; } tableOpts;
      chains = map (name: prepareChain scope name chains.${name}) (sortedNames chains);
      objects = lib.concatMap (
        kind:
        map (name: prepareObject scope kind name checkedBody.${kind}.${name}) (
          sortedNames checkedBody.${kind}
        )
      ) presentKinds;
    };

  # Declare all chains before objects (verdict maps can reference chains),
  # then objects before rules (rules can reference both). Rules keep source
  # order within each chain. Dependencies inside raw bodies are caller-owned.
  expandTable =
    node:
    let
      table = prepareTable node;
      add = kind: body: { add.${kind} = body; };
    in
    [ (add "table" table.body) ]
    ++ map (chain: add "chain" chain.body) table.chains
    ++ map (object: add object.kind object.body) table.objects
    ++ lib.concatMap (chain: map (add "rule") chain.rules) table.chains;

  renderTableBlock =
    pretty: node:
    if !(builtins.isAttrs node && (node.${markers.table} or false)) then
      throw "nix-nft-types: block-form text rendering expects one dsl.table node"
    else if
      node ? elements && !(builtins.isAttrs node.elements && sortedNames node.elements == [ ])
    then
      throw "nix-nft-types: block-form text rendering cannot embed standalone table elements; put initial elements on the set/map definition or use an imperative renderer"
    else
      let
        table = clean (prepareTable node);
        ctx = context.mkCtx {
          inherit pretty;
          block = true;
        };
        declarations =
          map (chain: text.renderChainBlock ctx chain.body chain.rules) table.chains
          ++ map (object: text.renderObject ctx object.kind object.body) table.objects;
      in
      # Validate even an empty table's omitted wrapper fields. Construction
      # stays lazy; validation is forced when the rendered string is needed.
      builtins.deepSeq table.body (lib.concatStringsSep "\n" declarations);
in
{
  inherit expandTable;
  toTextBlock = renderTableBlock false;
  toTextBlockPretty = renderTableBlock true;
}
