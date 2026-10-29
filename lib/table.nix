/*
  One table tree, two renderings: `expandTable` turns a Table tree into
  imperative commands, and `toTextBlock` / `toTextBlockPretty` render it in
  block form. Preparation keeps validated rules with their chains; only
  command expansion flattens them. The prepared shape is private to this
  module, so block rendering never has to recover ownership from commands or
  pass rules through the text renderer's formatting context.
*/
{
  compatibility,
  lib,
  objects,
  text,
}:

let
  validate = import ./dsl/internal/validate.nix { inherit lib; };
  requireBody = import ./dsl/internal/require-body.nix { inherit lib; };
  location = import ./dsl/internal/location.nix { inherit lib; };
  ruleBody = import ./dsl/internal/rule-body.nix { inherit lib; };
  compact = import ./dsl/internal/compact.nix { inherit lib; };
  rejectHandle = import ./dsl/internal/reject-handle.nix { inherit lib; };
  chainPriority = import ./dsl/internal/chain-priority.nix { inherit compatibility lib; };
  tableTreeMarker = import ./table-tree-marker.nix { };
  fail = import ./fail.nix { };
  inherit (import ./describe.nix { inherit lib; }) describe;
  objectKindRegistry = import ./dsl/structure/object-kinds.nix { inherit lib objects; };
  objectKinds = lib.mapAttrs' (
    _: cfg: lib.nameValuePair cfg.plural (removeAttrs cfg [ "plural" ])
  ) objectKindRegistry;

  # Attribute names are sorted.
  sortedNames = builtins.attrNames;

  # Stateful objects come first: a set or map element can name one (a map
  # of quotas, say), and JSON and imperative text load commands in order.
  # The other kinds keep their sorted order.
  statefulObjectKindNames = [
    "counters"
    "quotas"
    "limits"
    "ctHelpers"
    "ctTimeouts"
    "ctExpectations"
    "secmarks"
    "synproxies"
    "ctCounts"
  ];
  orderedObjectKindNames =
    statefulObjectKindNames ++ lib.subtractLists statefulObjectKindNames (sortedNames objectKinds);

  # Each Table-tree key holding named entries, by its singular name.
  treeKeysBySingular = lib.mapAttrs (_: cfg: cfg.plural) objectKindRegistry // {
    chain = "chains";
  };

  # The tree owns scope. Check after schema validation so ordinary type
  # errors keep their existing paths, and matching explicit scope fields
  # remain useful when composing bodies. Raw commands can choose any scope.
  # A tree's bodies take no handle, as `add` bodies take none.
  prepareBody =
    type: at: scope: userBody:
    let
      validated = compact (validate {
        inherit type;
        location = at;
        value = compact (scope // rejectHandle at (requireBody at userBody));
      });
      conflicts = builtins.filter (key: validated.${key} != scope.${key}) (sortedNames scope);
      key = builtins.head conflicts;
    in
    if conflicts == [ ] then
      validated
    else
      location.fail (location.within at [ key ])
        "must match its table-tree scope ${builtins.toJSON scope.${key}}, got ${
          builtins.toJSON validated.${key}
        }";

  # Preparation lists the names in `chains` or in one kind's named objects,
  # and the indexes in a chain's `rules`, before it checks any entry, so a
  # wrongly shaped value fails here, at its path `at`, instead of as a bare
  # Nix type error.
  requireShape =
    isShape: expected: at: value:
    if isShape value then
      value
    else
      location.fail at "expected ${expected}, got a ${builtins.typeOf value}";

  requireNamedBodies = noun: requireShape builtins.isAttrs "an attribute set of ${noun} bodies";

  /*
    `tree` is the table tree's location (../dsl/internal/location.nix). An
    object's key declares it, so it is the bare name: a key such as
    `sets."@s"` would declare a set no Reference could name without
    ambiguity (ADR 0009).
  */
  prepareObject =
    tree: scope: pluralKey: name: userBody:
    let
      cfg = objectKinds.${pluralKey};
      at = location.within tree [
        pluralKey
        name
      ];
      body = prepareBody cfg.body at (scope // { inherit name; }) (cfg.renameBody at userBody);
    in
    if lib.hasPrefix "@" name then
      location.fail at "a Table tree declares an object by its bare name; drop the leading `@`, which only a Reference adds"
    else
      {
        kind = cfg.tag;
        inherit body;
      };

  # A rule entry is a list of statements or a rule body with them in
  # `statements` (./dsl/internal/rule-body.nix).
  prepareRule =
    tree: scope: index: entry:
    let
      at = location.within tree [
        "chains"
        scope.chain
        "rules"
        (toString index)
      ];
    in
    prepareBody objects.addRuleBody at scope (ruleBody.ruleEntry at entry);

  prepareChain =
    tree: scope: name: userBody:
    let
      at = location.within tree [
        "chains"
        name
      ];
      checkedBody = requireBody at userBody;
      rules = requireShape builtins.isList "a list of rules" (location.within at [ "rules" ]) (
        checkedBody.rules or [ ]
      );
    in
    {
      # The tree's family resolves a Symbolic priority; a conflicting
      # `family` in the body still throws in `prepareBody`.
      body = prepareBody objects.chainBody at (scope // { inherit name; }) (
        chainPriority at scope.family (removeAttrs checkedBody [ "rules" ])
      );
      rules = lib.imap0 (prepareRule tree (scope // { chain = name; })) rules;
    };

  prepareTable =
    value:
    let
      inherit (value) family name;
      tree = location.tableTree family name;
      body = rejectHandle tree (
        removeAttrs value [
          "_type"
          "family"
          "name"
        ]
      );
      allowedBodyKeys = [
        "flags"
        "comment"
        "chains"
      ]
      ++ sortedNames objectKinds;
      unknownBodyKeys = lib.subtractLists allowedBodyKeys (sortedNames body);
      # A singular kind name, such as `set`, is a misspelled plural key.
      misspelledPlurals = builtins.filter (key: treeKeysBySingular ? ${key}) unknownBodyKeys;
      checkedBody =
        if unknownBodyKeys == [ ] then
          body
        else
          location.fail tree (
            "unsupported key(s): ${lib.concatStringsSep ", " unknownBodyKeys}; a Table tree takes ${lib.concatStringsSep ", " allowedBodyKeys}"
            +
              lib.optionalString (misspelledPlurals != [ ])
                "; write ${
                  lib.concatMapStringsSep " and " (
                    key: "`${treeKeysBySingular.${key}}` for `${key}`"
                  ) misspelledPlurals
                }"
            + lib.optionalString (builtins.elem "elements" unknownBodyKeys) "; give a set or map its elements in its body, as `sets.<name>.elements` or `maps.<name>.elements`, or add them to a set defined elsewhere with `add.element`"
          );
      tableOptions = builtins.intersectAttrs {
        flags = null;
        comment = null;
      } checkedBody;
      scope = {
        inherit family;
        table = name;
      };
      chains = requireNamedBodies "chain" (location.within tree [ "chains" ]) (checkedBody.chains or { });
      presentKinds = builtins.filter (kind: checkedBody ? ${kind}) orderedObjectKindNames;
      objectsOfKind =
        kind:
        requireNamedBodies objectKinds.${kind}.tag (location.within tree [ kind ]) checkedBody.${kind};
    in
    {
      body = prepareBody objects.tableBody tree { inherit family name; } tableOptions;
      chains = map (name: prepareChain tree scope name chains.${name}) (sortedNames chains);
      objects = lib.concatMap (
        kind:
        let
          bodiesByName = objectsOfKind kind;
        in
        map (name: prepareObject tree scope kind name bodiesByName.${name}) (sortedNames bodiesByName)
      ) presentKinds;
    };

  # Declare all chains before objects (verdict maps can reference chains),
  # then objects before rules (rules can reference both). Rules keep source
  # order within each chain. Dependencies inside raw bodies are caller-owned.
  expandTable =
    tree:
    let
      table = prepareTable tree;
      add = kind: body: { add.${kind} = body; };
    in
    [ (add "table" table.body) ]
    ++ map (chain: add "chain" chain.body) table.chains
    ++ map (object: add object.kind object.body) table.objects
    ++ lib.concatMap (chain: map (add "rule") chain.rules) table.chains;

  /*
    Render one Table tree's contents in block form. `api` names the
    renderer in errors, `pretty` selects multi-line output, and `tree` is
    the Table tree. Returns the table's `flags` and `comment`, then the
    chain and object declarations, each ending with a newline, without the
    `table <family> <name> { … }` wrapper. Throws when `tree` is not a
    Table tree, saying what it got; text refuses what block grammar cannot
    spell.
  */
  renderTableBlock =
    api: pretty:
    let
      # Bound before `tree`, so each renderer builds its text modules once.
      render = text.renderTableBlock api pretty;
    in
    tree:
    if !(tableTreeMarker.isTableTree tree) then
      fail api "expected one Table tree from `dsl.table`, got ${describe tree}; render a ruleset with `toText`"
    else
      let
        table = prepareTable tree;
      in
      # Validate even an empty table's omitted wrapper fields. Construction
      # stays lazy; validation is forced when the rendered string is needed.
      builtins.deepSeq table.body (render table);
in
{
  inherit expandTable;

  /*
    Render a Table tree for a host module that supplies the
    `table <family> <name> { … }` wrapper itself, such as nixpkgs'
    `networking.nftables.tables.<name>.content`. Takes the Table tree and
    returns compact block-form text; see `renderTableBlock` for failures.
  */
  toTextBlock = renderTableBlock "toTextBlock" false;

  /*
    Multi-line variant of `toTextBlock`, for readable generated
    configuration. Takes the Table tree and returns block-form text with
    each statement on its own indented line; see `renderTableBlock` for
    failures.
  */
  toTextBlockPretty = renderTableBlock "toTextBlockPretty" true;
}
