# The reach check's two halves: what a ruleset reaches, and the verdict on
# the schema's names. ../suites/reach.nix applies them to the Integration
# cases, with the exceptions in ../fixtures/reach.nix.
{ lib }:
let
  oneKey = value: builtins.isAttrs value && builtins.length (builtins.attrNames value) == 1;
  keyOf = value: builtins.head (builtins.attrNames value);
  found = category: name: [ { inherit category name; } ];

  /*
    The walk over a ruleset as `nftlib.toJson` writes it. Statements sit
    in a rule's `expr` and in any `stmt` field (meter, set and map
    statements, set objects, elements). Below a statement, a one-key
    attrset keyed by an expression tag is that expression; any other
    attrset is a body whose fields are walked in turn.
  */
  walker =
    expressionTags:
    let
      isExpressionTag = tag: builtins.elem tag expressionTags;

      fields =
        body:
        lib.concatLists (
          lib.mapAttrsToList (
            name: value: if name == "stmt" then statements value else expressions value
          ) body
        );

      expressions =
        value:
        if builtins.isList value then
          lib.concatMap expressions value
        else if oneKey value && isExpressionTag (keyOf value) then
          found "expressions" (keyOf value) ++ expressionBody value.${keyOf value}
        else if builtins.isAttrs value then
          fields value
        else
          [ ];

      expressionBody =
        body:
        if builtins.isList body then
          lib.concatMap expressions body
        else if builtins.isAttrs body then
          fields body
        else
          [ ];

      # A stateful statement can take an expression as its whole body
      # (`counter = { map = …; }`). A one-key body with a string value is
      # a field instead, such as log's `{ prefix = "…"; }`.
      statementBody =
        body:
        if oneKey body && isExpressionTag (keyOf body) && !builtins.isString body.${keyOf body} then
          expressions body
        else
          expressionBody body;

      statements = value: lib.concatMap statement (lib.toList value);

      statement =
        value:
        lib.concatLists (
          lib.mapAttrsToList (tag: body: found "statements" tag ++ statementBody body) value
        );

      objectBody =
        kind: body:
        if kind == "rule" && builtins.isAttrs body then
          fields (removeAttrs body [ "expr" ]) ++ statements (body.expr or [ ])
        else
          expressionBody body;

      commands =
        value:
        lib.concatLists (
          lib.mapAttrsToList (
            verb: objects:
            lib.concatLists (
              lib.mapAttrsToList (kind: body: found "commands" "${verb} ${kind}" ++ objectBody kind body) objects
            )
          ) value
        );
    in
    ruleset: lib.concatMap commands ruleset.nftables;
in
{
  /*
    What `ruleset`, a value as `nftlib.toJson` writes it, reaches:
    `{ statements; expressions; commands; }`, each a sorted list of the
    statement tags, the expression tags out of `expressionTags`, and the
    command/object pairs (`"<verb> <kind>"`, such as `"add rule"`) it
    contains.
  */
  reachedBy =
    expressionTags: ruleset:
    let
      reached = walker expressionTags ruleset;
      namesOf =
        category:
        lib.pipe reached [
          (builtins.filter (entry: entry.category == category))
          (map (entry: entry.name))
          lib.unique
          (lib.sort lib.lessThan)
        ];
    in
    {
      statements = namesOf "statements";
      expressions = namesOf "expressions";
      commands = namesOf "commands";
    };

  /*
    The reach check's verdict for one `category` (a label such as
    "statement"): a message for each name in `inventory`, the schema's
    names, that is not `reached` and has neither a `pending` entry (name →
    the open ticket under #24 that adds its case) nor a Named exclusion in
    `knownDifferences` (name → its Known difference), and for each entry
    that is stale or malformed. Returns `[ ]` when the check passes.
  */
  problems =
    {
      category,
      inventory,
      reached,
      pending,
      knownDifferences,
    }:
    let
      fixture = "tests/fixtures/reach.nix";
      subject = name: "${category} ${builtins.toJSON name}";
      isReached = name: builtins.elem name reached;
      isAccepted = name: builtins.elem name inventory;
      isTicket = ticket: lib.isInt ticket && ticket > 24 && ticket <= 53;

      uncovered = lib.pipe inventory [
        (builtins.filter (name: !(isReached name || pending ? ${name} || knownDifferences ? ${name})))
        (map (
          name:
          "${subject name} is in no Integration case, so it never reaches nft: add a case that uses it to tests/fixtures/integration-cases.nix"
        ))
      ];

      entryProblems =
        kind: entries: describe: check:
        lib.concatLists (
          lib.mapAttrsToList (
            name: value:
            if !(isAccepted name) then
              [
                "${subject name} has ${kind}, but the schema doesn't accept it: delete the entry from ${fixture}"
              ]
            else if isReached name then
              [ "${subject name} is in an Integration case now: delete its ${describe value} from ${fixture}" ]
            else
              check name value
          ) entries
        );

      pendingProblems =
        entryProblems "a pending entry" pending (ticket: "pending entry (#${toString ticket})")
          (
            name: ticket:
            lib.optional (
              !(isTicket ticket)
            ) "${subject name} has a pending entry naming #${toString ticket}, not an open ticket under #24"
          );

      exclusionProblems = entryProblems "a Named exclusion" knownDifferences (_: "Named exclusion") (
        name: reason:
        lib.optional (!(builtins.isString reason && reason != ""))
          "${subject name} has a Named exclusion with no Known difference: give the reason nft can't load it"
      );

      doubled = lib.pipe pending [
        builtins.attrNames
        (builtins.filter (name: knownDifferences ? ${name}))
        (map (name: "${subject name} is both pending and a Named exclusion: keep one in ${fixture}"))
      ];
    in
    uncovered ++ pendingProblems ++ exclusionProblems ++ doubled;
}
