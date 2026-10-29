/*
  Check a DSL rule's statements before anything validates or renders it,
  and rename its `statements` to the JSON `expr` (./rename.nix). A rule
  body without a non-empty `statements` list renders a rule with no
  statement, and a bare statement such as `dsl.drop` loses its null body to
  `compact`, so each throws, naming the rule's path and showing the list
  form. So does `expr`, the JSON spelling, and a builder left uncalled
  among the statements, such as a bare `dsl.last`.

  - `ruleEntry location entry`: a table tree's rule entry, a list of
    statements or a rule body. Returns the JSON rule body.
  - `ruleBody location body`: a rule command's body. Returns the JSON rule
    body.

  `location` is the rule's location (./location.nix), such as a table
  tree's `chains.input.rules.0`.
*/
{ lib }:

let
  requireBody = import ./require-body.nix { inherit lib; };
  rename = import ./rename.nix { inherit lib; };
  inherit (import ./location.nix { inherit lib; }) fail within;

  /*
    A builder left uncalled, such as the bare `dsl.last` that was a
    statement in 0.1.0, would fail the schema as a bare `<function>`. A
    Variant namespace whose null form is `.auto` names its tag there, so
    the error can point to it.
  */
  checkStatement =
    location: statement:
    let
      auto = statement.auto or null;
      autoTags = if builtins.isAttrs auto then builtins.attrNames auto else [ ];
    in
    if builtins.isAttrs statement && statement ? __functor && builtins.length autoTags == 1 then
      let
        tag = builtins.head autoTags;
      in
      fail location "expected a statement, got the Variant namespace `${tag}`; write `${tag}.auto` for its null form, or call it with a body"
    else if builtins.isFunction statement || builtins.isAttrs statement && statement ? __functor then
      fail location "expected a statement, got a function, such as a builder not yet called; call it to build the statement"
    else
      statement;

  # `statementPath` is the path from the rule's location to its statement
  # list, as the caller wrote it.
  check =
    {
      expected,
      example,
      statementPath,
    }:
    location: body:
    let
      malformed =
        got:
        fail location "expected ${expected}, got ${got}; write one statement as a list, such as ${example}";
      checked = rename.checkSpelling.rule location body;
      checkStatements =
        statements:
        if builtins.isList statements then
          lib.imap0 (
            index: checkStatement (within location (statementPath ++ [ (toString index) ]))
          ) statements
        else
          statements;
    in
    if !(builtins.isAttrs checked) then
      malformed "a ${builtins.typeOf body}"
    else if !(checked ? statements && checked.statements != null) then
      malformed "an attribute set without `statements`, such as a bare statement"
    else if checked.statements == [ ] then
      malformed "a rule with no statements"
    else
      rename.rule location (
        requireBody location (checked // { statements = checkStatements checked.statements; })
      );
in
{
  ruleEntry =
    location: entry:
    check {
      expected = "a list of statements or a rule body with them in `statements`";
      example = "[ dsl.drop ]";
      statementPath = lib.optional (!builtins.isList entry) "statements";
    } location (if builtins.isList entry then { statements = entry; } else entry);

  ruleBody = check {
    expected = "a rule body with a list of statements in `statements`";
    example = "statements = [ dsl.drop ]";
    statementPath = [ "statements" ];
  };
}
