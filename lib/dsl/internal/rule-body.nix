/*
  Check a DSL rule's statements before anything validates or renders it,
  and rename its `statements` to the JSON `expr` (./rename.nix). A rule
  body without a non-empty `statements` list renders a rule with no
  statement, and a bare statement such as `dsl.drop` loses its null body to
  `compact`, so each throws, naming the rule's path and showing the list
  form. So does `expr`, the JSON spelling.

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
  inherit (import ./location.nix { inherit lib; }) fail;

  check =
    {
      expected,
      example,
    }:
    location: body:
    let
      malformed =
        got:
        fail location "expected ${expected}, got ${got}; write one statement as a list, such as ${example}";
      checked = rename.checkSpelling.rule location body;
    in
    if !(builtins.isAttrs checked) then
      malformed "a ${builtins.typeOf body}"
    else if !(checked ? statements && checked.statements != null) then
      malformed "an attribute set without `statements`, such as a bare statement"
    else if checked.statements == [ ] then
      malformed "a rule with no statements"
    else
      rename.rule location (requireBody location checked);
in
{
  ruleEntry =
    location: entry:
    check {
      expected = "a list of statements or a rule body with them in `statements`";
      example = "[ dsl.drop ]";
    } location (if builtins.isList entry then { statements = entry; } else entry);

  ruleBody = check {
    expected = "a rule body with a list of statements in `statements`";
    example = "statements = [ dsl.drop ]";
  };
}
