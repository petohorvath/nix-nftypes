/*
  Check that a DSL rule has statements before anything validates or
  renders it. A rule body without a non-empty `expr` list renders a rule
  with no statement, and a bare statement such as `dsl.drop` loses its
  null body to `compact`, so each throws, naming the rule's path and
  showing the list form.

  - `ruleEntry location entry`: a table tree's rule entry, a list of
    statements or a rule body. Returns the rule body.
  - `ruleBody location body`: a rule command's body. Returns `body`.

  `location` is the rule's location (./location.nix), such as a table
  tree's `chains.input.rules.0`.
*/
{ lib }:

let
  requireBody = import ./require-body.nix { inherit lib; };
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
    in
    if !(builtins.isAttrs body) then
      malformed "a ${builtins.typeOf body}"
    else if !(body ? expr && body.expr != null) then
      malformed "an attribute set without `expr`, such as a bare statement"
    else if body.expr == [ ] then
      malformed "a rule with no statements"
    else
      requireBody location body;
in
{
  ruleEntry =
    location: entry:
    check {
      expected = "a list of statements or a rule body with them in `expr`";
      example = "[ dsl.drop ]";
    } location (if builtins.isList entry then { expr = entry; } else entry);

  ruleBody = check {
    expected = "a rule body with a list of statements in `expr`";
    example = "expr = [ dsl.drop ]";
  };
}
