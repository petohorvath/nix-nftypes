/*
  Match operators. Each returns a match statement
  (`{ match = { left; right; op; }; }`), validated when called as every
  statement builder's is (./internal/builder.nix), and top-level names
  read naturally: `eq tcp.dport 22`.

  `inSet` / `notInSet` wrap a list right-hand side as `{ set = [...]; }` and
  pass a named-set reference (`"@name"`) through unchanged. `hasAnyFlag`
  is the nftables `in` operator, which tests flag bits.
*/
{ lib, statement }:

let
  location = import ./internal/location.nix { inherit lib; };

  # The match statement `left <op> right` of the operator `dsl.<name>`.
  mkMatch =
    name: op: left: right:
    statement.tagged {
      inherit name;
      tag = "match";
    } { inherit op left right; };

  /*
    Wrap a right-hand side for set membership: list → anonymous set
    expression; anything else ("@name" references, pre-built set
    expressions, flag values, …) passes through. A string without `@` would
    be matched as one value, such as a hostname, so it throws; `name`
    names the operator in the error.
  */
  wrapSet =
    name: rhs:
    if builtins.isList rhs then
      { set = rhs; }
    else if builtins.isString rhs && !(lib.hasPrefix "@" rhs) then
      location.fail (location.builder [ name ])
        "the right side ${builtins.toJSON rhs} is a bare string, which nft matches as one value, not as a set; reference a named set with `expr.setRef ${builtins.toJSON rhs}` (or \"@${rhs}\")"
    else
      rhs;

  /*
    Match `left == right`. `left` is the expression under test and `right`
    the value to compare against. Returns a match statement, and throws
    when it doesn't validate.
  */
  eq = mkMatch "eq" "==";

  /*
    Match `left != right`. `left` is the expression under test and `right`
    the value to compare against. Returns a match statement, and throws
    when it doesn't validate.
  */
  ne = mkMatch "ne" "!=";

  /*
    Match `left < right`. `left` is the expression under test and `right`
    the value to compare against. Returns a match statement, and throws
    when it doesn't validate.
  */
  lt = mkMatch "lt" "<";

  /*
    Match `left > right`. `left` is the expression under test and `right`
    the value to compare against. Returns a match statement, and throws
    when it doesn't validate.
  */
  gt = mkMatch "gt" ">";

  /*
    Match `left <= right`. `left` is the expression under test and `right`
    the value to compare against. Returns a match statement, and throws
    when it doesn't validate.
  */
  le = mkMatch "le" "<=";

  /*
    Match `left >= right`. `left` is the expression under test and `right`
    the value to compare against. Returns a match statement, and throws
    when it doesn't validate.
  */
  ge = mkMatch "ge" ">=";

  /*
    Match membership without spelling out the set wrapper. `left` is the
    expression under test; `right` is a list (wrapped as an anonymous set)
    or any other set expression, such as `"@name"`. Returns a match
    statement, and throws when it doesn't validate or `right` is a string
    without `@`.
  */
  inSet = left: right: mkMatch "inSet" "==" left (wrapSet "inSet" right);

  /*
    Negated `inSet`. `left` is the expression under test; `right` is a list
    or other set expression, as for `inSet`. Returns a match statement, and
    throws as `inSet` does.
  */
  notInSet = left: right: mkMatch "notInSet" "!=" left (wrapSet "notInSet" right);

  /*
    Match when any of `flags` is set in `left`, with the nftables `in`
    operator: nft tests `(left & flags) != 0`. `left` is the expression
    under test, such as `tcp.flags`, and `flags` a flag value or a list of
    them. Returns a match statement, and throws when it doesn't validate.
  */
  hasAnyFlag = mkMatch "hasAnyFlag" "in";
in
{
  inherit
    eq
    ge
    gt
    hasAnyFlag
    inSet
    le
    lt
    ne
    notInSet
    ;
}
