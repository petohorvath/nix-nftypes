/*
  Match operators. Each returns a match statement
  (`{ match = { left; right; op; }; }`), validated when called as every
  statement builder's is (./internal/builder.nix), and top-level names
  read naturally: `eq tcp.dport 22`.

  `inSet` / `notInSet` wrap a list right-hand side as `{ set = [...]; }` and
  pass a named-set reference (`"@name"`) through unchanged. `hasAnyFlag`
  is the nftables `in` operator, which tests flag bits.
*/
{
  isMatchKey,
  lib,
  statement,
}:

let
  location = import ./internal/location.nix { inherit lib; };
  reference = import ./internal/reference.nix { inherit lib; };

  /*
    The match statement `left <op> right` of the operator `dsl.<name>`.
    nft takes a key, such as a Field leaf, on the left only, so a value
    on the left with a key on the right throws, asking to swap them.
  */
  mkMatch =
    name: op: left: right:
    if isMatchKey right && !(isMatchKey left) then
      location.fail (location.builder [ name ])
        "the right side is a key, such as a Field leaf, and the left side is not; nft takes the key on the left, so swap the sides, as in `${name} fields.tcp.dport 22`"
    else
      statement.tagged {
        inherit name;
        tag = "match";
      } { inherit op left right; };

  # Whether `right` is a set: an anonymous set or a named set's `@name`.
  isSet =
    right:
    builtins.isAttrs right && builtins.attrNames right == [ "set" ]
    || builtins.isString right && lib.hasPrefix "@" right;

  /*
    The comparison operator `dsl.<name>`. A list on its right is nft's
    flag combination, not a set: nft rejects it for a non-flag field and
    compares a flag field with every flag at once, so
    `eq ct.state [ "established" "related" ]` never matches. It throws
    instead, naming the operator that says what the caller means. A set
    on its right is membership, which `inSet` or `notInSet` names, so it
    throws too and points there; `member` names that operator, or is
    null for an ordering comparison, which nft refuses with a set.
  */
  mkComparison =
    name: member: op: left: right:
    if builtins.isList right then
      location.fail (location.builder [ name ])
        "the right side is a list, which nft reads as one combination of flags, not as a set of values; match any of the values with `inSet`, any of the flags with `hasAnyFlag`, or the exact combination of flags with `expr.bitOr`"
    else if member != null && isSet right then
      location.fail (location.builder [ name ])
        "the right side is a set, which makes the match a membership test; write `${member}`, which takes a list, a set expression, or a named set's \"@name\""
    else
      mkMatch name op left right;

  /*
    Wrap a right-hand side for set membership: list → anonymous set
    expression; a set expression or a `"@name"` reference passes through.
    A string without `@` would be matched as one value, such as a
    hostname, so it throws, as does an empty list, which nft rejects, and
    any other value, which `comparison`, `eq` or `ne`, matches; `name`
    names the operator in the error.
  */
  wrapSet =
    name: comparison: rhs:
    if rhs == [ ] then
      reference.failEmptyList (location.builder [ name ]) "the right side"
    else if builtins.isList rhs then
      { set = rhs; }
    else if builtins.isString rhs && !(lib.hasPrefix "@" rhs) then
      location.fail (location.builder [ name ])
        "the right side ${builtins.toJSON rhs} is a bare string, which nft matches as one value, not as a set; reference a named set with `expr.setRef ${builtins.toJSON rhs}` (or \"@${rhs}\")"
    else if !(isSet rhs) then
      location.fail (location.builder [ name ])
        "the right side is one value, not a set; compare with it using `${comparison}`, or give a list, a set expression, or a named set's \"@name\""
    else
      rhs;

  /*
    Match `left == right`. `left` is the expression under test and `right`
    the value to compare against. Returns a match statement, and throws
    when it doesn't validate or `right` is a list.
  */
  eq = mkComparison "eq" "inSet" "==";

  /*
    Match `left != right`. `left` is the expression under test and `right`
    the value to compare against. Returns a match statement, and throws
    when it doesn't validate or `right` is a list.
  */
  ne = mkComparison "ne" "notInSet" "!=";

  /*
    Match `left < right`. `left` is the expression under test and `right`
    the value to compare against. Returns a match statement, and throws
    when it doesn't validate or `right` is a list.
  */
  lt = mkComparison "lt" null "<";

  /*
    Match `left > right`. `left` is the expression under test and `right`
    the value to compare against. Returns a match statement, and throws
    when it doesn't validate or `right` is a list.
  */
  gt = mkComparison "gt" null ">";

  /*
    Match `left <= right`. `left` is the expression under test and `right`
    the value to compare against. Returns a match statement, and throws
    when it doesn't validate or `right` is a list.
  */
  le = mkComparison "le" null "<=";

  /*
    Match `left >= right`. `left` is the expression under test and `right`
    the value to compare against. Returns a match statement, and throws
    when it doesn't validate or `right` is a list.
  */
  ge = mkComparison "ge" null ">=";

  /*
    Match membership without spelling out the set wrapper. `left` is the
    expression under test; `right` is a list (wrapped as an anonymous set)
    or any other set expression, such as `"@name"`. Returns a match
    statement, and throws when it doesn't validate or `right` is a string
    without `@`.
  */
  inSet = left: right: mkMatch "inSet" "==" left (wrapSet "inSet" "eq" right);

  /*
    Negated `inSet`. `left` is the expression under test; `right` is a list
    or other set expression, as for `inSet`. Returns a match statement, and
    throws as `inSet` does.
  */
  notInSet = left: right: mkMatch "notInSet" "!=" left (wrapSet "notInSet" "ne" right);

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
