/*
  Match operators. Each returns a statement
  (`{ match = { left; right; op; }; }`), and top-level names read
  naturally: `eq tcp.dport 22`.

  `inSet` / `notInSet` wrap a list right-hand side as `{ set = [...]; }` and
  pass a string (typically `"@name"`) through unchanged. For the nftables `in`
  operator (bitwise flag testing), use `match.in_`.
*/
{ lib }:

let
  mkMatch = op: left: right: { match = { inherit op left right; }; };

  # Wrap a right-hand side for set membership: list → anonymous set
  # expression; anything else ("@name" references, pre-built set expressions,
  # flag values, …) passes through.
  wrapSet = rhs: if builtins.isList rhs then { set = rhs; } else rhs;

  /*
    Match `left == right`. `left` is the expression under test and `right`
    the value to compare against. Returns a match statement.
  */
  eq = left: right: mkMatch "==" left right;

  /*
    Match `left != right`. `left` is the expression under test and `right`
    the value to compare against. Returns a match statement.
  */
  ne = left: right: mkMatch "!=" left right;

  /*
    Match `left < right`. `left` is the expression under test and `right`
    the value to compare against. Returns a match statement.
  */
  lt = left: right: mkMatch "<" left right;

  /*
    Match `left > right`. `left` is the expression under test and `right`
    the value to compare against. Returns a match statement.
  */
  gt = left: right: mkMatch ">" left right;

  /*
    Match `left <= right`. `left` is the expression under test and `right`
    the value to compare against. Returns a match statement.
  */
  le = left: right: mkMatch "<=" left right;

  /*
    Match `left >= right`. `left` is the expression under test and `right`
    the value to compare against. Returns a match statement.
  */
  ge = left: right: mkMatch ">=" left right;

  /*
    Match membership without spelling out the set wrapper. `left` is the
    expression under test; `right` is a list (wrapped as an anonymous set)
    or any other set expression, such as `"@name"`. Returns a match statement.
  */
  inSet = left: right: mkMatch "==" left (wrapSet right);

  /*
    Negated `inSet`. `left` is the expression under test; `right` is a list
    or other set expression, as for `inSet`. Returns a match statement.
  */
  notInSet = left: right: mkMatch "!=" left (wrapSet right);

  /*
    Synonym for `inSet` that reads well with ranges. `left` is the
    expression under test and `right` a list or set expression. Returns a
    match statement.
  */
  within = left: right: inSet left right;

  # Namespaced match operators for callers who prefer explicit
  # disambiguation, plus the raw escape hatch and the bitwise `in` operator.
  match = {
    inherit
      eq
      ge
      gt
      le
      lt
      ne
      ;

    /*
      Test flag bits with the nftables `in` operator. `left` is the
      expression under test and `right` the flag value or list. Returns a
      match statement.
    */
    in_ = left: right: mkMatch "in" left right;

    /*
      Build a match with any operator. `op` is the JSON operator string,
      `left` the expression under test, and `right` the compared value.
      Returns a match statement.
    */
    raw =
      {
        op,
        left,
        right,
      }:
      mkMatch op left right;
  };
in
{
  inherit
    eq
    ge
    gt
    inSet
    le
    lt
    match
    ne
    notInSet
    within
    ;
}
