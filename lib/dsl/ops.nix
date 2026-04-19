{ lib }:

# Match operators. Each returns a statement (`{ match = { left; right; op; }; }`).
# Top-level operator names read naturally: `eq tcp.dport 22`.
#
# `inSet` / `notInSet` auto-wrap a list rhs as `{ set = [...]; }` and pass a
# string rhs (typically `"@name"`) through unchanged — eliminating the most
# common boilerplate step from the current DSL.
#
# For the nftables `in` operator (bitwise flag-testing), use `match.in`.

let
  mkMatch =
    op: left: right:
    { match = { inherit op left right; }; };

  # Wrap a right-hand-side for set membership: list → anonymous set expression,
  # anything else → pass through (covers "@name" references, pre-built set
  # expressions, individual values for flag testing, etc.).
  wrapSet = rhs: if builtins.isList rhs then { set = rhs; } else rhs;

  eq = mkMatch "==";
  ne = mkMatch "!=";
  lt = mkMatch "<";
  gt = mkMatch ">";
  le = mkMatch "<=";
  ge = mkMatch ">=";

  inSet = left: right: mkMatch "==" left (wrapSet right);
  notInSet = left: right: mkMatch "!=" left (wrapSet right);

  # `within` is a synonym for `inSet`; reads well with ranges.
  within = inSet;

  # Namespaced match operators for callers who prefer explicit disambiguation,
  # plus the raw escape hatch and the bitwise `in` operator for flag tests.
  match = {
    inherit
      eq
      ne
      lt
      gt
      le
      ge
      ;
    in_ = mkMatch "in";
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
    ne
    lt
    gt
    le
    ge
    inSet
    notInSet
    within
    match
    ;
}
