/*
  Rate-limiting statements: `limit` and `quota`. Each supports an inline
  form plus a `.ref name` form for references to named objects. The
  camelCase unit keys (`rateUnit`, `valUnit`, …) are translated to the
  underscored JSON keys by internal/rename.nix.
*/
{ lib, statement }:

let
  variant = import ../internal/variant.nix { inherit lib; };
in
{
  /*
    Match packets within a rate.

    `limit { rate; per; rateUnit?; burst?; burstUnit?; inv?; }` builds an
    inline limit: `rate` per time unit `per`, with an optional unit, burst,
    and inversion. `limit.ref ref` references a named limit object, as
    `counter.ref` does. Each returns a limit statement, and throws when its
    body doesn't validate.
  */
  limit = variant (statement.fromFields { name = "limit"; }) {
    ref = statement.ref "limit" "limit";
  };

  /*
    Match until a byte quota is used up.

    `quota { val; valUnit?; used?; usedUnit?; inv?; }` builds an inline
    quota of `val`, optionally seeded with a `used` amount and inverted.
    `quota.ref ref` references a named quota object, as `counter.ref`
    does. Each returns a quota statement, and throws when its body doesn't
    validate.
  */
  quota = variant (statement.fromFields { name = "quota"; }) {
    ref = statement.ref "quota" "quota";
  };
}
