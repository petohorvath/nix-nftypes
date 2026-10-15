/*
  Rate-limiting statements: `limit` and `quota`. Each supports an inline
  form plus a `.ref name` form for references to named objects. The
  camelCase unit keys (`rateUnit`, `valUnit`, …) are translated to the
  underscored JSON keys by internal/rename.nix.
*/
{ lib }:

let
  compact = import ../internal/compact.nix { inherit lib; };
  variant = import ../internal/variant.nix { inherit lib; };
  rename = import ../internal/rename.nix { inherit lib; };
  location = import ../internal/location.nix { inherit lib; };
  reference = import ../internal/reference.nix { inherit lib; };

  limitBase =
    args@{
      rate,
      per,
      rateUnit ? null,
      burst ? null,
      burstUnit ? null,
      inv ? null,
    }:
    {
      limit = compact (rename.limit (location.builder [ "limit" ]) args);
    };

  quotaBase =
    args@{
      val,
      valUnit ? null,
      used ? null,
      usedUnit ? null,
      inv ? null,
    }:
    {
      quota = compact (rename.quota (location.builder [ "quota" ]) args);
    };
in
{
  /*
    Match packets within a rate.

    `limit { rate; per; rateUnit?; burst?; burstUnit?; inv?; }` builds an
    inline limit: `rate` per time unit `per`, with an optional unit, burst,
    and inversion. `limit.ref ref` references a named limit object, as
    `counter.ref` does. Each
    returns a limit statement.
  */
  limit = variant limitBase {
    ref = ref: { limit = reference.objectReference "limit.ref" ref; };
  };

  /*
    Match until a byte quota is used up.

    `quota { val; valUnit?; used?; usedUnit?; inv?; }` builds an inline
    quota of `val`, optionally seeded with a `used` amount and inverted.
    `quota.ref ref` references a named quota object, as `counter.ref`
    does. Each returns a quota
    statement.
  */
  quota = variant quotaBase {
    ref = ref: { quota = reference.objectReference "quota.ref" ref; };
  };
}
