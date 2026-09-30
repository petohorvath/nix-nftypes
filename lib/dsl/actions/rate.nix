/*
  Rate-limiting statements: `limit` and `quota`. Each supports an inline
  form plus a `.ref "name"` form for references to named objects.
*/
{ lib }:

let
  compact = import ../internal/compact.nix { inherit lib; };
  variant = import ../internal/variant.nix { inherit lib; };

  limitBase =
    {
      rate,
      per,
      rate_unit ? null,
      burst ? null,
      burst_unit ? null,
      inv ? null,
    }:
    {
      limit = compact {
        inherit
          rate
          per
          rate_unit
          burst
          burst_unit
          inv
          ;
      };
    };

  quotaBase =
    {
      val,
      val_unit ? null,
      used ? null,
      used_unit ? null,
      inv ? null,
    }:
    {
      quota = compact {
        inherit
          val
          val_unit
          used
          used_unit
          inv
          ;
      };
    };
in
{
  /*
    Match packets within a rate.

    `limit { rate; per; rate_unit?; burst?; burst_unit?; inv?; }` builds an
    inline limit: `rate` per time unit `per`, with an optional unit, burst,
    and inversion. `limit.ref name` references a named limit object. Each
    returns a limit statement.
  */
  limit = variant limitBase {
    ref = name: { limit = name; };
  };

  /*
    Match until a byte quota is used up.

    `quota { val; val_unit?; used?; used_unit?; inv?; }` builds an inline
    quota of `val`, optionally seeded with a `used` amount and inverted.
    `quota.ref name` references a named quota object. Each returns a quota
    statement.
  */
  quota = variant quotaBase {
    ref = name: { quota = name; };
  };
}
