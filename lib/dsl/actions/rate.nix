/*
  Rate-limiting statements: `limit` and `quota`. Each supports an inline
  form plus a `.ref "name"` form for references to named objects. The
  camelCase unit keys (`rateUnit`, `valUnit`, …) are translated to the
  underscored JSON keys by internal/rename.nix.
*/
{ lib }:

let
  compact = import ../internal/compact.nix { inherit lib; };
  variant = import ../internal/variant.nix { inherit lib; };
  rename = import ../internal/rename.nix { inherit lib; };

  limitBase =
    {
      rate,
      per,
      rateUnit ? null,
      burst ? null,
      burstUnit ? null,
      inv ? null,
    }:
    {
      limit = compact (
        rename.limit {
          inherit
            rate
            per
            rateUnit
            burst
            burstUnit
            inv
            ;
        }
      );
    };

  quotaBase =
    {
      val,
      valUnit ? null,
      used ? null,
      usedUnit ? null,
      inv ? null,
    }:
    {
      quota = compact (
        rename.quota {
          inherit
            val
            valUnit
            used
            usedUnit
            inv
            ;
        }
      );
    };
in
{
  /*
    Match packets within a rate.

    `limit { rate; per; rateUnit?; burst?; burstUnit?; inv?; }` builds an
    inline limit: `rate` per time unit `per`, with an optional unit, burst,
    and inversion. `limit.ref name` references a named limit object. Each
    returns a limit statement.
  */
  limit = variant limitBase {
    ref = name: { limit = name; };
  };

  /*
    Match until a byte quota is used up.

    `quota { val; valUnit?; used?; usedUnit?; inv?; }` builds an inline
    quota of `val`, optionally seeded with a `used` amount and inverted.
    `quota.ref name` references a named quota object. Each returns a quota
    statement.
  */
  quota = variant quotaBase {
    ref = name: { quota = name; };
  };
}
