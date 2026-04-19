{ lib }:

# Rate-limiting statements: `limit` and `quota`. Each supports an inline form
# plus a `.ref "name"` form for references to named objects.

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
  limit = variant limitBase {
    ref = name: { limit = name; };
  };

  quota = variant quotaBase {
    ref = name: { quota = name; };
  };
}
