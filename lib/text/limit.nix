/*
  Limit text grammar for inline statements, named-object body lines, and
  positional `create limit` commands. Callers own scope and brace layout;
  this module owns the rate clause and its spelling in each form.
*/
{ lib, primitives }:

let
  inherit (primitives) safeToken;

  renderRate =
    body:
    let
      # The schema accepts arbitrary strings for these bare units. Validate
      # each emitted unit so parser metacharacters cannot split the clause.
      rateUnit = lib.optionalString (
        (body.rate_unit or null) != null
      ) " ${safeToken "limit rate_unit" body.rate_unit}";
      burst =
        if (body.burst or null) == null then
          ""
        else
          let
            # Text requires an explicit burst unit. Preserve the renderer's
            # packet default when the JSON-shaped input omits it.
            unit =
              if (body.burst_unit or null) != null then
                safeToken "limit burst_unit" body.burst_unit
              else
                "packets";
          in
          " burst ${toString body.burst} ${unit}";
    in
    "rate"
    + lib.optionalString ((body.inv or null) == true) " over"
    + " ${toString body.rate}${rateUnit}/${body.per}${burst}";
in
{
  renderStatement =
    body:
    if builtins.isString body then
      "limit name ${primitives.quoteString "limit reference" body}"
    else
      "limit ${renderRate body}";

  renderObjectBody =
    body:
    [ (renderRate body) ]
    ++ lib.optional (
      (body.comment or null) != null
    ) "comment ${primitives.quoteString "limit comment" body.comment}";

  renderCreate = renderRate;
}
