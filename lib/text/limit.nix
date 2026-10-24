/*
  Limit text grammar for inline statements, named-object body lines, and
  positional `create limit` commands. Callers own scope and brace layout;
  this module owns the rate clause and its spelling in each form.
*/
{ lib, primitives }:

let
  inherit (primitives) safeToken;

  /*
    The rate clause, spelled so that text loads what JSON loads
    (parser_json.c json_parse_limit_stmt):
    - a missing `rate_unit`, or `packets`, is a packet rate, which text
      writes without a unit; its burst is in packets, and JSON ignores
      `burst_unit`;
    - any other unit is a byte rate, whose burst unit defaults to bytes;
    - a burst of 0 is the default either way (JSON turns a packet burst
      of 0 into 5, as text does without one), so it is left out: nft's
      text refuses `burst 0 packets` inline.
  */
  renderRate =
    body:
    let
      burst = body.burst or null;
      rateUnit = body.rate_unit or null;
      burstUnit = body.burst_unit or null;
      # A Raw attrset can hold any string in these bare units. Check each
      # one, even an ignored burst unit, so parser metacharacters can't
      # split the clause.
      checkedBurstUnit = if burstUnit == null then null else safeToken "limit burst_unit" burstUnit;
      packetRate = rateUnit == null || rateUnit == "packets";
      rate = safeToken "limit rate" body.rate;
      per = safeToken "limit per" body.per;
      rateClause =
        if packetRate then "${rate}/${per}" else "${rate} ${safeToken "limit rate_unit" rateUnit}/${per}";
      burstClause =
        if burst == null || burst == 0 then
          ""
        else if packetRate then
          builtins.seq checkedBurstUnit " burst ${safeToken "limit burst" burst} packets"
        else
          " burst ${safeToken "limit burst" burst} ${
             if checkedBurstUnit == null then "bytes" else checkedBurstUnit
           }";
    in
    "rate" + lib.optionalString ((body.inv or null) == true) " over" + " ${rateClause}${burstClause}";
in
{
  # Inline form only; statements.nix renders named-object references.
  renderStatement = body: "limit ${renderRate body}";

  renderObjectBody =
    body:
    [ (renderRate body) ]
    ++ lib.optional (
      (body.comment or null) != null
    ) "comment ${primitives.quoteString "limit comment" body.comment}";

  renderCreate = renderRate;
}
