/*
  Render equivalence (ADR 0001): every Integration case, loaded through
  JSON and through each text form in separate network namespaces, must
  list the same ruleset. ../fixtures/render-equivalence.nix holds the
  forms, the Refusals, and the named exclusions; each exclusion is
  asserted to still differ, so a stale one fails.
*/
{
  fixtures,
  helpers,
  lib,
  observations,
  ...
}:
let
  plan = fixtures.renderEquivalence;
  record = observations.renderEquivalence;
  version = helpers.nftVersion record;
  runOf = case: form: record."${case.name}-${form}";

  textForms = case: builtins.filter (form: form != "json") (plan.loadedForms case);

  # A text form's listing equals the JSON listing, or, for a named
  # exclusion, still differs from it.
  textFormTest =
    case: form:
    let
      json = runOf case "json";
      run = runOf case form;
      matches = run.status == 0 && run.output == json.output;
    in
    if plan.exclusionOn version case form != null then
      lib.nameValuePair "testStillDiffers_${case.name}_${form}" {
        expr = matches;
        expected = false;
      }
    else
      lib.nameValuePair "testListingMatches_${case.name}_${form}" {
        expr = {
          inherit (run) output status;
        };
        expected = {
          inherit (json) output;
          status = 0;
        };
      };

  loadTests =
    case:
    if helpers.rejectedOn version case then
      map (
        form:
        lib.nameValuePair "testRejected_${case.name}_${form}" (helpers.runFailsWith [ ] (runOf case form))
      ) (plan.loadedForms case)
    else
      [ (lib.nameValuePair "testLoads_${case.name}_json" (helpers.runSucceeds (runOf case "json"))) ]
      ++ map (textFormTest case) (textForms case);

  refusalTests =
    case:
    lib.mapAttrsToList (
      form: message:
      lib.nameValuePair "testRefuses_${case.name}_${form}" {
        expr = plan.render.${form} case;
        expectedError = {
          type = "ThrownError";
          msg = message;
        };
      }
    ) (plan.refusals.${case.name} or { });
in
lib.listToAttrs (lib.concatMap (case: loadTests case ++ refusalTests case) plan.cases)
// {
  testCaseNames = {
    expr = lib.sort lib.lessThan (map (case: case.name) plan.cases);
    expected = fixtures.integrationCaseNames;
  };

  # The probe loaded each case's forms, and recorded the nft version.
  testRecordedRuns = {
    expr = builtins.attrNames record;
    expected = lib.sort lib.lessThan (
      [ "nftVersion" ]
      ++ lib.concatMap (case: map (form: "${case.name}-${form}") (plan.loadedForms case)) plan.cases
    );
  };
}
