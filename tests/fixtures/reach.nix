/*
  The reach check's exceptions (../unit/reach.nix). Every statement
  tag, expression tag, and command/object pair (`"<verb> <kind>"`) that
  the schema accepts must appear in an Integration case whose JSON loads,
  or have one entry here:
  - `pending.<category>.<name> = <ticket>`: no case yet; the open ticket
    under #24 adds one and deletes the entry.
  - `knownDifferences.<category>.<name> = "<reason>"`: a Named exclusion,
    for a name no case can load; the reason names its Known difference.
  An entry whose name a case reaches, or that the schema no longer
  accepts, fails the check.
*/
{ }:
{
  pending = {
    statements = { };

    expressions = { };

    commands = { };
  };

  knownDifferences = {
    statements = {
      # docs/spec-coverage.md, Known differences.
      secmark = "a secmark object loads only on an SELinux kernel, which the test VMs lack, so no rule can reference one";
      xt = "xt is a Read-back shape: nft's JSON parser refuses it as input";
    };
    expressions = {
      # docs/spec-coverage.md, Known differences.
      "dccp option" =
        "Linux 6.16 removed DCCP, so a newer kernel refuses a rule with a DCCP option match";
    };
    commands =
      let
        # docs/spec-coverage.md, Known differences.
        secmark = "a secmark object loads only on an SELinux kernel, which the test VMs lack, so no case can hold one";
      in
      {
        "add secmark" = secmark;
        "create secmark" = secmark;
        "delete secmark" = secmark;
        "list secmark" = secmark;
        "reset rule" =
          "nft's JSON path fails `reset rule` with Operation not supported; only its text resets a rule";
      };
  };
}
