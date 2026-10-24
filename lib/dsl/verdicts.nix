/*
  Verdict values. Valid in both statement position (rule body) and
  expression position (vmap data). Terminal verdicts are plain attrsets;
  `jump` and `goto` take a target chain name.
*/
{ statement }:

{
  accept = {
    accept = null;
  };
  drop = {
    drop = null;
  };
  continue = {
    continue = null;
  };
  return = {
    return = null;
  };

  /*
    Build a `jump` verdict, which evaluates another chain and then returns
    to the calling rule. `target` is the chain name. Returns
    `{ jump = { target; }; }`, and throws when `target` is not a string.
  */
  jump = target: statement.tagged "jump" "jump" { inherit target; };

  /*
    Build a `goto` verdict, which continues in another chain without
    returning. `target` is the chain name. Returns `{ goto = { target; }; }`,
    and throws when `target` is not a string.
  */
  goto = target: statement.tagged "goto" "goto" { inherit target; };
}
