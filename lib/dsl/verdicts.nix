{ lib }:

# Verdict values. Valid in both statement position (rule body) and
# expression position (vmap data). Terminals are plain attrsets; `jump` and
# `goto` take a target chain name.

{
  accept = { accept = null; };
  drop = { drop = null; };
  continue = { continue = null; };
  return = { return = null; };
  notrack = { notrack = null; };
  jump = target: { jump = { inherit target; }; };
  goto = target: { goto = { inherit target; }; };
}
