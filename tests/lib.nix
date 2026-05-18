{ lib }:

# Shared boilerplate for `tests/*.nix` files.
#
# Each test file historically rolled its own `runTests` that:
#   1. ran `lib.runTests` against the in-file `tests` attrset,
#   2. emitted a derivation named `<name>-pass` when results were empty,
#   3. emitted a derivation named `<name>-fail` with the formatted
#      `lib.runTests` output piped through a heredoc + `exit 1` otherwise.
#
# `mkRunTests` builds that callback once. Call it with the derivation
# `name` (the suffix `-pass`/`-fail` is appended) and the test attrset:
#
#   runTests = mkRunTests { name = "comment-safety-tests"; tests = …; };
#
# The result takes `pkgs` and returns the derivation, matching the
# historical `runTests = pkgs: …` shape consumed by `flake.nix`.

{
  mkRunTests =
    { name, tests }:
    pkgs:
    let
      results = lib.runTests tests;
      count = toString (builtins.length (builtins.attrNames tests));
      fmt = lib.generators.toPretty { };
    in
    if results == [ ] then
      pkgs.runCommandLocal "${name}-pass" { } ''
        echo "${name}: all ${count} tests passed"
        touch $out
      ''
    else
      pkgs.runCommandLocal "${name}-fail" { } ''
        cat <<'EOF'
        ${name} failed:
        ${fmt results}
        EOF
        exit 1
      '';
}
