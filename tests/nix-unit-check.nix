/*
  Builds a check that runs nix-unit inside the build sandbox, against the
  given package set's `lib` and `nix-unit`.

  - `name`: the check's derivation name.
  - `entryPoint`: ./unit.nix (evaluation-only suites) or ./live.nix
    (suites that assert on probe records).
  - `suites`: names of the entry point's suites to run; `null` runs all.
  - `observationPaths`: probe outputs the live suites read, keyed by
    observation name. They become build inputs, so the probes run before
    nix-unit.

  Returns the check derivation.
*/
{ pkgs }:
{
  name,
  entryPoint,
  suites ? null,
  observationPaths ? { },
}:
let
  inherit (pkgs) lib;
  # The suites load ../lib and ../examples; the source-policy suite also
  # reads the flake, the source package, the workflows, and the
  # upstream-sync guide.
  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../.github/workflows
      ../docs/upstream-sync.md
      ../examples
      ../flake.nix
      ../lib
      ../packages/nftables-source/package.nix
      ./.
    ];
  };
  # Store paths are written as Nix path literals so the sandboxed
  # evaluator can read them.
  observationPathsExpr = "{ ${
    lib.concatStrings (
      lib.mapAttrsToList (
        probe: path: "${lib.strings.escapeNixIdentifier probe} = ${path}; "
      ) observationPaths
    )
  }}";
  entryArgs =
    "{ inherit lib; "
    + lib.optionalString (observationPaths != { }) "observationPaths = ${observationPathsExpr}; "
    + "}";
  selectSuites =
    lib.optionalString (suites != null)
      "lib.getAttrs [ ${lib.concatMapStringsSep " " builtins.toJSON suites} ]";
  testsExpr = ''
    let
      lib = import ${pkgs.path}/lib;
    in
    ${selectSuites} (import ${src}/tests/${entryPoint} ${entryArgs})
  '';
in
pkgs.runCommandLocal name { nativeBuildInputs = [ pkgs.nix-unit ]; } ''
  export HOME="$(realpath .)"
  nix-unit --quiet \
    --eval-store "$HOME" \
    --gc-roots-dir "$HOME/gc-roots" \
    --expr ${lib.escapeShellArg testsExpr}
  touch $out
''
