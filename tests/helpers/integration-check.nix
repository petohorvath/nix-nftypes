/*
  Builds the `integration-<suite>` entry that runs one integration suite
  with nix-unit in the build sandbox, against the probe records it reads.
  nix-unit's flake-parts module cannot run these suites: it evaluates
  `tests` from the flake source in the sandbox, where the records, which
  are build outputs, do not exist. Here they are inputs of the build.

  - `suite`: the suite's attribute in ../integration.
  - `observationPaths`: the records the suite reads, by observation name.
  - `requiredSystemFeatures`: features of the builds that wrote them, such
    as those of the NixOS VM run.
  - `postCheck`: shell commands run after the suite passes; `jq` is
    available.
*/
{ pkgs }:
{
  suite,
  observationPaths,
  requiredSystemFeatures ? [ ],
  postCheck ? "",
}:
let
  inherit (pkgs) lib;
  # The files the suites read.
  src = lib.fileset.toSource {
    root = ../..;
    fileset = lib.fileset.unions [
      ../../examples
      ../../lib
      ../.
    ];
  };
  suiteName = lib.strings.escapeNixIdentifier suite;
  # Store paths are written as Nix path literals so the sandboxed
  # evaluator can read them.
  observationPathsExpr = "{ ${
    lib.concatStrings (
      lib.mapAttrsToList (
        observation: path: "${lib.strings.escapeNixIdentifier observation} = ${path}; "
      ) observationPaths
    )
  }}";
  # The suites use only `nixpkgs.lib`, so the package set's `lib` stands in
  # for the flake input, which the sandbox cannot evaluate as a flake.
  testsExpr = ''
    let
      suites = import ${src}/tests/integration {
        nixpkgs.lib = import ${pkgs.path}/lib;
        observationPaths = ${observationPathsExpr};
      };
    in
    { ${suiteName} = suites.${suiteName}; }
  '';
in
pkgs.runCommandLocal "nix-nftypes-integration-${suite}"
  {
    inherit requiredSystemFeatures;
    nativeBuildInputs = [
      pkgs.jq
      pkgs.nix-unit
    ];
  }
  ''
    export HOME="$TMPDIR"
    nix-unit --quiet --show-trace \
      --eval-store "$TMPDIR/eval-store" \
      --gc-roots-dir "$TMPDIR/gc-roots" \
      --expr ${lib.escapeShellArg testsExpr}
    ${postCheck}
    touch "$out"
  ''
