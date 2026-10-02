/*
  Runs the nix-unit suites (./unit.nix) inside the build sandbox, against
  the given package set's `lib` and `nix-unit`.
*/
{ pkgs }:
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
in
pkgs.runCommandLocal "unit-tests" { nativeBuildInputs = [ pkgs.nix-unit ]; } ''
  export HOME="$(realpath .)"
  nix-unit --quiet \
    --eval-store "$HOME" \
    --gc-roots-dir "$HOME/gc-roots" \
    --expr 'import ${src}/tests/unit.nix { lib = import ${pkgs.path}/lib; }'
  touch $out
''
