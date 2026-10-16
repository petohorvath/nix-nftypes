{
  checks,
  formatter,
  packages,
  pkgs,
}:
let
  inherit (pkgs) lib;
  nixpkgsSourcePolicy = import ./nixpkgs-source-policy.nix { inherit lib; };
  reportNames =
    heading: names:
    lib.optionalString (names != [ ]) ''
      echo ${lib.escapeShellArg heading} >&2
      printf '  %s\n' ${lib.escapeShellArgs names} >&2
    '';

  # The policy only evaluates `packages`, so build what consumers install.
  packageChecks = lib.mapAttrs' (name: lib.nameValuePair "package-${name}") (
    removeAttrs packages [ "default" ]
  );
in
lib.foldl' lib.attrsets.unionOfDisjoint { } [
  checks
  packageChecks
  {
    # The policy only evaluates the formatter, so check the tree here.
    formatting =
      pkgs.runCommand "formatting"
        {
          src = ../.;
          nativeBuildInputs = [ formatter ];
        }
        ''
          cp -r --no-preserve=mode "$src" source
          cd source
          treefmt --ci --tree-root .
          touch "$out"
        '';

    # Static guards on the repo's own files.
    lint = pkgs.runCommand "lint" { } (
      reportNames "nixpkgs source policy: forbidden sources present:" nixpkgsSourcePolicy.forbiddenPresent
      + reportNames "nixpkgs source policy: required sources missing:" nixpkgsSourcePolicy.requiredMissing
      + (
        if nixpkgsSourcePolicy.forbiddenPresent == [ ] && nixpkgsSourcePolicy.requiredMissing == [ ] then
          ''touch "$out"''
        else
          "exit 1"
      )
    );
  }
]
