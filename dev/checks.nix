{
  checks,
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
    # statix runs here, as treefmt would run only `statix fix`, which leaves
    # the findings it cannot fix in place. The rest guards the repo's files.
    lint = pkgs.runCommand "nix-nftypes-lint" { nativeBuildInputs = [ pkgs.statix ]; } (
      ''
        cd ${../.}
        statix check .
      ''
      + reportNames "nixpkgs source policy: forbidden sources present:" nixpkgsSourcePolicy.forbiddenPresent
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
