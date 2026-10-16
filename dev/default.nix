{ inputs, ... }:
{
  imports = [ inputs.nix-unit.modules.flake.default ];

  perSystem =
    { config, pkgs, ... }:
    {
      # The integration suites read probe records, which are build outputs,
      # so they run as the `integration-<suite>` entries of ../tests.
      nix-unit = {
        package = pkgs.nix-unit;
        inputs = removeAttrs inputs [ "self" ];
        enableSystemAgnostic = false;
        tests.unit = import ../tests/unit { inherit (inputs) nixpkgs; };
      };
      formatter = pkgs.callPackage ./formatter.nix { };
      devShells.default = pkgs.callPackage ./shell.nix {
        inherit (config) formatter;
      };
      devShells.review = pkgs.callPackage ./review-shell.nix { };
      checks = import ./checks.nix {
        inherit (config) formatter;
        inherit pkgs;
        checks = import ../tests { inherit inputs pkgs; };
      };
    };
}
