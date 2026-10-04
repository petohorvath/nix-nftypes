{
  formatter,
  packages,
  pkgs,
  pkgsUnstable,
}:
import ../tests { inherit packages pkgs pkgsUnstable; }
// {
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
}
