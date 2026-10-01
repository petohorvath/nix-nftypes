# Ad-hoc parser checks use the same stable nftables as the check matrix.
# Nix itself is supplied by the caller's upstream Nix installation.
{
  mkShellNoCC,
  nftables,
  util-linux,
}:
mkShellNoCC {
  packages = [
    nftables
    util-linux
  ];
}
