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
