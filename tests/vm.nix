/*
  Runs the live-parser probe runners (./probes/nft.nix) in one NixOS VM
  built from the package set. Root in the VM can create the private user
  and network namespaces that hosted CI runners deny inside the build
  sandbox.

  Returns the VM test; its output holds `probes/<observation>.json`.
*/
{ pkgs, runners }:
let
  inherit (pkgs) lib;
in
pkgs.testers.runNixOSTest {
  name = "nft-probes";

  nodes.machine = {
    # Load the netfilter and dummy-link modules up front rather than
    # relying on autoloading from inside the probes' namespaces.
    boot.kernelModules = [
      "dummy"
      "nf_tables"
    ];
  };

  testScript = ''
    machine.wait_for_unit("multi-user.target")
    machine.succeed("mkdir /tmp/probes")
    ${lib.concatStrings (
      lib.mapAttrsToList (name: runner: ''
        machine.succeed("${runner} /tmp/probes/${name}.json")
      '') runners
    )}
    machine.copy_from_vm("/tmp/probes", "")
  '';
}
