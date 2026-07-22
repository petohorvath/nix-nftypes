{
  pkgs,
  flakeFile ? ../flake.nix,
  workflowFile ? ../.github/workflows/upstream-sync.yml,
}:

# Static regression guard for the channel-authority design. The project must
# not grow a second, independently pinned Netfilter source or reintroduce a
# direct upstream Git dependency in the scheduled workflow.
let
  inherit (pkgs) lib;
  flakeText = builtins.readFile flakeFile;
  workflowText = builtins.readFile workflowFile;

  forbidden = [
    {
      name = "direct nftables-src flake input";
      present = lib.hasInfix "inputs.nftables-src" flakeText;
    }
    {
      name = "direct libnftnl-src flake input";
      present = lib.hasInfix "inputs.libnftnl-src" flakeText;
    }
    {
      name = "Netfilter Git flake input";
      present = lib.hasInfix "git+https://git.netfilter.org" flakeText;
    }
    {
      name = "git ls-remote in channel watcher";
      present = lib.hasInfix "git ls-remote" workflowText;
    }
    {
      name = "git clone in channel watcher";
      present = lib.hasInfix "git clone" workflowText;
    }
    {
      name = "direct git.netfilter.org workflow dependency";
      present = lib.hasInfix "git.netfilter.org/nftables" workflowText;
    }
  ];

  required = [
    {
      name = "nixpkgs applyPatches source derivation";
      present = lib.hasInfix "pkgs.applyPatches" flakeText;
    }
    {
      name = "floating channel override";
      present = lib.hasInfix "--override-input" workflowText;
    }
    {
      name = "content-based source comparison";
      present = lib.hasInfix "nix hash path" workflowText;
    }
    {
      name = "stable channel authority";
      present = lib.hasInfix "- input: nixpkgs\n" workflowText;
    }
    {
      name = "unstable channel authority";
      present = lib.hasInfix "- input: nixpkgs-unstable\n" workflowText;
    }
    {
      name = "resolved-drift close condition";
      present = lib.hasInfix "if: steps.source.outputs.drift == 'false'" workflowText;
    }
    {
      name = "resolved-drift issue closure";
      present = lib.hasInfix "gh issue close" workflowText;
    }
  ];

  failures =
    map (entry: "forbidden: ${entry.name}") (builtins.filter (entry: entry.present) forbidden)
    ++ map (entry: "missing: ${entry.name}") (builtins.filter (entry: !entry.present) required);
  failureMessage = lib.concatStringsSep "\n" failures;
in
{
  inherit failures;

  runTests =
    _pkgs:
    if failures == [ ] then
      pkgs.runCommandLocal "channel-source-policy-tests" { } ''
        echo "channel source policy assertions passed"
        touch $out
      ''
    else
      pkgs.runCommandLocal "channel-source-policy-tests-fail" { } ''
        cat >&2 <<'EOF'
        channel source policy assertions failed:
        ${failureMessage}
        EOF
        exit 1
      '';
}
