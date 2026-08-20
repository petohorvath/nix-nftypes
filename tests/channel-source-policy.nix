{
  pkgs,
  flakeFile ? ../flake.nix,
  workflowFile ? ../.github/workflows/upstream-sync.yml,
  ciWorkflowFile ? ../.github/workflows/ci.yml,
  docsFile ? ../docs/upstream-sync.md,
}:

# Static regression guard for the channel-authority design. The project must
# not grow a second, independently pinned Netfilter source or reintroduce a
# direct upstream Git dependency in the scheduled workflow.
let
  inherit (pkgs) lib;
  flakeText = builtins.readFile flakeFile;
  workflowText = builtins.readFile workflowFile;
  ciWorkflowText = builtins.readFile ciWorkflowFile;
  docsText = builtins.readFile docsFile;
  actionUseLines =
    lib.concatMap (text: builtins.filter (line: lib.hasInfix "uses:" line) (lib.splitString "\n" text))
      [
        workflowText
        ciWorkflowText
      ];
  actionUseIsPinned =
    line:
    let
      parts = lib.splitString "@" line;
    in
    builtins.length parts == 2
    && builtins.match "[0-9a-f]{40}([[:space:]]+#.*)?[[:space:]]*" (lib.last parts) != null;
  unpinnedActionUseLines = builtins.filter (line: !actionUseIsPinned line) actionUseLines;
  canaryCheckNames = [
    "integration-tests"
    "text-integration-tests"
    "text-block-integration-tests"
    "render-equivalence-tests"
    "nftables-source-provenance-tests"
    "nftables-corpus-tests"
    "nftables-enum-extraction-tests"
    "nftables-roundtrip-tests"
    "nftables-tooling-selftests"
  ];
  canaryScript = lib.last (lib.splitString "Compatibility suite vs latest" workflowText);
  canaryEvaluationMarker = "          locked_version=$(nix eval --raw";
  canaryPreEvaluation = builtins.head (lib.splitString canaryEvaluationMarker canaryScript);

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
    {
      name = "deprecated flake lock update-input command";
      present = lib.hasInfix "nix flake lock --update-input" docsText;
    }
    {
      name = "mutable GitHub Action references: ${lib.concatStringsSep " | " unpinnedActionUseLines}";
      present = unpinnedActionUseLines != [ ];
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
    {
      name = "full channel-tip revision recorded before canary evaluation";
      present =
        lib.hasInfix canaryEvaluationMarker canaryScript
        && lib.hasInfix ''echo "nixpkgs revision: \`$tip_rev\`."'' canaryPreEvaluation;
    }
    {
      name = "full-source hash distinguished from selected-file diagnostic";
      present =
        lib.hasInfix "NAR hashes are authoritative for whether drift exists" docsText
        && lib.hasInfix "`parser.diff` is a selected-file diagnostic" docsText;
    }
    {
      name = "stable and unstable canary reproduction selectors";
      present =
        lib.hasInfix "- stable: `input=nixpkgs`, `suffix=`;" docsText
        && lib.hasInfix "- unstable: `input=nixpkgs-unstable`, `suffix=-unstable`." docsText
        && lib.hasInfix "revision=FULL_REVISION_FROM_SUMMARY\n" docsText;
    }
    {
      name = "current single-input update commands";
      present =
        lib.hasInfix "nix flake update nixpkgs\n" docsText
        && lib.hasInfix "nix flake update nixpkgs-unstable\n" docsText;
    }
  ]
  ++ map (name: {
    name = "documented canary target ${name}";
    present =
      lib.hasInfix ("            " + name) canaryScript
      && lib.hasInfix ("\".#checks.x86_64-linux." + name + "$" + "{suffix}\"") docsText;
  }) canaryCheckNames;

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
