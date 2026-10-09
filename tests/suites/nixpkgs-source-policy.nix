{ helpers, lib, ... }:

# Static regression guard for the nixpkgs-authority design. The project must
# not grow a second nixpkgs input or an independently pinned Netfilter
# source, or reintroduce a direct upstream Git dependency in the scheduled
# workflow.
let
  # `hasInfix` matches `.*infix.*` against the whole text, which
  # overflows nix-unit's stack on files this long; splitting does not.
  hasInfix = infix: text: builtins.length (lib.splitString infix text) > 1;
  flakeText = helpers.readProjectFile "flake.nix";
  # The branch of the `nixpkgs` input, which the stable matrix entries track.
  stableBranch = lib.pipe flakeText [
    (lib.splitString "\n")
    (map (builtins.match "[[:space:]]*nixpkgs\\.url = \"github:NixOS/nixpkgs/([^\"]+)\";"))
    (lib.findFirst (match: match != null) [ null ])
    builtins.head
  ];
  sourcePackageText = helpers.readProjectFile "packages/nftables-source/package.nix";
  workflowText = helpers.readProjectFile ".github/workflows/upstream-sync.yml";
  docsText = helpers.readProjectFile "docs/upstream-sync.md";
  # check.yml calls the policy through its moving minor-series tag, as the
  # policy requires, so only the scheduled workflow pins actions.
  actionUseLines = builtins.filter (line: hasInfix "uses:" line) (lib.splitString "\n" workflowText);
  actionUseIsPinned =
    line:
    let
      parts = lib.splitString "@" line;
    in
    builtins.length parts == 2
    && builtins.match "[0-9a-f]{40}([[:space:]]+#.*)?[[:space:]]*" (lib.last parts) != null;
  unpinnedActionUseLines = builtins.filter (line: !actionUseIsPinned line) actionUseLines;
  # Canary targets by name, with the attribute path that holds them.
  canaryTargets =
    lib.genAttrs [
      "integration-tests"
      "text-integration-tests"
      "text-block-integration-tests"
      "render-equivalence-tests"
      "nftables-roundtrip-tests"
    ] (_: "legacyPackages.x86_64-linux.vmTests")
    // lib.genAttrs [
      "nftables-source-provenance-tests"
      "nftables-corpus-tests"
      "nftables-enum-extraction-tests"
      "nftables-tooling-selftests"
    ] (_: "checks.x86_64-linux");
  canaryScript = lib.last (lib.splitString "Compatibility suite vs latest" workflowText);
  canaryEvaluationMarker = "          locked_version=$(nix eval --raw";
  canaryPreEvaluation = builtins.head (lib.splitString canaryEvaluationMarker canaryScript);
  # The workflow's jobs, split at the canary job's key. Each job's matrix
  # must list each branch exactly once.
  workflowJobs =
    let
      parts = lib.splitString "\n  canary:\n" workflowText;
    in
    {
      nixpkgs-source-watch = builtins.head parts;
      canary = lib.last parts;
    };
  matrixEntries =
    jobText: branch: builtins.length (lib.splitString "- branch: ${branch}\n" jobText) - 1;
  everyMatrixListsOnce =
    branch:
    builtins.length (lib.splitString "\n  canary:\n" workflowText) == 2
    && lib.all (jobText: matrixEntries jobText branch == 1) (builtins.attrValues workflowJobs);
  canaryRevisionEcho = ''echo "nixpkgs revision: \`$tip_rev\`."'';

  forbidden = [
    {
      name = "nixpkgs-unstable flake input";
      present = hasInfix "nixpkgs-unstable" flakeText;
    }
    {
      name = "nixpkgs-unstable in the scheduled workflow";
      present = hasInfix "nixpkgs-unstable" workflowText;
    }
    {
      name = "nixpkgs-unstable in the upstream-sync docs";
      present = hasInfix "nixpkgs-unstable" docsText;
    }
    {
      name = "direct nftables-src flake input";
      present = hasInfix "inputs.nftables-src" flakeText;
    }
    {
      name = "direct libnftnl-src flake input";
      present = hasInfix "inputs.libnftnl-src" flakeText;
    }
    {
      name = "Netfilter Git flake input";
      present = hasInfix "git+https://git.netfilter.org" flakeText;
    }
    {
      name = "git ls-remote in source watcher";
      present = hasInfix "git ls-remote" workflowText;
    }
    {
      name = "git clone in source watcher";
      present = hasInfix "git clone" workflowText;
    }
    {
      name = "direct git.netfilter.org workflow dependency";
      present = hasInfix "git.netfilter.org/nftables" workflowText;
    }
    {
      name = "deprecated flake lock update-input command";
      present = hasInfix "nix flake lock --update-input" docsText;
    }
    {
      name = "mutable GitHub Action references: ${lib.concatStringsSep " | " unpinnedActionUseLines}";
      present = unpinnedActionUseLines != [ ];
    }
  ];

  required = [
    {
      name = "nixpkgs applyPatches source derivation";
      present = hasInfix "applyPatches" sourcePackageText;
    }
    {
      name = "floating branch-tip override";
      present = hasInfix "--override-input" workflowText;
    }
    {
      name = "content-based source comparison";
      present = hasInfix "nix hash path" workflowText;
    }
    {
      name = "single nixpkgs branch-tip override";
      present = hasInfix "--override-input nixpkgs \"$tip_uri\"" workflowText;
    }
    {
      name = "stable branch matches the nixpkgs input";
      present = stableBranch != null && everyMatrixListsOnce stableBranch;
    }
    {
      name = "unstable branch";
      present = everyMatrixListsOnce "nixos-unstable";
    }
    {
      name = "resolved-drift close condition";
      present = hasInfix "if: steps.source.outputs.drift == 'false'" workflowText;
    }
    {
      name = "resolved-drift issue closure";
      present = hasInfix "gh issue close" workflowText;
    }
    {
      name = "superseded drift issue closure";
      present =
        hasInfix "Superseded by #" workflowText
        && hasInfix "closes older open drift issues for the same branch" docsText;
    }
    {
      name = "full branch-tip revision recorded before canary evaluation";
      present =
        hasInfix canaryEvaluationMarker canaryScript && hasInfix canaryRevisionEcho canaryPreEvaluation;
    }
    {
      name = "full-source hash distinguished from selected-file diagnostic";
      present =
        hasInfix "NAR hashes are authoritative for whether drift exists" docsText
        && hasInfix "`parser.diff` is a selected-file diagnostic" docsText;
    }
    {
      name = "canary reproduction overrides nixpkgs";
      present =
        hasInfix "revision=FULL_REVISION_FROM_SUMMARY\n" docsText
        && hasInfix "--override-input nixpkgs \"github:NixOS/nixpkgs/$revision\"" docsText;
    }
    {
      name = "current single-input update command";
      present = hasInfix "nix flake update nixpkgs\n" docsText;
    }
  ]
  ++ lib.mapAttrsToList (name: attrPath: {
    name = "documented canary target ${name}";
    present =
      hasInfix ("            " + name) canaryScript && hasInfix "\".#${attrPath}.${name}\"" docsText;
  }) canaryTargets;

  namesWhere = predicate: entries: map (entry: entry.name) (builtins.filter predicate entries);
in
{
  testForbiddenSourcesAbsent = {
    expr = namesWhere (entry: entry.present) forbidden;
    expected = [ ];
  };
  testRequiredSourcesPresent = {
    expr = namesWhere (entry: !entry.present) required;
    expected = [ ];
  };
}
