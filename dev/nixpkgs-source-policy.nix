/*
  Static regression guard for the nixpkgs-authority design, part of the
  `lint` entry. The project must not grow a second nixpkgs input or an
  independently pinned Netfilter source, or reintroduce a direct upstream
  Git dependency or its own nixpkgs revision resolution in the scheduled
  workflow, which reads the policy pins.

  Returns the names of the forbidden sources present and of the required
  sources missing; both are empty when the repo follows the design.
*/
{ lib }:
let
  # `hasInfix` matches `.*infix.*` against the whole text, which can
  # overflow the evaluator's stack on files this long; splitting does not.
  hasInfix = infix: text: builtins.length (lib.splitString infix text) > 1;
  flakeText = builtins.readFile ../flake.nix;
  sourcePackageText = builtins.readFile ../packages/nftables-source/package.nix;
  workflowText = builtins.readFile ../.github/workflows/upstream-sync.yml;
  checkWorkflowText = builtins.readFile ../.github/workflows/check.yml;
  docsText = builtins.readFile ../docs/upstream-sync.md;
  # The policy series that check.yml calls, such as `v0.6`; the scheduled
  # workflow reads the pins from the same series.
  policySeries = lib.pipe checkWorkflowText [
    (lib.splitString "\n")
    (map (
      builtins.match "[[:space:]]*uses: petohorvath/nixos-project-policy/\\.github/workflows/check\\.yml@([^[:space:]]+).*"
    ))
    (lib.findFirst (match: match != null) [ null ])
    builtins.head
  ];
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
      name = "nixpkgs branch-tip resolution in the scheduled workflow";
      present =
        hasInfix "nix flake metadata" workflowText || hasInfix "github:NixOS/nixpkgs/nixos-" workflowText;
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
      name = "content-based source comparison";
      present = hasInfix "nix hash path" workflowText;
    }
    {
      name = "single nixpkgs policy-pin override";
      present = hasInfix "--override-input nixpkgs \"$pin_uri\"" workflowText;
    }
    {
      name = "pins read from the policy series that check.yml calls";
      present =
        policySeries != null
        && hasInfix "POLICY: github:petohorvath/nixos-project-policy/${policySeries}\n" workflowText
        && hasInfix "nix run \"$POLICY\" -- validate" workflowText;
    }
    {
      name = "stable and unstable pins";
      present = hasInfix "label: [stable, unstable]\n" workflowText;
    }
    {
      name = "resolved-drift issue closure";
      present = hasInfix "gh issue close" workflowText;
    }
    {
      name = "one drift issue per pin, edited in place";
      present =
        hasInfix "title=\"nixpkgs nftables drift ($PIN)\"\n" workflowText
        && hasInfix "gh issue edit" workflowText
        && hasInfix "edits that issue in place" docsText;
    }
    {
      name = "changed-file list beside the authoritative full-source hash";
      present =
        hasInfix "diff -rq --no-dereference locked/ pinned/" workflowText
        && hasInfix "NAR hashes are authoritative for whether drift exists" docsText;
    }
    {
      name = "current single-input update command";
      present = hasInfix "nix flake update nixpkgs\n" docsText;
    }
  ];

  namesWhere = predicate: entries: map (entry: entry.name) (builtins.filter predicate entries);
in
{
  forbiddenPresent = namesWhere (entry: entry.present) forbidden;
  requiredMissing = namesWhere (entry: !entry.present) required;
}
