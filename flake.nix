{
  description = "Nix type definitions mirroring the libnftables-json schema";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});

      mkLib = lib: import ./lib { inherit lib; };
    in
    {
      lib = mkLib nixpkgs.lib;

      checks = forAllSystems (
        pkgs:
        let
          nftlib = mkLib pkgs.lib;
          tests = import ./tests { inherit pkgs nftlib; };
          integration = import ./tests/dsl-integration.nix {
            inherit (pkgs) lib;
            inherit nftlib;
          };
          textParity = import ./tests/text-parity.nix { inherit pkgs nftlib; };
          textBlockParity = import ./tests/text-block-parity.nix { inherit pkgs nftlib; };
          textIntegration = import ./tests/text-integration.nix {
            inherit (pkgs) lib;
            inherit nftlib;
          };
          renderEquivalence = import ./tests/render-equivalence.nix {
            inherit (pkgs) lib;
            inherit nftlib;
          };
          validation = import ./tests/dsl-validation.nix {
            inherit (pkgs) lib;
            inherit nftlib;
          };
          validationMessages = import ./tests/dsl-validation-messages.nix {
            inherit pkgs;
            inherit (pkgs) lib;
          };
          commentSafety = import ./tests/comment-safety.nix {
            inherit (pkgs) lib;
            inherit nftlib;
          };
          restrictedTypes = import ./tests/restricted-types.nix {
            inherit (pkgs) lib;
            inherit nftlib;
          };
        in
        {
          schema-tests = tests.runTests pkgs;
          # End-to-end: each case is rendered and piped through
          # `unshare -rn nft -c -j -f` (the real libnftables parser inside a
          # private network namespace). Catches any divergence between the
          # DSL's JSON output and what nftables actually accepts.
          integration-tests = integration.runIntegrationTests pkgs integration.cases;
          # Text-renderer parity tests: compact-form expected-string
          # assertions per construct.
          text-parity-tests = textParity.runTests pkgs;
          # Block-form text-renderer parity tests: assertions for
          # toTextBlock / toTextBlockPretty (the contents of a single
          # `table { ... }` block, no `add` keyword, no family/table
          # prefix on object headers).
          text-block-parity-tests = textBlockParity.runTests pkgs;
          # Block-form text-renderer live-parser check: each case is
          # rendered via toTextBlockPretty, wrapped in
          # `table <fam> <name> { ... }`, and piped through
          # `unshare -rn nft -c -f -` to verify the round-trip is
          # accepted by the upstream parser.
          text-block-integration-tests = textBlockParity.runIntegrationTests pkgs textBlockParity.integrationCases;
          # Text-renderer live-parser tests: same case set as
          # integration-tests, but rendered to text and piped through
          # `unshare -rn nft -c -f -` (no `-j`).
          text-integration-tests = textIntegration.runIntegrationTests pkgs textIntegration.textCases;
          # Render-equivalence: render each case via JSON and via text,
          # load both into separate netns, diff `nft list ruleset`. The
          # binding 1:1 contract — both renderers agree on what they
          # build inside the kernel.
          render-equivalence-tests = renderEquivalence.runEquivalenceTests pkgs renderEquivalence.equivalenceCases;
          # DSL-level validation: each constructor that takes a user body
          # must route it through the matching schema submodule before
          # emitting JSON. Catches the silent-data-loss bug (where a bad
          # field rendered to JSON and `nft -j -f` dropped the section).
          dsl-validation-tests = validation.runTests pkgs;
          # End-to-end check on validation error-message format: each case
          # runs `nix-instantiate --eval` against a bad expression and
          # asserts the stderr names the offending option path. Companion
          # to dsl-validation-tests, which checks the failure but not the
          # message shape.
          dsl-validation-message-tests = validationMessages.runMessageTests;
          # Regression pin for the nft quoted-string injection class:
          # schema rejects '"', '\', control chars, and >128 bytes on
          # commentOption / elemBody.comment / log prefix; renderer
          # asserts the same set as defence-in-depth; safe comments
          # round-trip through both text and JSON paths byte-for-byte.
          comment-safety-tests = commentSafety.runTests pkgs;
          comment-safety-integration-tests = commentSafety.runIntegrationTests pkgs;
          # Subset-helper coverage: `statementOf` / `matchStatement` /
          # `expressionOf` accept the in-subset tags and reject the
          # rest, throw on construction-time misuse, and stay in sync
          # with the schema unions (per-kind smoke loop).
          restricted-types-tests = restrictedTypes.runTests pkgs;
        }
      );

      formatter = forAllSystems (pkgs: pkgs.nixfmt-tree);
    };
}
