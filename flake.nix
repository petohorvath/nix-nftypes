{
  description = "Nix type definitions mirroring the libnftables-json schema";

  # The library targets BOTH nixpkgs flake inputs: `nixpkgs` is the current
  # NixOS stable release (the compatibility floor consumers deploy on) and
  # `nixpkgs-unstable` tracks the branch where a newer nftables lands first.
  # Every package-set-dependent check is instantiated against both — the
  # stable set keeps the plain names, the unstable set gets an `-unstable`
  # suffix — so a divergence between the two package sets' `nft` (or `lib`
  # module system) turns a check red instead of surfacing in a consumer's
  # deployment. When a new NixOS release becomes stable, repoint `nixpkgs`
  # here (see docs/upstream-sync.md, "Updating inputs").
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
  inputs.nixpkgs-unstable.url = "github:NixOS/nixpkgs/nixos-unstable";

  # nftables has no independent flake input. Each compatibility surface uses
  # the exact binary, release source, and downstream patches carried by its
  # nixpkgs package set. This keeps the test oracle identical to what
  # consumers install and avoids a second, fragile upstream-Git authority.

  inputs.flake-parts = {
    url = "github:hercules-ci/flake-parts";
    inputs.nixpkgs-lib.follows = "nixpkgs";
  };

  outputs =
    inputs@{ flake-parts, nixpkgs, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      # The library itself is platform-independent. Packages and checks
      # invoke Linux-only nftables/network-namespace tooling.
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      perSystem =
        {
          config,
          pkgs,
          system,
          ...
        }:
        let
          /*
            Package-set-dependent check set, instantiated once per nixpkgs flake
            input. Everything here depends on the package set through one of two
            surfaces: the eval-time suites exercise the package set's `lib`
            (module system, error-message shapes — dsl-validation-message-tests
            asserts message format, which can shift between nixpkgs releases),
            and the live-parser suites exercise the package set's `nft` binary.
            Running the set against both package sets is the "compatible with
            stable AND unstable" contract, enforced on every `nix flake check`.
          */
          mkPackageSetChecks =
            pkgs: nftablesSource:
            let
              nftlib = import ./lib { inherit (pkgs) lib; };
              tests = import ./tests { inherit nftlib pkgs; };
              integration = import ./tests/dsl-integration.nix {
                inherit (pkgs) lib;
                inherit nftlib;
              };
              textParity = import ./tests/text-parity.nix { inherit nftlib pkgs; };
              textBlockParity = import ./tests/text-block-parity.nix { inherit nftlib pkgs; };
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
              ifnameSafety = import ./tests/ifname-safety.nix {
                inherit (pkgs) lib;
                inherit nftlib;
              };
              verdictTargetSafety = import ./tests/verdict-target-safety.nix {
                inherit (pkgs) lib;
                inherit nftlib;
              };
              exprScalarSafety = import ./tests/expr-scalar-safety.nix {
                inherit (pkgs) lib;
                inherit nftlib;
              };
              setDatatypeSafety = import ./tests/set-datatype-safety.nix {
                inherit (pkgs) lib;
                inherit nftlib;
              };
              exprTokenSafety = import ./tests/expr-token-safety.nix {
                inherit (pkgs) lib;
                inherit nftlib;
              };
              namedRefSafety = import ./tests/named-ref-safety.nix {
                inherit (pkgs) lib;
                inherit nftlib;
              };
              unitNameSafety = import ./tests/unit-name-safety.nix {
                inherit (pkgs) lib;
                inherit nftlib;
              };
              ctTimeoutPolicySafety = import ./tests/ct-timeout-policy-safety.nix {
                inherit (pkgs) lib;
                inherit nftlib;
              };
              prioritySafety = import ./tests/priority-safety.nix {
                inherit (pkgs) lib;
                inherit nftlib;
              };
              restrictedTypes = import ./tests/restricted-types.nix {
                inherit (pkgs) lib;
                inherit nftlib;
              };
              sourceProvenance = import ./tests/nftables-source-provenance.nix {
                inherit nftablesSource pkgs;
              };
              nftablesCorpus = import ./tests/upstream-corpus.nix {
                inherit nftablesSource nftlib pkgs;
              };
              nftablesEnums = import ./tests/upstream-enums.nix {
                inherit nftablesSource nftlib pkgs;
              };
              nftablesRoundtrip = import ./tests/upstream-roundtrip.nix {
                inherit nftlib pkgs;
                nftables = pkgs.nftables;
              };
              nftablesSelftest = import ./tests/upstream-selftest.nix {
                inherit nftablesSource nftlib pkgs;
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
              # runs `nix eval --file` against a bad expression and
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
              # Regression pin for the ifname-typed set/map element widening
              # class: a `,` in a `type = "ifname"` element rendered bare
              # split into two elements at parse time, silently broadening
              # the set. DSL emit rejects at evalModules; renderer asserts
              # the same predicate as defence-in-depth; safe ifname sets
              # round-trip through both text and JSON paths with the
              # element count preserved.
              ifname-safety-tests = ifnameSafety.runTests pkgs;
              ifname-safety-integration-tests = ifnameSafety.runIntegrationTests pkgs;
              # Regression pin for the verdict-target injection class: a
              # `jump`/`goto` target with a newline used to render bare and
              # let `nft -f` parse the trailing bytes as a fresh top-level
              # command. Renderer now routes the target through
              # `primitives.identQuote`, which either emits the bare ident
              # or asserts via `assertSafeString` (rejecting '"', '\', control
              # chars) and quotes the rest — where nft rejects the quoted form
              # in identifier position.
              verdict-target-safety-tests = verdictTargetSafety.runTests pkgs;
              # Regression pin for the expression-scalar injection class: a
              # bare string in expression position (match RHS, NAT addr,
              # set element, …) used to render verbatim through
              # `renderScalar`, so a newline + statement payload landed in
              # the text stream as a fresh top-level command. The renderer
              # now asserts the value against `nft-safe-scalar.nix`'s
              # predicate — non-empty, no whitespace, no nft-grammar
              # metacharacters, no control chars.
              expr-scalar-safety-tests = exprScalarSafety.runTests pkgs;
              # Regression pin for the set/map datatype injection class:
              # the `type <X>` clause (and `type K . V` for concatenated
              # keys) rendered each name string bare. The renderer now
              # walks every name through `nft-safe-scalar.nix`'s predicate,
              # so an unsafe byte truncating the clause and dropping a
              # fresh `add chain …` payload into the rendered file no
              # longer reaches `nft -f`.
              set-datatype-safety-tests = setDatatypeSafety.runTests pkgs;
              # Regression pin for the tagged-body token injection class:
              # payload/exthdr/ip-option/tcp-option/sctp-chunk/ct schema
              # bodies expose `types.str` fields (protocol, field, name,
              # key) that the renderer used to interpolate bare into the
              # surrounding clause. A new `safeToken` helper in
              # lib/text/primitives.nix routes each through the shared
              # `nft-safe-scalar` predicate so an unsafe byte truncating
              # the clause no longer reaches `nft -f`.
              expr-token-safety-tests = exprTokenSafety.runTests pkgs;
              # Regression pin for the named-reference injection class:
              # `set`/`map`/`flow` statements named the referenced object
              # via a `types.str` field rendered bare into the surrounding
              # statement. The renderer now routes each name through
              # `safeToken` so an unsafe byte truncating the statement and
              # dropping an attacker payload no longer reaches `nft -f`.
              named-ref-safety-tests = namedRefSafety.runTests pkgs;
              # Regression pin for the limit/quota unit-name injection
              # class: `rate_unit` / `burst_unit` / `val_unit` /
              # `used_unit` are `types.str` in the schema and used to
              # render bare into the surrounding clause. All three render
              # surfaces (statement, named-object body, positional
              # `create` form) now route the unit name through `safeToken`.
              unit-name-safety-tests = unitNameSafety.runTests pkgs;
              # Regression pin for the ct-timeout policy-key injection
              # class: `policy` is `attrsOf ints.unsigned`, so keys are
              # arbitrary strings. The renderer emitted each key bare into
              # `policy = { <k>: <v>, … }`. Each key now flows through
              # `safeToken`.
              ct-timeout-policy-safety-tests = ctTimeoutPolicySafety.runTests pkgs;
              # Regression pin for the chain/flowtable priority injection
              # class: the renderer used to accept string priorities even
              # though the schema typed `prio` as `nullOr int`. A raw
              # attrset could slip an unsafe string into the `priority <X>`
              # clause; the renderer now mirrors the schema and refuses
              # anything but an int.
              priority-safety-tests = prioritySafety.runTests pkgs;
              # Subset-helper coverage: `statementOf` / `matchStatement` /
              # `expressionOf` accept the in-subset tags and reject the
              # rest, throw on construction-time misuse, and stay in sync
              # with the schema unions (per-kind smoke loop).
              restricted-types-tests = restrictedTypes.runTests pkgs;

              # Source-side compatibility checks use the exact release archive and
              # downstream patches carried by this package set's nftables
              # derivation. They complement the live binary checks above by
              # covering valid shapes the hand-written integration corpus cannot
              # anticipate.
              nftables-source-provenance-tests = sourceProvenance.runTests pkgs;
              nftables-corpus-tests = nftablesCorpus.runTests pkgs;
              nftables-enum-extraction-tests = nftablesEnums.runTests pkgs;
              nftables-roundtrip-tests = nftablesRoundtrip.runTests pkgs;
              nftables-tooling-selftests = nftablesSelftest.runTests pkgs;
            };
        in
        {
          packages = import ./packages {
            inherit pkgs;
            pkgsUnstable = inputs.nixpkgs-unstable.legacyPackages.${system};
          };

          checks =
            let
              suffixed =
                suffix: pkgs.lib.mapAttrs' (name: value: pkgs.lib.nameValuePair "${name}${suffix}" value);
              sourcePolicy = import ./tests/nixpkgs-source-policy.nix { inherit pkgs; };
            in
            mkPackageSetChecks pkgs config.packages.nftables-source
            // suffixed "-unstable" (
              mkPackageSetChecks inputs.nixpkgs-unstable.legacyPackages.${system}
                config.packages.nftables-source-unstable
            )
            // {
              nixpkgs-source-policy-tests = sourcePolicy.runTests pkgs;
            };

          devShells.review = pkgs.mkShellNoCC {
            packages = [
              pkgs.nftables
              pkgs.util-linux
            ];
          };

          formatter = pkgs.nixfmt-tree;
        };

      flake.lib = import ./lib { inherit (nixpkgs) lib; };
    };
}
