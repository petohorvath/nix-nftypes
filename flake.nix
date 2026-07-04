{
  description = "Nix type definitions mirroring the libnftables-json schema";

  # The library targets BOTH nixpkgs channels: `nixpkgs` is the current
  # NixOS stable release (the compatibility floor consumers deploy on) and
  # `nixpkgs-unstable` tracks the channel where a newer nftables lands
  # first. Every channel-dependent check is instantiated against both — the
  # stable set keeps the plain names, the unstable set gets an `-unstable`
  # suffix — so a divergence between the two channels' `nft` (or `lib`
  # module system) turns a check red instead of surfacing in a consumer's
  # deployment. When a new NixOS release becomes stable, repoint `nixpkgs`
  # here (see docs/upstream-sync.md, "Bumping the channels").
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
  inputs.nixpkgs-unstable.url = "github:NixOS/nixpkgs/nixos-unstable";

  # The exact nftables revision the schema in `lib/schema/` was hand-derived
  # from. This is the machine-readable form of the README's "authoritative
  # reference" pin and `docs/spec-coverage.md`'s "version audited" line —
  # bumping it here (via `nix flake update nftables-src`) is the deliberate,
  # reviewable act of adopting a newer parser. Every upstream-sync check
  # (corpus conformance, enum extraction, the pinned-parser integration
  # build) reads its source files from this input, so the pin and the
  # checks can never silently disagree. `flake = false`: nftables ships no
  # flake.nix, we only want its source tree. cgit snapshot tarballs are
  # disabled on git.netfilter.org (HTTP 400), so this is a git input.
  inputs.nftables-src = {
    url = "git+https://git.netfilter.org/nftables?ref=master&rev=f7dc8269ddaed49fe643423a3a403b91ab1e50db";
    flake = false;
  };

  # libnftnl for the Layer 1 conformance build only. A post-1.1.6 nftables
  # needs libnftnl symbols (nftnl_set_elem_set_imm, …) newer than nixpkgs
  # ships, so the pinned `nft` is built against this. Bump it together with
  # `nftables-src` when adopting a newer parser — if a future nftables bump
  # fails to build here, a stale libnftnl pin is the first thing to check.
  inputs.libnftnl-src = {
    url = "git+https://git.netfilter.org/libnftnl?ref=master&rev=363b0e32361969fc695c3eaf619f343abcf2f912";
    flake = false;
  };

  outputs =
    {
      self,
      nixpkgs,
      nixpkgs-unstable,
      nftables-src,
      libnftnl-src,
    }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});

      mkLib = lib: import ./lib { inherit lib; };

      # Layer 1 conformance oracle (docs/upstream-sync.md): `nft` built from
      # the pinned `nftables-src` + matching libnftnl — the exact parser
      # `lib/schema/` was derived from. Exposed under `packages` and consumed
      # by the `integration-tests-pinned` check. Dropping nixpkgs'
      # release-tarball patches and adding autoreconfHook is what lets a git
      # checkout (no ./configure) build.
      mkPinnedNft =
        pkgs:
        let
          libnftnl = pkgs.libnftnl.overrideAttrs (old: {
            version = "git-363b0e32";
            src = libnftnl-src;
            patches = [ ];
            nativeBuildInputs = (old.nativeBuildInputs or [ ]) ++ [ pkgs.autoreconfHook ];
          });
        in
        (pkgs.nftables.override { inherit libnftnl; }).overrideAttrs (old: {
          version = "1.1.6-105-gf7dc8269";
          src = nftables-src;
          patches = [ ];
          nativeBuildInputs = (old.nativeBuildInputs or [ ]) ++ [ pkgs.autoreconfHook ];
        });

      /*
        Channel-dependent check set, instantiated once per nixpkgs channel.
        Everything here depends on the channel through one of two surfaces:
        the eval-time suites exercise the channel's `lib` (module system,
        error-message shapes — dsl-validation-message-tests asserts message
        format, which can shift between nixpkgs releases), and the
        live-parser suites exercise the channel's `nft` binary. Running the
        set against both channels is the "compatible with stable AND
        unstable" contract, enforced on every `nix flake check`.
      */
      mkChannelChecks =
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
          # or asserts via `escape` (rejecting '"', '\', control chars)
          # and quotes the rest — where nft rejects the quoted form in
          # identifier position.
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
          # lib/text/expressions.nix routes each through the shared
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
        };

      # ── Upstream-sync pipeline (docs/upstream-sync.md) ────────────────
      # Keep the schema/DSL in step with the nftables JSON parser as it
      # evolves. These checks are anchored to the `nftables-src` pin in
      # `flake.lock` — not to a nixpkgs channel — so unlike the channel
      # checks above they are instantiated once, on the stable channel
      # (whose stdenv changes least often, minimizing gratuitous
      # from-source rebuilds of the pinned `nft`).
      mkPinChecks =
        pkgs:
        let
          nftlib = mkLib pkgs.lib;
          integration = import ./tests/dsl-integration.nix {
            inherit (pkgs) lib;
            inherit nftlib;
          };
          upstreamCorpus = import ./tests/upstream-corpus.nix {
            inherit pkgs nftlib;
            nftablesSrc = nftables-src;
          };
          upstreamEnums = import ./tests/upstream-enums.nix {
            inherit pkgs nftlib;
            nftablesSrc = nftables-src;
          };
          nftablesPinned = mkPinnedNft pkgs;
          upstreamRoundtrip = import ./tests/upstream-roundtrip.nix {
            inherit pkgs nftlib nftablesPinned;
          };
          upstreamSelftest = import ./tests/upstream-selftest.nix {
            inherit pkgs nftlib;
            nftablesSrc = nftables-src;
          };
        in
        {
          # Layer 2 — nftables' own `tests/py` corpus validated against the
          # schema. Catches the test-invisible "schema too restrictive"
          # direction (D2): constructs the parser accepts that the schema
          # rejects, baselined against a documented known-divergence set.
          upstream-corpus-tests = upstreamCorpus.runTests pkgs;
          # Layer 4 — deterministic enum extraction from the pinned parser's
          # C tables (family_tbl, rt_key_tbl, fib_result_tbl, meta_templates)
          # vs `nftlib.enums`. Zero-AI, zero-false-positive enum drift.
          upstream-enum-extraction-tests = upstreamEnums.runTests pkgs;
          # Layer 1 — the integration case set against `nft` built from the
          # pinned `nftables-src` (the exact parser the schema claims to
          # match), as opposed to `integration-tests` / `-unstable` which
          # run against the channels' nft. A green-pinned / red-channel
          # split is drift in parser acceptance.
          integration-tests-pinned =
            integration.runIntegrationTestsWithNft nftablesPinned pkgs
              integration.cases;
          # Layer 5 — read-back round-trip: really load each case with the
          # pinned `nft`, capture `nft -j list ruleset`, validate every
          # emitted command against the schema. The only deterministic net
          # for serializer (src/json.c) and object-shape drift, and the
          # test behind the README's "round-trip safe" claim.
          upstream-roundtrip-tests = upstreamRoundtrip.runTests pkgs;
          # Red-path self-tests: inject drift/defects into the tooling's
          # inputs and assert every drift check actually goes red — the
          # guard against the checks themselves rotting silently green
          # (dead extraction regex, over-broad baseline, toothless
          # validator).
          upstream-tooling-selftests = upstreamSelftest.runTests pkgs;
        };
    in
    {
      lib = mkLib nixpkgs.lib;

      # Per system: the full channel check set against stable `nixpkgs`
      # (plain names — the floor consumers deploy on), the same set against
      # `nixpkgs-unstable` (`-unstable` suffix — where a newer nftables/lib
      # lands first), and the pin-anchored upstream-sync checks once.
      checks = nixpkgs.lib.genAttrs systems (
        system:
        let
          suffixed =
            suffix: nixpkgs.lib.mapAttrs' (name: value: nixpkgs.lib.nameValuePair "${name}${suffix}" value);
        in
        mkChannelChecks nixpkgs.legacyPackages.${system}
        // suffixed "-unstable" (mkChannelChecks nixpkgs-unstable.legacyPackages.${system})
        // mkPinChecks nixpkgs.legacyPackages.${system}
      );

      /*
        The pinned conformance `nft` (Layer 1) and matching libnftnl, exposed
        for manual validation against the exact parser the schema was derived
        from:

          nix build .#nftables-pinned
          ./result/bin/nft --version
      */
      packages = forAllSystems (pkgs: {
        nftables-pinned = mkPinnedNft pkgs;
      });

      formatter = forAllSystems (pkgs: pkgs.nixfmt-tree);
    };
}
