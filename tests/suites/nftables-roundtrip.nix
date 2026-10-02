/*
  Read-back round trip (docs/upstream-sync.md): every command the package
  set's `nft -j list ruleset` emits for the really loaded integration
  cases must validate against `nftlib.types.ruleset`, whose `topLevel`
  union deliberately accepts bare listed objects alongside command
  wrappers.

  Every other suite tests the INPUT direction. This one samples the OUTPUT
  direction, and is the only deterministic net for two drift surfaces:
    - `src/json.c`, the serializer, which evolves independently of
      `parser_json.c`; a new emitted field breaks read-back consumers even
      when the input direction is fine;
    - object bodies; the tests/py corpus only carries per-rule statement
      arrays, so a new field on an emitted set/chain/ct-timeout/… is
      invisible to it.

  The listing is deterministic for a fixed packaged `nft`: handles are
  assigned sequentially in a fresh netns and the metainfo version string
  is that package's own. The probe's /etc/protocols handling is described
  in tests/probes/nft.nix and docs/upstream-sync.md.
*/
{
  helpers,
  lib,
  nftlib,
  observations,
  ...
}:
let
  runs = observations.nftablesRoundtrip;

  # Vacuous-pass guard: if environment rot (missing kernel modules, broken
  # userns) makes cases fail to load, the suite must not stay green with
  # nothing validated. example-basic-firewall-dsl and the flush/reset
  # cases need no optional kernel features, so this floor holds on any
  # Linux builder that can run the other netns probes at all.
  minLoaded = 4;

  loaded = lib.filterAttrs (_: run: run.status == 0) runs;
  listings = lib.mapAttrsToList (_: run: builtins.fromJSON run.output) loaded;

  # A read-back command validates as a `topLevel` entry when wrapped as a
  # singleton ruleset, exercising the public type's oneOf.
  validates = command: helpers.validates nftlib.types.ruleset { nftables = [ command ]; };

  # Read-back commands the schema rejects, deduped by JSON form.
  offending = lib.pipe listings [
    (map (listing: builtins.filter (command: !(validates command)) listing.nftables))
    lib.flatten
    lib.unique
  ];

  classify = command: "readback:${builtins.head (builtins.attrNames command)}";

  /*
    Baselined read-back divergences: shapes the packaged `nft -j list
    ruleset` emits that the schema (deliberately or not-yet) rejects.
    EMPTY today — every command the packaged serializer emits for the
    current case set validates, which is the round-trip claim holding.
    A future nixpkgs package update that makes json.c emit a new field
    lands here (or, preferably, in the schema), with the reason.
  */
  knownReadbackDivergences = { };
in
{
  # Cases the sandbox cannot really load are excluded in the fixture
  # (`knownNoLoad`); any other load failure would silently reduce coverage.
  testEveryRoundtripCaseLoads = {
    expr = lib.mapAttrs (_: run: run.output) (lib.filterAttrs (_: run: run.status != 0) runs);
    expected = { };
  };

  testEnoughCasesLoad = {
    expr = builtins.length listings >= minLoaded;
    expected = true;
  };

  testReadbackHasNoNewDrift = {
    expr = map builtins.toJSON (
      builtins.filter (command: !(knownReadbackDivergences ? ${classify command})) offending
    );
    expected = [ ];
  };
}
