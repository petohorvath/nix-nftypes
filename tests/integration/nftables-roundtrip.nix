/*
  Read-back round trip (docs/upstream-sync.md): every command the package
  set's `nft -j list ruleset` emits for the really loaded integration
  cases, and for the text Read-back states (`textReadbacks`), must
  validate against `nftlib.types.ruleset`, whose `topLevel`
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
  in tests/helpers/probes/nft.nix and docs/upstream-sync.md.
*/
{
  fixtures,
  helpers,
  lib,
  nftlib,
  observations,
  ...
}:
let
  record = observations.nftablesRoundtrip;
  version = helpers.nftVersion record;

  # Cases this nft version must reject (`rejectedBefore`) list nothing.
  rejectedNames = map (case: case.name) (
    builtins.filter (helpers.rejectedOn version) fixtures.integrationCases.cases
  );
  rejectedRuns = lib.getAttrs rejectedNames record;
  runs = removeAttrs (helpers.caseRuns record) rejectedNames;

  loaded = lib.filterAttrs (_: run: run.status == 0) runs;
  listings = lib.mapAttrs (_: run: builtins.fromJSON run.output) loaded;

  # Every listing starts with `metainfo`, so a listing that holds only it
  # checks nothing.
  objectsOf = listing: builtins.filter (command: !(command ? metainfo)) listing.nftables;

  /*
    Vacuous-pass guard: if environment rot (missing kernel modules, broken
    userns) or a case change empties the listings, the suite must not stay
    green with little validated. The floor is the number of objects,
    besides `metainfo`, that the listings held when it was set, less some
    slack for cases that change.
  */
  minListedObjects = 300;

  # A read-back command validates as a `topLevel` entry when wrapped as a
  # singleton ruleset, exercising the public type's oneOf.
  validates = command: helpers.validates nftlib.types.ruleset { nftables = [ command ]; };

  # Read-back commands the schema rejects, deduped by JSON form.
  offending = lib.pipe listings [
    builtins.attrValues
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
  # Every case must load; a load failure would silently reduce coverage.
  testEveryRoundtripCaseLoads = {
    expr = lib.mapAttrs (_: run: run.output) (lib.filterAttrs (_: run: run.status != 0) runs);
    expected = { };
  };

  testVersionRejectedCasesFail = {
    expr = lib.mapAttrs (_: run: run.status != 0) rejectedRuns;
    expected = lib.mapAttrs (_: _: true) rejectedRuns;
  };

  testEveryListingHoldsAnObject = {
    expr = builtins.attrNames (lib.filterAttrs (_: listing: objectsOf listing == [ ]) listings);
    expected = [ ];
  };

  testEnoughObjectsListed = {
    expr =
      lib.foldl' (total: listing: total + builtins.length (objectsOf listing)) 0 (
        builtins.attrValues listings
      ) >= minListedObjects;
    expected = true;
  };

  testCaseNames = {
    expr = builtins.attrNames (helpers.caseRuns record);
    expected = lib.sort lib.lessThan (
      fixtures.integrationCaseNames
      ++ [
        "commented-set-and-map-text"
        "element-statements-text"
      ]
    );
  };

  # nft's JSON parser ignores set and map comments, so only the text
  # state reads them back; it must still list them.
  testTextReadbackListsComments = {
    expr = lib.pipe runs.commented-set-and-map-text.output [
      builtins.fromJSON
      (listing: builtins.filter (command: command ? set || command ? map) listing.nftables)
      (map (command: (command.set or command.map).comment or null))
    ];
    expected = [
      "blocked hosts"
      "per-host verdicts"
    ];
  };

  # JSON input can't seed element statements, so the text state lists each
  # with its state, as keys beside the element's `val`. The time since
  # `last used` grows, so only its lower bound is compared.
  testTextReadbackListsElementStatements = {
    expr = lib.pipe runs.element-statements-text.output [
      builtins.fromJSON
      (listing: builtins.filter (command: command ? set) listing.nftables)
      (map (command: removeAttrs (builtins.head command.set.elem).elem [ "val" ]))
      (map (elem: elem // lib.optionalAttrs (elem ? last) { last.used = elem.last.used >= 1000; }))
    ];
    expected = [
      {
        counter = {
          packets = 1;
          bytes = 2;
        };
      }
      {
        quota = {
          val = 100;
          val_unit = "kbytes";
          used = 40;
          used_unit = "kbytes";
        };
      }
      {
        limit = {
          rate = 5;
          burst = 10;
          per = "second";
          inv = true;
        };
      }
      { last.used = true; }
    ];
  };

  testReadbackHasNoNewDrift = {
    expr = map builtins.toJSON (
      builtins.filter (command: !(knownReadbackDivergences ? ${classify command})) offending
    );
    expected = [ ];
  };
}
