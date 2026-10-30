/*
  Every statement tag whose body is more than `null` has a body under
  `types.statementBodies`, and that body accepts exactly what the
  `statement` union accepts for its tag, so a downstream option typed with
  a statement body takes every value nft lists for the statement. The tags
  that take only `null` have no body there and take `types.nullLiteral`.
*/
{
  helpers,
  lib,
  nftlib,
  ...
}:
let
  inherit (helpers) validates;
  inherit (nftlib) types;

  # The body of each statement tag that takes more than `null`, by its name
  # in `types.statementBodies`. Pinned here, not read from the schema, as
  # `public-surface.nix` pins the exported names.
  bodyNameByTag = {
    jump = "verdictTargetBody";
    goto = "verdictTargetBody";
    match = "matchBody";
    counter = "counterBody";
    mangle = "mangleBody";
    quota = "quotaBody";
    limit = "limitBody";
    fwd = "fwdBody";
    dup = "dupBody";
    snat = "natBody";
    dnat = "natBody";
    masquerade = "masqueradeBody";
    redirect = "masqueradeBody";
    reject = "rejectBody";
    set = "setBody";
    map = "mapBody";
    log = "logBody";
    "ct helper" = "objectReferenceBody";
    "ct timeout" = "objectReferenceBody";
    "ct expectation" = "objectReferenceBody";
    meter = "meterBody";
    queue = "queueBody";
    vmap = "vmapBody";
    "ct count" = "ctCountBody";
    xt = "xtBody";
    last = "lastBody";
    flow = "flowBody";
    tproxy = "tproxyBody";
    synproxy = "synproxyBody";
    reset = "resetBody";
    secmark = "objectReferenceBody";
    tunnel = "objectReferenceBody";
  };

  # The tags whose only body is the JSON null. They have no body under
  # `types.statementBodies` and take `types.nullLiteral`.
  nullBodyTags = [
    "accept"
    "continue"
    "drop"
    "notrack"
    "return"
  ];

  bodyOf =
    tag:
    if builtins.elem tag nullBodyTags then
      types.nullLiteral
    else
      types.statementBodies.${bodyNameByTag.${tag}};

  tags = builtins.attrNames types.statement.functor.payload.tags;

  payload = {
    payload = {
      protocol = "ip";
      field = "saddr";
    };
  };

  # Bodies to try against every tag: one that each tag's body accepts, and
  # values a body may take or refuse, such as null, a bare name, a map
  # expression that selects one, and an empty attrset.
  samples = [
    null
    { }
    [ ]
    1
    1.5
    true
    "name"
    "@name"
    { nftypesNoSuchField = 1; }
    {
      map = {
        key = payload;
        data = "@m";
      };
    }
    { target = "chain"; }
    {
      left.meta.key = "iif";
      right = "eth0";
      op = "==";
    }
    {
      packets = 0;
      bytes = 0;
    }
    {
      key.meta.key = "mark";
      value = 1;
    }
    { val = 10; }
    {
      rate = 1;
      per = "second";
    }
    { dev = "eth0"; }
    { addr = "192.0.2.1"; }
    { port = 8080; }
    { type = "tcp reset"; }
    {
      op = "add";
      elem = payload;
      set = "@s";
    }
    {
      op = "add";
      elem = payload;
      data = 1;
      map = "@m";
    }
    { prefix = "x"; }
    {
      name = "m";
      key = payload;
      stmt.accept = null;
    }
    { num = 1; }
    {
      key = payload;
      data = "@vm";
    }
    {
      type = "match";
      name = "x";
    }
    { used = 0; }
    {
      op = "add";
      flowtable = "@f";
    }
    {
      mss = 1460;
      wscale = 7;
    }
    { "tcp option".name = "maxseg"; }
  ];

  # Whether the tag's body and the union take the sample alike.
  compare = tag: sample: {
    inherit tag sample;
    body = validates (bodyOf tag) sample;
    union = validates (types.statementOf [ tag ]) { ${tag} = sample; };
  };

  comparisons = lib.concatMap (tag: map (compare tag) samples) tags;
in
{
  testEveryStatementTagHasABodyOrTakesOnlyNull = {
    expr = lib.sort lib.lessThan (builtins.attrNames bodyNameByTag ++ nullBodyTags);
    expected = tags;
  };

  testEachBodyAcceptsWhatTheUnionAcceptsForItsTag = {
    expr = builtins.filter (comparison: comparison.body != comparison.union) comparisons;
    expected = [ ];
  };

  # The samples tell bodies apart: each tag's union accepts one and
  # refuses another, so agreement isn't a body accepting everything.
  testEveryTagAcceptsAndRefusesASample = {
    expr = builtins.filter (
      tag:
      let
        accepted = map (comparison: comparison.union) (
          builtins.filter (comparison: comparison.tag == tag) comparisons
        );
      in
      !(builtins.elem true accepted && builtins.elem false accepted)
    ) tags;
    expected = [ ];
  };
}
