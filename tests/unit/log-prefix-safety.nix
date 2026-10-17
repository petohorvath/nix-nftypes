{
  fixtures,
  helpers,
  lib,
  nftlib,
  ...
}:

/*
  Log prefixes through the schema and the text renderer. nft loads a
  prefix of 1 to 127 bytes ("log prefix must have a minimum length of 1
  character", "log prefix is too long"), and its text expands `$name`
  inside a quoted `log prefix` from a `define`, with no escape for `$`:
  an undefined name fails, while JSON loads the prefix literally.

  One predicate (lib/nft-safe-log-prefix.nix) holds those rules and the
  quoted-string rules. The schema's `types.logPrefix` and the renderer's
  `quoteLogPrefix` both check it, so a raw attrset that bypasses the
  schema gets a Refusal naming its field (ADR 0004).
*/
let
  inherit (nftlib) toJson toText;
  inherit (helpers) refusals;

  repeatA = count: lib.concatStrings (lib.replicate count "a");

  # Prefixes the predicate rejects.
  badPrefixes = {
    empty = "";
    oversize = repeatA 128;
    dollarName = "$x";
    dollarInside = "drop $x: ";
    dollarDigit = "cost $5";
    dollarAlone = "$";
    quote = ''has " quote'';
    backslash = ''has \ backslash'';
    newline = "has\nnewline";
    tab = "has\ttab";
  };

  # Prefixes the predicate accepts, with the boundary lengths.
  goodPrefixes = {
    oneByte = "a";
    maxLength = repeatA 127;
    simple = "DROP: ";
    byteA0 = fixtures.byteA0Comment;
  };

  schemaRefusal = "nft log prefix";

  # A raw rule holding one log statement, bypassing the schema.
  rawRule = prefix: {
    nftables = [
      {
        add.rule = {
          family = "inet";
          table = "t";
          chain = "c";
          expr = [ { log.prefix = prefix; } ];
        };
      }
    ];
  };

  perPrefix =
    prefixes: test:
    lib.mapAttrs' (name: value: lib.nameValuePair (test.name name) (test.value value)) prefixes;

  schemaRejectionTests = perPrefix badPrefixes {
    name = name: "testSchemaRejects_${name}";
    value = prefix: {
      expr = toJson (fixtures.logPrefixRuleset prefix);
      expectedError.msg = schemaRefusal;
    };
  };

  schemaAcceptanceTests = perPrefix goodPrefixes {
    name = name: "testSchemaAccepts_${name}";
    value = prefix: {
      expr = helpers.validates nftlib.types.statement { log.prefix = prefix; };
      expected = true;
    };
  };

  textRefusalTests = perPrefix badPrefixes {
    name = name: "testTextRefuses_${name}";
    value = prefix: {
      expr = toText (rawRule prefix);
      expectedError.msg = refusals.logPrefix "log prefix";
    };
  };

  textAcceptanceTests = perPrefix goodPrefixes {
    name = name: "testTextQuotes_${name}";
    value = prefix: {
      expr = toText (rawRule prefix);
      expected = ''add rule inet t c log prefix "${prefix}"'';
    };
  };
in
schemaRejectionTests
// schemaAcceptanceTests
// textRefusalTests
// textAcceptanceTests
// {
  # A prefix that isn't a string at all.
  testTextRefusesInteger = {
    expr = toText (rawRule 1);
    expectedError.msg = refusals.logPrefix "log prefix";
  };
}
