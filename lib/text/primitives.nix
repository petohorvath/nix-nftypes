/*
  Primitive atoms used by every higher-level renderer.

    identQuote     — render an identifier (table/chain/set name etc.); bare
                     when it matches the unquoted-identifier rule, else
                     double-quoted (asserted-safe). Note nft REJECTS quoted
                     strings in most identifier positions, so the fallback
                     is mostly a load-bearing parse error.
    quoteString    — render a free-form string (a comment); always
                     double-quoted (asserted-safe).
    quoteLogPrefix — render a log prefix; always double-quoted, and
                     asserted to load as written (no `$`, 1-127 bytes).
    quoteIfname    — render an interface name; always double-quoted, and
                     asserted to be a name the kernel could give a device.
    safeToken      — render a value written bare: an integer, or a string
                     asserted safe to emit as a bare token, unchanged.
    namedReference — assert that a string is `@` and a safe bare name, as
                     a set, map or flowtable reference, and return it.
    flags          — render a flag value that the schema accepts as either a
                     bare string or a list (listOrSingleton), each flag a
                     safe bare token. Joined with `, ` by default.
    refuse         — raise a Refusal; every other refusing helper calls it.
    refuseBarePrefix
                   — refuse a bare expression string containing `/`,
                     which text would load as a prefix.
    refuseJsonIgnored
                   — refuse a field that nft's JSON parser ignores, which
                     text would load (ADR 0010).
    refuseNoTextSpelling
                   — refuse a value whose JSON meaning nft's text grammar
                     can't spell (ADR 0001).
    isWrittenSymbol
                   — whether nft's lexer reads a bare string as written.
    refuseUnidentified
                   — refuse a string of unknown type that nft's lexer
                     would read as something else.
    priority       — render a chain priority value. Schema types prio as
                     `nullOr int`; this helper enforces the same on the
                     render side. Symbolic priorities go through
                     `nftlib.compatibility.priorityValue` upstream, and
                     offsets through Nix arithmetic.

  The asserting helpers take a `field` label first (e.g. "table comment",
  "payload protocol"). Each refusal keeps its generic wording and ends
  with `Field: <label>.`, so a failure names the offending field.
*/
{
  fail,
  lib,
  nftSafeIfname,
  nftSafeLogPrefix,
  nftSafeScalar,
  nftSafeString,
}:

let
  # Matches the part of nftables scanner.l's string-token rule that's safe
  # to emit unquoted in scope (table/chain/set/object name) positions.
  # Names in those positions are *required* to be bare — `nft -c -f -`
  # rejects `add table inet "main"` with `unexpected quoted string`.
  # nft accepts hyphens and underscores; this regex conservatively
  # covers the names typically used in rulesets.
  bareIdentRegex = "[A-Za-z_][A-Za-z0-9_-]*";

  isBareIdent = s: builtins.match bareIdentRegex s != null;

  /*
    Raise a Refusal. Every Refusal reads the same way: `message`, one line
    that is never hard-wrapped and starts `refusing to render`, then an
    `Offending value: <JSON>` line when `args` has a `value`, then
    `Field: <label>.` for `args.field`.
  */
  refuse =
    args: message:
    fail (
      message
      + lib.optionalString (args ? value) "\nOffending value: ${builtins.toJSON args.value}"
      + "\nField: ${args.field}."
    );

  # SECURITY-CRITICAL: nft has NO string-escape grammar. The lexer ends a
  # quoted token at the next bare `"`, treating any preceding `\` as a
  # literal byte. A string containing `"` therefore terminates early and
  # any trailing content is parsed as further nft commands — at table
  # scope that includes nested `chain` definitions, yielding a real
  # firewall bypass (e.g. `comment "X"; chain bypass { ... }; #"`
  # injects a chain with `policy accept` at priority -10).
  #
  # We cannot "escape" the dangerous characters because nft has no escape
  # syntax to render into. Instead the function asserts the input is
  # already safe (no `"`, no `\`, no control characters incl. NUL/\n) and
  # returns it as-is. The schema's `comment` type uses the same
  # predicate (see lib/nft-safe-string.nix) and catches most violations
  # at eval time; this assert is the defense-in-depth backstop for any
  # caller that bypasses the schema (tests, third-party DSLs, hand-built
  # attrsets).
  assertSafeString =
    field: s:
    if !nftSafeString.isSafe s then
      refuse
        {
          inherit field;
          value = s;
        }
        "refusing to render a string containing a character unsafe for nft's quoted-string syntax (any of: '\"', '\\', control character). nft has no string-escape grammar — these characters either terminate the token early (allowing statement injection) or corrupt the parser."
    else
      s;

  quoteString = field: s: ''"${assertSafeString field s}"'';

  /*
    nft's text expands `$name` inside a quoted log prefix from a `define`
    and has no escape for `$`, so a prefix with `$` either fails to load
    or loads another string; JSON loads it literally. nft also refuses a
    prefix outside 1 to 127 bytes. The schema's `logPrefix` checks the
    same predicate.
  */
  quoteLogPrefix =
    field: s:
    if nftSafeLogPrefix.isSafe s then
      ''"${s}"''
    else
      refuse
        {
          inherit field;
          value = s;
        }
        "refusing to render a log prefix that nft's text would not load as written: it must be a string of 1 to 127 bytes, free of '$' (nft expands `$name` from a `define` there and has no escape for it), '\"', '\\', and control characters. JSON loads a '$' literally.";

  /*
    Quoted, an interface name loads as exactly its string: bare, `010`
    loads as `8` and `a|b` as `c`, and `$lan` takes a host `define`. nft
    expands `$` only in a log prefix, so quoting needs no more than the
    quoted-string rules, which the shared ifname predicate includes.
  */
  quoteIfname =
    field: s:
    if nftSafeIfname.isSafe s then
      ''"${s}"''
    else
      refuse
        {
          inherit field;
          value = s;
        }
        "refusing to render an interface name that is not one: it must be 1 to 15 bytes, not `.` or `..`, and free of '/', ':', whitespace (byte 0xA0 included), '\"', '\\', and control characters. nft has no string-escape grammar, and the kernel rejects such a device name.";

  identQuote = field: s: if isBareIdent s then s else quoteString field s;

  /*
    SECURITY-CRITICAL: every value the renderer writes bare (payload
    protocol and field, ct key, enum fields such as a chain policy,
    integer fields such as a set size) lands in the surrounding nft text
    as is. Raw attrsets bypass the schema, so the renderer is the last
    line of defence (ADR 0004): an unsafe byte either truncates the
    clause or splits the token, letting trailing input parse as fresh
    nft commands. An integer renders with `toString`; anything else must
    be a string that passes the shared `nft-safe-scalar` predicate, so a
    string in an integer field gets the same check.
  */
  safeToken =
    field: s:
    if builtins.isInt s then
      toString s
    else if builtins.isString s && nftSafeScalar.isSafe s then
      s
    else
      refuse
        {
          inherit field;
          value = s;
        }
        "refusing to render a bare nft token that contains a character unsafe for the surrounding expression context. The renderer emits the value verbatim into a `tcp <field>` / `meta <key>` / `ct <key>` / `ip option <name>` / similar clause, so an unsafe byte either truncates the clause and lets the trailing input parse as fresh nft commands, or splits the token. The shared predicate (lib/nft-safe-scalar.nix) excludes whitespace, ',', ';', '{', '}', '\"', '\\', '#', control characters, and bytes above 0x7F, which nft's lexer reads as junk; legitimate field/key names are identifier-shaped and pass cleanly.";

  # A stored named reference (`@blocked`) prints as is. Without its `@`
  # nft would read the name as something else, so it is refused.
  namedReference =
    field: s:
    if !(builtins.isString s && lib.hasPrefix "@" s) then
      refuse
        {
          inherit field;
          value = s;
        }
        "refusing to render a named reference without its `@`. A set, map or flowtable reference is stored as `@<name>`, as nft's JSON requires; build it with the DSL, which adds the `@`."
    else
      "@${safeToken field (lib.removePrefix "@" s)}";

  # Render a listOrSingleton flag value, each flag through `safeToken`.
  # The default separator matches `nft list ruleset` output (`, `); some
  # flag positions take another, so pass `sep` there.
  flags =
    {
      field,
      sep ? ", ",
    }:
    v: lib.concatMapStringsSep sep (safeToken field) (lib.toList v);

  # A Read-back field that nft's JSON parser ignores, such as a set
  # comment: text would load it while JSON drops it (ADR 0001, ADR 0010).
  refuseJsonIgnored =
    field:
    refuse
      {
        inherit field;
      }
      "refusing to render a field that nft's JSON parser ignores. Text would load it, while the JSON form of the same ruleset drops it, so the two forms would load different rulesets. Remove the field, or load the ruleset as JSON.";

  /*
    A bare string containing `/`. nft's JSON parser reads `10.0.0.0/8` as
    a hostname and rejects it, but text loads it as a prefix, so a typo
    such as `198.51.100.7/0` would match every address. The schema's
    expression strings reject them too; text refuses them in a raw
    attrset, which bypasses the schema.
  */
  refuseBarePrefix =
    field: s:
    refuse
      {
        inherit field;
        value = s;
      }
      "refusing to render a bare string containing `/` at expression position. nft's text loads it as a prefix, while its JSON parser rejects it as a hostname. Write a prefix as a prefix expression, `{ prefix = { addr = …; len = …; }; }`, which `dsl.expr.prefix` builds.";

  /*
    Whether nft's lexer (scanner.l) reads the bare string `s` as one token
    whose text is `s`, the symbol JSON makes of a string: a name (the
    `string` rule, with an optional trailing `*`), an IPv4, IPv6 or MAC
    address, a `@name` reference, or the catch-all `*`. Anything else
    reads as something other than `s`: `010` is a number (8), `$x` a
    variable, `1-5` a range, `a|b` an expression. Time strings and class
    ids also lex as one token, but are left out. A name that is an nft
    keyword lexes as the keyword, which nft rejects in element position or
    reads back as the same word.
  */
  isWrittenSymbol =
    s:
    let
      isName = n: builtins.match "[A-Za-z_.][A-Za-z0-9/_.-]*" n != null;
      isIp4 = a: builtins.match "[0-9]{1,3}(\\.[0-9]{1,3}){3}" a != null;
      isHex4 = g: builtins.match "[0-9A-Fa-f]{1,4}" g != null;
      halves = lib.splitString "::" s;
      compressed = builtins.length halves == 2;
      groupsOf = part: if part == "" then [ ] else lib.splitString ":" part;
      tailGroups = groupsOf (lib.last halves);
      # Only a compressed address ends in an IPv4 address (`::ffff:1.2.3.4`).
      ip4Tail = compressed && tailGroups != [ ] && isIp4 (lib.last tailGroups);
      groups = lib.concatMap groupsOf halves;
      hexGroups = if ip4Tail then lib.init groups else groups;
      groupCount = builtins.length hexGroups + (if ip4Tail then 2 else 0);
      isIp6 =
        builtins.length halves <= 2
        && lib.hasInfix ":" s
        && lib.all isHex4 hexGroups
        && (if compressed then groupCount <= 7 else groupCount == 8);
      isMac = builtins.match "[0-9A-Fa-f]{1,2}(:[0-9A-Fa-f]{1,2}){5}" s != null;
    in
    s == "*"
    || (lib.hasPrefix "@" s && isName (lib.removePrefix "@" s))
    || isName (lib.removeSuffix "*" s)
    || isIp4 s
    || isIp6
    || isMac;

  # A string the renderer can't place: it doesn't know the value's type,
  # and nft's text would read the bare string as something else.
  refuseUnidentified =
    field: s:
    refuse
      {
        inherit field;
        value = s;
      }
      "refusing to render a string that nft's text would misread. The renderer can't tell this value's type here (an `add element` command carries no set type), and nft's lexer reads the bare string as a number, a variable, a range or several tokens, so `010` would load as `8`. Give a number as an integer, or declare the elements in the set or map, whose type lets the renderer quote them.";

  # A value whose JSON meaning nft's text grammar can't spell: text would
  # fail to load, or load something else (ADR 0001). `detail` says why.
  refuseNoTextSpelling =
    field: detail:
    refuse
      {
        inherit field;
      }
      "refusing to render a value that nft's text has no spelling for with the meaning nft's JSON parser gives it, so the text form would fail to load or load a different ruleset. ${detail}";

  # Chain priority. The schema types `prio` as `types.nullOr types.int`
  # (chainBody / flowtableBody), so the renderer mirrors that contract
  # and refuses anything else. The earlier "or string" branch was dead
  # — schema rejects strings — and offered a way for raw-attrset
  # callers bypassing the schema to slip a `priority <token>` clause
  # containing a newline + top-level command into the rendered text.
  # Named priorities (`filter`) flow through
  # `compatibility.priorityValue` to an int before reaching this
  # point, and an offset is Nix arithmetic on that int; renderers stay
  # int-only.
  priority =
    field: v:
    if builtins.isInt v then
      toString v
    else
      refuse
        {
          inherit field;
          value = v;
        }
        "refusing to render a non-integer chain/flowtable priority. The schema types `prio` as `nullOr int`; resolve a symbolic priority such as \"filter\" with `nftlib.compatibility.priorityValue` and add any offset with Nix arithmetic. A bare string here would land in the `priority <X>` clause unchecked and let a parser-meta byte split the clause into separate statements.";
in
{
  inherit
    assertSafeString
    flags
    identQuote
    isBareIdent
    isWrittenSymbol
    namedReference
    priority
    quoteIfname
    quoteLogPrefix
    quoteString
    refuse
    refuseBarePrefix
    refuseJsonIgnored
    refuseNoTextSpelling
    refuseUnidentified
    safeToken
    ;
}
