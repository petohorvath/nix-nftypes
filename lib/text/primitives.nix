{ lib }:

# Primitive atoms used by every higher-level renderer.
#
#   identQuote     — render an identifier (table/chain/set name etc.); bare
#                    when it matches the unquoted-identifier rule, else
#                    double-quoted (asserted-safe). Note nft REJECTS quoted
#                    strings in most identifier positions, so the fallback
#                    is mostly a load-bearing parse error.
#   string         — render a free-form string (comment, log prefix); always
#                    double-quoted (asserted-safe).
#   flags          — render a flag value that the schema accepts as either a
#                    bare string or a list (listOrSingleton). Joined with `,`.
#   handle         — render a `handle <n>` clause when handle is non-null.
#   comment        — render a trailing `comment "<text>"` clause when
#                    comment is non-null.
#   priority       — render a chain priority value. Schema accepts either
#                    int or string (named priority like "filter", "filter +
#                    10"); both render as-is, with strings unquoted because
#                    the text grammar uses unquoted priority tokens.

let
  # Matches the subset of nftables scanner.l string-token rule that's safe
  # to emit unquoted in scope (table/chain/set/object name) positions.
  # Names in those positions are *required* to be bare — `nft -c -f -`
  # rejects `add table inet "main"` with `unexpected quoted string`.
  # nft accepts hyphens and underscores; this regex is a conservative
  # subset that covers names typically used in rulesets.
  bareIdentRegex = "[A-Za-z_][A-Za-z0-9_-]*";

  isBareIdent = s: builtins.match bareIdentRegex s != null;

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
  # returns it as-is. Schema-level types (see lib/schema/primitives.nix
  # `nftQuotedString`) catch most violations at eval time; this assert is
  # the defense-in-depth backstop for any caller that bypasses the
  # schema (tests, third-party DSLs, hand-built attrsets).
  escape =
    s:
    if builtins.match ''[^"\\[:cntrl:]]*'' s == null then
      throw ''
        nftypes: refusing to render a string containing a character unsafe for
        nft's quoted-string syntax (any of: '"', '\', control character). nft
        has no string-escape grammar — these characters either terminate the
        token early (allowing statement injection) or corrupt the parser.
        Offending value: ${builtins.toJSON s}
      ''
    else
      s;

  quoteString = s: ''"${escape s}"'';

  identQuote = s: if isBareIdent s then s else quoteString s;

  string = quoteString;

  # Render a listOrSingleton flag value. Default separator matches
  # `nft list ruleset` output (`, `). Some flag positions use space
  # separation (e.g. `log flags`); pass `sep` explicitly there.
  flags =
    {
      sep ? ", ",
    }:
    v: if builtins.isList v then lib.concatStringsSep sep v else v;

  handle = v: if v == null then "" else " handle ${toString v}";

  comment = v: if v == null then "" else " comment ${quoteString v}";

  # Chain priority: int → "0", "-100" etc.; string → "filter", "filter + 10"
  # emitted as-is (no quoting — the text grammar parses these as named
  # priority tokens).
  priority = v: if builtins.isInt v then toString v else v;
in
{
  inherit
    isBareIdent
    escape
    quoteString
    identQuote
    string
    flags
    handle
    comment
    priority
    ;
}
