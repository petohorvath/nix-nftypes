{ lib }:

# Primitive atoms used by every higher-level renderer.
#
#   identQuote     — render an identifier (table/chain/set name etc.); bare
#                    when it matches the unquoted-identifier rule, else
#                    double-quoted with `"`/`\` escaped.
#   string         — render a free-form string (comment, log prefix); always
#                    double-quoted with `"`/`\` escaped.
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

  escape = s: lib.escape [ "\"" "\\" ] s;

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
