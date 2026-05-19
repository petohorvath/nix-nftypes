{ lib, nftSafeString }:

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
#   priority       — render a chain priority value. Schema types prio as
#                    `nullOr int`; this helper enforces the same on the
#                    render side. Symbolic priorities go through
#                    `nftlib.resolvePriority` upstream.

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
  # returns it as-is. The schema's `nftQuotedString` type uses the same
  # predicate (see lib/nft-safe-string.nix) and catches most violations
  # at eval time; this assert is the defense-in-depth backstop for any
  # caller that bypasses the schema (tests, third-party DSLs, hand-built
  # attrsets).
  escape =
    s:
    if !nftSafeString.isSafe s then
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

  # Chain priority. The schema types `prio` as `types.nullOr types.int`
  # (chainBody / flowtableBody), so the renderer mirrors that contract
  # and refuses anything else. The earlier "or string" branch was dead
  # — schema rejects strings — and offered a way for raw-attrset
  # callers bypassing the schema to slip a `priority <token>` clause
  # containing a newline + top-level command into the rendered text.
  # Named priorities (`filter`, `filter + 10`) flow through
  # `compatibility.resolvePriority` to an int before reaching this
  # point; renderers stay int-only.
  priority =
    v:
    if builtins.isInt v then
      toString v
    else
      throw ''
        nftypes: refusing to render a non-integer chain/flowtable priority ${builtins.toJSON v}. The schema types `prio` as `nullOr int`; symbolic priorities ("filter", "filter + 10", …) flow through `nftlib.resolvePriority` to an int before reaching the renderer. A bare string here would land in the `priority <X>` clause unchecked and let a parser-meta byte split the clause into separate statements.
      '';
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
