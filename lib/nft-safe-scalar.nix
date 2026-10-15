/*
  Shared predicate for the bare-string atoms that the text renderer
  emits unquoted at expression scalar position — IP addresses
  (`192.0.2.1`, `2001:db8::1`), set/map references (`@trusted`),
  ICMP type names (`host-unreachable`), enum-like names (`established`).
  `renderScalar` outputs the string byte-for-byte, so any whitespace
  or nft-grammar metacharacter would either split the token or break
  the parser context — at rule scope a newline + `add chain …` payload
  silently appends an attacker-controlled chain.

  The text renderer's bare-token checks (`safeToken` and `renderScalar`
  in lib/text) use it.
*/
_:

let
  /*
    Printable ASCII, non-empty. nft's lexer (scanner.l) builds bare tokens
    from ASCII only and reads any byte above 0x7F, such as the 0xA0 of a
    no-break space, as junk. Whitespace (incl. newline/tab) would split a
    single scalar into multiple tokens, and control characters (NUL, DEL,
    …) corrupt the parse. A zero-byte scalar carries no meaning.
  */
  printableRegex = "[!-~]+";

  # Parser-meta in scope context: `,` `;` `{` `}` `"` `\` `#`.
  noParserMetaRegex = ''[^,;{}"\\#]*'';

  isSafe = s: builtins.match printableRegex s != null && builtins.match noParserMetaRegex s != null;
in
{
  inherit isSafe;
}
