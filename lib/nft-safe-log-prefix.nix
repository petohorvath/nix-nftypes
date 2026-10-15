/*
  Shared predicate for a log prefix, the one quoted-string position where
  nft's text expands `$name` from a `define` (`parser_bison.y`, through
  `preprocess.c`), with no escape for `$`: an undefined name fails to
  load, and JSON loads the same prefix literally. nft also requires 1 to
  127 bytes ("log prefix must have a minimum length of 1 character", "log
  prefix is too long"; the kernel's NF_LOG_PREFIXLEN is 128 with the NUL).
  The schema type (`logPrefix`) and the text renderer's `quoteLogPrefix`
  both check it, so neither path can drift from the other.
*/
{ nftSafeString }:

let
  maxLength = 127;

  isSafe =
    s:
    builtins.isString s
    && builtins.stringLength s >= 1
    && builtins.stringLength s <= maxLength
    && builtins.match "[^$]*" s != null
    && nftSafeString.isSafe s;
in
{
  inherit isSafe;
}
