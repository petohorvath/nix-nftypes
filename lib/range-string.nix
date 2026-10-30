/*
  A string that nft's text lexer reads as a range: two numbers or two IP
  addresses joined by `-`, such as `1000-2000` or `10.0.0.1-10.0.0.5`.
  nft's JSON parser reads such a string as one symbol, a service or a
  hostname, and rejects it, so the schema rejects one and text refuses
  one, as both do a prefix written as a string. A word with a hyphen, such
  as `echo-request` or `wg-home`, lexes as one name and stays a string.
*/
_:

let
  number = "[0-9]+|0[xX][0-9a-fA-F]+";
  ipv4 = "[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+";
  ipv6 = "[0-9a-fA-F]*:[0-9a-fA-F:.]*";
  end = "(${number}|${ipv4}|${ipv6})";
in
{
  # Whether `s` is a string that text reads as a range.
  isRangeString = s: builtins.isString s && builtins.match "${end}-${end}" s != null;
}
